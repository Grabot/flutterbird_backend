import json
from typing import Optional
from urllib.parse import urlencode

import requests
from fastapi import Depends, Request, status
from fastapi.responses import RedirectResponse
from oauthlib.oauth2 import WebApplicationClient
from pydantic import BaseModel
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.api_login import api_router_login
from app.api.api_login.logins.login_user_origin import login_user_origin
from app.celery_worker.tasks import task_generate_avatar
from app.config.config import settings
from app.database import get_db
from app.models import User
from app.util.util import get_user_tokens

google_client = WebApplicationClient(settings.GOOGLE_CLIENT_ID)


def get_google_provider_cfg():
    return requests.get(settings.GOOGLE_DISCOVERY_URL).json()


@api_router_login.get("/google", status_code=200)
async def login_google(
    request: Request,
):
    # Find out what URL to hit for Google api_login
    print("loging google")
    google_provider_cfg = get_google_provider_cfg()
    print(f"base url {google_provider_cfg}")

    authorization_endpoint = google_provider_cfg["authorization_endpoint"]

    # Use library to construct the request for Google api_login and provide
    # scopes that let you retrieve user's profile from Google
    print(f"base url {request.base_url}")
    final_redirect_url = str(request.base_url)
    # final_redirect_url = final_redirect_url.replace("http://", "https://", 1)
    print("redirect uri: %s" % final_redirect_url)
    request_uri = google_client.prepare_request_uri(
        authorization_endpoint,
        redirect_uri=str(final_redirect_url) + "/callback",
        scope=["openid", "email", "profile"],
    )
    print("request_uri: %s" % request_uri)
    print("url: %s" % request.url)
    return RedirectResponse(request_uri, status_code=status.HTTP_302_FOUND)


class GoogleCallbackRequest(BaseModel):
    code: str


@api_router_login.route("/google/callback", methods=["GET", "POST"])
async def google_callback(
    google_callback_request: GoogleCallbackRequest,
    request: Request,
    db: AsyncSession = Depends(get_db),
):
    # Get authorization code Google sent back to you
    code = google_callback_request.code
    print("code: %s" % code)

    # Find out what URL to hit to get tokens that allow you to ask for
    # things on behalf of a user
    google_provider_cfg = get_google_provider_cfg()
    token_endpoint = google_provider_cfg["token_endpoint"]

    # Prepare and send a request to get tokens! Yay, tokens!
    # Not sure why it reverts to regular http:// but change it back to secure connection
    final_redirect_url = str(request.base_url)
    authorization_response = str(request.url)
    # final_redirect_url = final_redirect_url.replace("http://", "https://", 1)
    # authorization_response = authorization_response.replace("http://", "https://", 1)
    print(f"final_redirect_url: {str(final_redirect_url)}")
    print(f"authorization_response: {str(authorization_response)}")

    token_url, headers, body = google_client.prepare_token_request(
        token_endpoint,
        authorization_response=authorization_response,
        redirect_url=final_redirect_url,
        code=code,
    )
    print(f"token_url: {str(token_url)}")
    print(f"headers: {str(headers)}")
    print(f"body: {str(body)}")

    token_response = requests.post(
        token_url,
        headers=headers,
        data=body,
        auth=(
            settings.GOOGLE_CLIENT_ID,
            settings.GOOGLE_CLIENT_SECRET,
        ),
    )
    print(f"token_response: {str(token_response)}")
    print(f"token_response: {str(token_response.json())}")
    # Parse the tokens!
    google_client.parse_request_body_response(json.dumps(token_response.json()))

    # Now that you have tokens (yay) let's find and hit the URL
    # from Google that gives you the user's profile information,
    # including their Google profile image and email
    userinfo_endpoint = google_provider_cfg["userinfo_endpoint"]
    uri, headers, body = google_client.add_token(userinfo_endpoint)
    print(f"uri: {str(uri)}")

    userinfo_response = requests.get(uri, headers=headers, data=body)
    print(f"userinfo_response: {str(userinfo_response)}")

    # You want to make sure their email is verified.
    # The user authenticated with Google, authorized your
    # app, and now you've verified their email through Google!
    if not userinfo_response.json().get("email_verified"):
        return "User email not available or not verified by Google.", 400

    users_email = userinfo_response.json()["email"]
    users_name = userinfo_response.json()["given_name"]
    print(f"users_email: {str(users_email)}")
    print(f"users_name: {str(users_name)}")

    user: Optional[User] = await login_user_origin(users_name, users_email, 1, db)
    if user:
        print("user created and now logging in")

        [access_token, refresh_token] = get_user_tokens(user, 30, 60)
        print(f"access_token: {str(access_token)}")
        print(f"refresh_token: {str(refresh_token)}")

        db.add(user)
        await db.commit()
        await db.refresh(user)

        task = task_generate_avatar.delay(user.avatar_filename(), user.id)
        print(f"running avatar generation! {task}")

        params = dict()
        params["access_token"] = access_token
        params["refresh_token"] = refresh_token

        url_params = urlencode(params)

        # Send user to the world
        request_base_url = str(request.base_url)
        print(f"request_base_url: {str(request_base_url)}")
        world_url = request_base_url.replace("/api_login/google/callback", "/birdaccess")
        world_url_params = world_url + "?" + url_params
        print(f"redirected to the url: {world_url_params}")
        return RedirectResponse(world_url_params)
    else:
        print("user creation failed")
        request_base_url = str(request.base_url)
        login_url = request_base_url.replace("/api_login/google/callback", "/")
        return RedirectResponse(login_url)


@api_router_login.post("/test/call_2", status_code=200)
async def test_call_2() -> dict:
    return {
        "result": True,
    }
