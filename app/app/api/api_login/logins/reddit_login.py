from base64 import b64encode
from typing import Optional
from urllib.parse import urlencode

import requests
from fastapi import Depends, Request, status
from fastapi.responses import RedirectResponse
from pydantic import BaseModel
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.api_login import api_router_login
from app.api.api_login.logins.login_user_origin import login_user_origin
from app.celery_worker.tasks import task_generate_avatar
from app.config.config import settings
from app.database import get_db
from app.models import User
from app.util.util import get_user_tokens


@api_router_login.get("/reddit", status_code=200)
async def login_reddit(
    request: Request,
):
    # Find out what URL to hit for Reddit login
    print("loging reddit")
    reddit_base_url = settings.REDDIT_AUTHORIZE
    params = dict()
    params["client_id"] = settings.REDDIT_CLIENT_ID
    params["duration"] = "temporary"
    params["redirect_uri"] = settings.REDDIT_REDIRECT
    params["response_type"] = "code"
    params["scope"] = "identity"
    params["state"] = "x"

    url_params = urlencode(params)
    reddit_url = reddit_base_url + "/?" + url_params
    print("testing url: %s" % reddit_url)

    return RedirectResponse(reddit_url, status_code=status.HTTP_302_FOUND)


class RedditCallbackRequest(BaseModel):
    code: str


@api_router_login.route("/reddit/callback", methods=["GET", "POST"])
async def reddit_callback(
    reddit_callback_request: RedditCallbackRequest,
    request: Request,
    db: AsyncSession = Depends(get_db),
):
    # Get authorization code Reddit sent back to you
    code = reddit_callback_request.code
    print(f"code: {code}")
    access_base_url = settings.REDDIT_ACCESS

    token_post_data = {
        "grant_type": "authorization_code",
        "code": code,
        "redirect_uri": settings.REDDIT_REDIRECT,
    }
    print(f"token_post_data: {token_post_data}")

    encoded_authorization = "%s:%s" % (
        settings.REDDIT_CLIENT_ID,
        settings.REDDIT_CLIENT_SECRET,
    )
    print(f"encoded_authorization: {encoded_authorization}")

    http_auth = b64encode(encoded_authorization.encode("utf-8")).decode("utf-8")
    authorization = "Basic %s" % http_auth
    headers = {
        "Accept": "application/json",
        "User-agent": "age of gold login bot 0.1",
        "Authorization": authorization,
    }

    token_response = requests.post(access_base_url, headers=headers, data=token_post_data)
    print(f"token_response: {token_response}")

    reddit_response_json = token_response.json()
    print(f"reddit_response_json: {reddit_response_json}")

    headers_authorization = {
        "Accept": "application/json",
        "User-agent": "app of gold login bot 0.1",
        "Authorization": "bearer %s" % reddit_response_json["access_token"],
    }
    authorization_url = settings.REDDIT_USER

    authorization_response = requests.get(authorization_url, headers=headers_authorization)
    print(f"authorization_response: {authorization_response}")

    reddit_user = authorization_response.json()
    print(f"reddit_user: {reddit_user}")

    users_name = reddit_user["name"]
    users_email = "%s@reddit.com" % users_name  # Reddit gives no email

    user: Optional[User] = await login_user_origin(users_name, users_email, 3, db)

    if user:
        print("user creation reddit success")
        [access_token, refresh_token] = get_user_tokens(user, 30, 60)

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
        world_url = request_base_url.replace("/login/reddit/callback", "/birdaccess")
        world_url_params = world_url + "?" + url_params
        print(f"redirected to the url: {world_url_params}")
        return RedirectResponse(world_url_params)
    else:
        print("user creation reddit failed")
        request_base_url = str(request.base_url)
        login_url = request_base_url.replace("/login/reddit/callback", "/")
        return RedirectResponse(login_url)
