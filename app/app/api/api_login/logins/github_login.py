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


@api_router_login.get("/github", status_code=200)
async def login_github(
    request: Request,
):
    # Find out what URL to hit for GitHub login
    print("loging github")
    base_url = settings.GITHUB_AUTHORIZE
    params = dict()
    params["client_id"] = settings.GITHUB_CLIENT_ID

    url_params = urlencode(params)
    github_url = base_url + "/?" + url_params
    print("testing url: %s" % github_url)
    return RedirectResponse(github_url, status_code=status.HTTP_302_FOUND)


class GithubCallbackRequest(BaseModel):
    code: str


@api_router_login.route("/github/callback", methods=["GET", "POST"])
async def github_callback(
    github_callback_request: GithubCallbackRequest,
    request: Request,
    db: AsyncSession = Depends(get_db),
):
    # Get authorization code GitHub sent back to you
    code = github_callback_request.code
    print(f"code: {code}")
    access_base_url = settings.GITHUB_ACCESS
    params = dict()
    params["client_id"] = settings.GITHUB_CLIENT_ID
    params["client_secret"] = settings.GITHUB_CLIENT_SECRET
    params["code"] = code

    url_params = urlencode(params)
    github_post_url = access_base_url + "/?" + url_params
    print(f"github_post_url: {str(github_post_url)}")

    headers = {
        "Accept": "application/json",
    }
    token_response = requests.post(github_post_url, headers=headers)
    print(f"token_response: {str(token_response)}")

    github_response_json = token_response.json()
    print(f"github_response_json: {str(github_response_json)}")

    headers_authorization = {
        "Accept": "application/json",
        "Authorization": "Bearer %s" % github_response_json["access_token"],
    }
    authorization_url = settings.GITHUB_USER

    authorization_response = requests.get(authorization_url, headers=headers_authorization)
    print(f"authorization_response: {str(authorization_response)}")

    github_user = authorization_response.json()
    print(f"github_user: {str(github_user)}")

    users_name = github_user["login"]
    users_email = github_user["email"]

    user: Optional[User] = await login_user_origin(users_name, users_email, 2, db)

    if user:
        print("user create success github")
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
        world_url = request_base_url.replace("/login/github/callback", "/birdaccess")
        world_url_params = world_url + "?" + url_params
        print(f"redirected to the url: {world_url_params}")
        return RedirectResponse(world_url_params)
    else:
        print("user creation github failed")
        request_base_url = str(request.base_url)
        login_url = request_base_url.replace("/login/github/callback", "/")
        return RedirectResponse(login_url)
