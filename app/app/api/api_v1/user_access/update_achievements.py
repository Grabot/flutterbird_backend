import json
from typing import Optional

from fastapi import Depends, Request, Response
from pydantic import BaseModel
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.api_v1 import api_router_v1
from app.database import get_db
from app.models import User
from app.util.rest_util import get_failed_response
from app.util.util import check_token, get_auth_token


class UpdateAchievementsRequest(BaseModel):
    achievements_dict: dict


@api_router_v1.post("/achievements/update", status_code=200)
async def update_achievements(
    update_achievements_request: UpdateAchievementsRequest,
    request: Request,
    response: Response,
    db: AsyncSession = Depends(get_db),
) -> dict:
    auth_token = get_auth_token(request.headers.get("Authorization"))
    if auth_token == "":
        return get_failed_response("an error occurred", response)

    user_update: Optional[User] = await check_token(db, auth_token)
    if not user_update:
        return get_failed_response("an error occurred", response)

    achievements_dict = update_achievements_request.achievements_dict
    achievements_user = json.loads(user_update.achievements)
    for key in achievements_dict:
        achievements_user[key] = achievements_dict[key]

    user_update.achievements = json.dumps(achievements_user)
    db.add(user_update)
    await db.commit()

    return {"result": True, "message": "achievements updated"}
