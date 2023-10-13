from datetime import datetime
from typing import Optional

from fastapi import Depends, Request, Response
from pydantic import BaseModel
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.api_v1 import api_router_v1
from app.database import get_db
from app.models import User
from app.models.leaderboard_one_player import LeaderboardOnePlayer
from app.sockets.sockets import sio
from app.util.rest_util import get_failed_response
from app.util.util import check_token, get_auth_token


class UpdateLeaderboardAllOnePlayerRequest(BaseModel):
    score: int


@api_router_v1.post("/update/leaderboard/one_player", status_code=200)
async def update_leaderboard_one_player(
    update_leaderboard_all_one_player_request: UpdateLeaderboardAllOnePlayerRequest,
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

    score = update_leaderboard_all_one_player_request.score

    now = datetime.utcnow()

    new_leaderboard_update = LeaderboardOnePlayer(
        score=score, user_name=user_update.username, user_id=user_update.id, timestamp=now
    )
    db.add(new_leaderboard_update)
    await db.commit()

    socket_response = {
        "score": score,
        "user_name": user_update.username,
        "user_id": user_update.id,
        "timestamp": now.strftime("%Y-%m-%dT%H:%M:%S.%f"),
    }

    await sio.emit("update_leaderboard", socket_response)

    return {"result": True, "message": "leaderboard updated with your score"}
