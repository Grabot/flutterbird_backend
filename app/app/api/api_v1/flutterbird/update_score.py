from typing import Optional

from fastapi import Depends, Request, Response
from pydantic import BaseModel
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.api_v1 import api_router_v1
from app.database import get_db
from app.models import User
from app.util.rest_util import get_failed_response
from app.util.util import check_token, get_auth_token


class ScoreUpdateRequest(BaseModel):
    best_score_single_bird: Optional[int]
    best_score_double_bird: Optional[int]
    total_flutters: int
    total_pipes_cleared: int
    total_games: int


@api_router_v1.post("/score/update", status_code=200)
async def update_score(
    score_update_request: ScoreUpdateRequest,
    request: Request,
    response: Response,
    db: AsyncSession = Depends(get_db),
) -> dict:
    auth_token = get_auth_token(request.headers.get("Authorization"))

    if auth_token == "":
        return get_failed_response("An error occurred", response)

    user: Optional[User] = await check_token(db, auth_token)
    if not user:
        return get_failed_response("An error occurred", response)

    best_score_single_bird = score_update_request.best_score_single_bird
    best_score_double_bird = score_update_request.best_score_double_bird
    total_flutters = score_update_request.total_flutters
    total_pipes_cleared = score_update_request.total_pipes_cleared
    total_games = score_update_request.total_games
    # A final check to make sure the score only goes up

    if best_score_single_bird:
        if best_score_single_bird > user.best_score_single_bird:
            user.best_score_single_bird = best_score_single_bird
    if best_score_double_bird:
        if best_score_double_bird > user.best_score_double_bird:
            user.best_score_double_bird = best_score_double_bird
    if total_flutters > user.total_flutters:
        user.total_flutters = total_flutters
    if total_pipes_cleared > user.total_pipes_cleared:
        user.total_pipes_cleared = total_pipes_cleared
    if total_games > user.total_games:
        user.total_games = total_games
    db.add(user)
    await db.commit()

    return {
        "result": True,
        "message": "users score updated",
    }
