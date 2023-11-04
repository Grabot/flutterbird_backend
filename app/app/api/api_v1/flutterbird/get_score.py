from typing import Optional

from fastapi import Depends, Request, Response
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.api_v1 import api_router_v1
from app.database import get_db
from app.models import User
from app.util.rest_util import get_failed_response
from app.util.util import check_token, get_auth_token


@api_router_v1.post("/score/get", status_code=200)
async def get_score(
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

    return {
        "result": True,
        "score": {
            "total_flutters": user.total_flutters,
            "total_pipes_cleared": user.total_pipes_cleared,
            "total_games": user.total_games,
            "best_score_single_bird": user.best_score_single_bird,
            "best_score_double_bird": user.best_score_double_bird,
        },
    }
