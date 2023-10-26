from datetime import datetime, timedelta

from fastapi import Depends, Request
from sqlalchemy import asc, desc
from sqlalchemy.ext.asyncio import AsyncSession
from sqlmodel import select

from app.api.api_v1 import api_router_v1
from app.database import get_db
from app.models.leaderboard_one_player import LeaderboardOnePlayer


@api_router_v1.get("/get/leaderboard/one_player", status_code=200)
async def get_leaderboard_one_player(request: Request, db: AsyncSession = Depends(get_db)):
    current_time = datetime.utcnow()
    day_ago = current_time - timedelta(days=1)
    week_ago = current_time - timedelta(days=7)
    month_ago = current_time - timedelta(days=31)
    year_ago = current_time - timedelta(days=365)

    leaderboard_size = 10
    # We combine all the results together. On the frontend we will sort them by timestamp
    statement = (
        select(LeaderboardOnePlayer)
        .order_by(desc(LeaderboardOnePlayer.score), asc(LeaderboardOnePlayer.timestamp))
        .limit(leaderboard_size)
    ).union(
        (
            select(LeaderboardOnePlayer)
            .filter(LeaderboardOnePlayer.timestamp > year_ago)
            .order_by(desc(LeaderboardOnePlayer.score), asc(LeaderboardOnePlayer.timestamp))
            .limit(leaderboard_size)
        ).union(
            (
                select(LeaderboardOnePlayer)
                .filter(LeaderboardOnePlayer.timestamp > month_ago)
                .order_by(desc(LeaderboardOnePlayer.score), asc(LeaderboardOnePlayer.timestamp))
                .limit(leaderboard_size)
            ).union(
                (
                    select(LeaderboardOnePlayer)
                    .filter(LeaderboardOnePlayer.timestamp > week_ago)
                    .order_by(desc(LeaderboardOnePlayer.score), asc(LeaderboardOnePlayer.timestamp))
                    .limit(leaderboard_size)
                ).union(
                    (
                        select(LeaderboardOnePlayer)
                        .filter(LeaderboardOnePlayer.timestamp > day_ago)
                        .order_by(
                            desc(LeaderboardOnePlayer.score), asc(LeaderboardOnePlayer.timestamp)
                        )
                        .limit(leaderboard_size)
                    )
                )
            )
        )
    )
    leaderboard_statement = await db.execute(statement)
    all_leaders = leaderboard_statement.all()

    leaders = []
    for lead in all_leaders:
        leader = LeaderboardOnePlayer(**dict(lead))
        leaders.append(leader.serialize)

    return {"result": True, "leaders": leaders}
