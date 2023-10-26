from datetime import datetime, timedelta

from fastapi import Depends, Request
from sqlalchemy import asc, desc
from sqlalchemy.ext.asyncio import AsyncSession
from sqlmodel import select

from app.api.api_v1 import api_router_v1
from app.database import get_db
from app.models.leaderboard_two_player import LeaderboardTwoPlayer


@api_router_v1.get("/get/leaderboard/two_players", status_code=200)
async def get_leaderboard_two_players(request: Request, db: AsyncSession = Depends(get_db)):
    current_time = datetime.utcnow()
    day_ago = current_time - timedelta(days=1)
    week_ago = current_time - timedelta(days=7)
    month_ago = current_time - timedelta(days=31)
    year_ago = current_time - timedelta(days=365)

    leaderboard_size = 20
    # We combine all the results together. On the frontend we will sort them by timestamp
    statement = (
        select(LeaderboardTwoPlayer)
        .order_by(desc(LeaderboardTwoPlayer.score), asc(LeaderboardTwoPlayer.timestamp))
        .limit(leaderboard_size)
    ).union(
        (
            select(LeaderboardTwoPlayer)
            .filter(LeaderboardTwoPlayer.timestamp > year_ago)
            .order_by(desc(LeaderboardTwoPlayer.score), asc(LeaderboardTwoPlayer.timestamp))
            .limit(leaderboard_size)
        ).union(
            (
                select(LeaderboardTwoPlayer)
                .filter(LeaderboardTwoPlayer.timestamp > month_ago)
                .order_by(desc(LeaderboardTwoPlayer.score), asc(LeaderboardTwoPlayer.timestamp))
                .limit(leaderboard_size)
            ).union(
                (
                    select(LeaderboardTwoPlayer)
                    .filter(LeaderboardTwoPlayer.timestamp > week_ago)
                    .order_by(desc(LeaderboardTwoPlayer.score), asc(LeaderboardTwoPlayer.timestamp))
                    .limit(leaderboard_size)
                ).union(
                    (
                        select(LeaderboardTwoPlayer)
                        .filter(LeaderboardTwoPlayer.timestamp > day_ago)
                        .order_by(
                            desc(LeaderboardTwoPlayer.score), asc(LeaderboardTwoPlayer.timestamp)
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
        leader = LeaderboardTwoPlayer(**dict(lead))
        leaders.append(leader.serialize)

    return {"result": True, "leaders": leaders}
