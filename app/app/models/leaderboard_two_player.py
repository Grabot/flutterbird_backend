from datetime import datetime
from typing import Optional

from sqlmodel import Field, SQLModel


class LeaderboardTwoPlayer(SQLModel, table=True):
    __tablename__ = "LeaderboardTwoPlayer"
    id: Optional[int] = Field(default=None, primary_key=True)

    score: int
    user_name: str
    user_id: int = Field(foreign_key="User.id")
    timestamp: datetime = Field(index=True, default=datetime.utcnow())

    @property
    def serialize(self):
        return {
            "score": self.score,
            "user_name": self.user_name,
            "user_id": self.user_id,
            "timestamp": self.timestamp.strftime("%Y-%m-%dT%H:%M:%S.%f"),
        }
