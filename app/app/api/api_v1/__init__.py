from fastapi import APIRouter

api_router_v1 = APIRouter()

from . import email, flutterbird, leaderboard, message, settings, social, test, user_access
