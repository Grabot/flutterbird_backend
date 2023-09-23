from fastapi import APIRouter

api_router_v1 = APIRouter()

from . import email, message, settings, social, user_access
