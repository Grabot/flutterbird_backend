from app.api.api_v1 import api_router_v1
from app.celery_worker.tasks import task_activate_celery


@api_router_v1.get("/test/call", status_code=200)
async def test_call() -> dict:
    task = task_activate_celery.delay()
    return {
        "result": True,
        "task": task,
    }
