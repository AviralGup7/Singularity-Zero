"""Router inclusion for the FastAPI dashboard."""

from typing import Any

from fastapi import FastAPI

from src.dashboard.fastapi.config import DashboardConfig
from src.dashboard.fastapi.routers import api_router


def setup_routers(app: FastAPI, config: DashboardConfig | None = None) -> None:
    app.include_router(api_router)
    try:
        from src.api.health import router as survival_router

        if survival_router is not None:
            app.include_router(survival_router)

        @app.middleware("http")
        async def _survival_readonly_guard(request: Any, call_next: Any) -> Any:
            from src.core.recovery.survival import get_survival_state, mutation_blocked

            if mutation_blocked(request.method):
                from fastapi.responses import JSONResponse

                state = get_survival_state()
                return JSONResponse(
                    status_code=503,
                    content={
                        "detail": "SURVIVAL_READONLY",
                        "reason": state.reason,
                    },
                    headers=state.headers(),
                )
            return await call_next(request)
    except Exception:
        pass
