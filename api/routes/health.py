"""Health check route for the SecureTrap API."""

from fastapi import APIRouter

from api.schemas import HealthResponse

router = APIRouter()


@router.get("/health", response_model=HealthResponse)
def health() -> HealthResponse:
    """Report that the API process itself is running.

    Deliberately has no dependencies and performs no I/O — this only
    confirms the API process is alive, not that any downstream
    component (database, model, Cowrie) is healthy. Deterministic:
    always the same response.
    """
    return HealthResponse(status="ok")