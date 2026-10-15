from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse
from fastapi.exceptions import RequestValidationError
from fastapi.middleware.cors import CORSMiddleware
from app.core.config import settings
from app.api.routes_gateway import router as gateway_router
from app.api.routes_logs import router as logs_router
from app.api.routes_rules import router as rules_router

app = FastAPI(
    title=settings.PROJECT_NAME,
    version=settings.VERSION,
    description="Security gateway preventing sensitive data leakage and prompt injection before reaching AI models.",
)

# CORS configuration to allow local frontend communication
app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.ALLOWED_ORIGINS,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Mount API routers
app.include_router(gateway_router, prefix=settings.API_PREFIX)
app.include_router(logs_router, prefix=settings.API_PREFIX)
app.include_router(rules_router, prefix=settings.API_PREFIX)


@app.exception_handler(RequestValidationError)
async def validation_exception_handler(request: Request, exc: RequestValidationError):
    """
    Prevents reflection of raw payloads or sensitive parameters on schema validation errors.
    """
    return JSONResponse(
        status_code=422,
        content={"detail": "Request validation failed. Please check field formats."},
    )


@app.exception_handler(Exception)
async def generic_exception_handler(request: Request, exc: Exception):
    """
    Prevents leakage of internal stack traces, system paths, or secret values on unhandled errors.
    """
    return JSONResponse(
        status_code=500,
        content={"detail": "An internal error occurred while processing the security gateway request."},
    )


@app.get("/")
def root():
    return {
        "service": settings.PROJECT_NAME,
        "status": "online",
        "docs_url": "/docs",
    }


@app.get("/api/health")
def health_check():
    return {"status": "healthy", "service": "SentinelAI Gateway"}
