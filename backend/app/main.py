from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from app.api.routes import router
from app.core.config import get_settings


settings = get_settings()

app = FastAPI(
    title="ShivShakti: Securing the Agentic Future",
    description="Enterprise-grade AI security command center for autonomous agents.",
    version="1.0.0",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.allowed_origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(router, prefix=settings.api_prefix)


@app.get("/")
def root():
    return {
        "name": "ShivShakti",
        "tagline": "Securing the Agentic Future",
        "docs": "/docs",
        "health": f"{settings.api_prefix}/health",
    }

