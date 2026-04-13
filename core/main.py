# sentinel - aplicacion principal fastapi
# m-society & c1q_
# plataforma osint enterprise - version 1.0.0

import asyncio
from contextlib import asynccontextmanager

from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import ORJSONResponse
import structlog
from prometheus_fastapi_instrumentator import Instrumentator

from config import config
from db.session import inicializar_db, cerrar_db
from api.v1.auth import router as auth_router
from api.v1.investigations import router as investigations_router
from api.v1.entities import router as entities_router
from api.v1.modules import router as modules_router
from api.v1.reports import router as reports_router
from api.v1.feeds import router as feeds_router

# configurar structlog
structlog.configure(
    processors=[
        structlog.stdlib.filter_by_level,
        structlog.stdlib.add_logger_name,
        structlog.stdlib.add_log_level,
        structlog.processors.TimeStamper(fmt="iso"),
        structlog.processors.JSONRenderer() if config.ambiente == "production"
        else structlog.dev.ConsoleRenderer(),
    ],
    wrapper_class=structlog.stdlib.BoundLogger,
    context_class=dict,
    logger_factory=structlog.stdlib.LoggerFactory(),
)

log = structlog.get_logger()

DISCLAIMER = """
╔══════════════════════════════════════════════════════════════════╗
║  SENTINEL v1.0.0 - plataforma osint by m-society & c1q_        ║
║                                                                  ║
║  esta herramienta esta disenada exclusivamente para:             ║
║  - investigaciones de seguridad autorizadas                      ║
║  - investigacion academica y periodismo                          ║
║  - threat intelligence corporativa sobre activos propios         ║
║  - ejercicios de red team/blue team autorizados                  ║
║                                                                  ║
║  el uso indebido de esta herramienta es responsabilidad          ║
║  exclusiva del usuario. respeta las leyes aplicables:            ║
║  cfaa, gdpr, lopd y legislacion local.                           ║
╚══════════════════════════════════════════════════════════════════╝
"""


@asynccontextmanager
async def lifespan(app: FastAPI):
    """ciclo de vida de la app - startup y shutdown"""
    log.info("sentinel iniciando", version=config.version, ambiente=config.ambiente)
    print(DISCLAIMER)
    await inicializar_db()
    log.info("base de datos inicializada")
    yield
    await cerrar_db()
    log.info("sentinel detenido")


app = FastAPI(
    title="SENTINEL",
    description="plataforma osint enterprise by m-society & c1q_",
    version=config.version,
    default_response_class=ORJSONResponse,
    lifespan=lifespan,
    docs_url="/api/docs",
    redoc_url="/api/redoc",
    openapi_url="/api/openapi.json",
)

# cors
app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:3000", "http://localhost:5173", "http://localhost:80"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# prometheus metricas
Instrumentator().instrument(app).expose(app, endpoint="/api/v1/metrics")

# registrar routers
app.include_router(auth_router, prefix="/api/v1")
app.include_router(investigations_router, prefix="/api/v1")
app.include_router(entities_router, prefix="/api/v1")
app.include_router(modules_router, prefix="/api/v1")
app.include_router(reports_router, prefix="/api/v1")
app.include_router(feeds_router, prefix="/api/v1")


@app.get("/api/v1/health")
async def health_check():
    """endpoint de health check"""
    return {
        "estado": "operativo",
        "version": config.version,
        "nombre": config.nombre_app,
        "autor": "m-society & c1q_",
    }


@app.get("/api/v1/info")
async def info():
    """informacion general de la plataforma"""
    return {
        "nombre": "SENTINEL",
        "version": config.version,
        "autor": "m-society & c1q_",
        "descripcion": "plataforma unificada de inteligencia de fuentes abiertas",
        "disclaimer": "uso exclusivo para investigaciones autorizadas",
        "capacidades": [
            "identity intelligence",
            "network intelligence",
            "social media intelligence",
            "breach & leak intelligence",
            "dark web intelligence",
            "threat intelligence",
            "company intelligence",
            "metadata intelligence",
            "correlacion de entidades",
            "visualizacion de grafos",
            "generacion de reportes",
        ],
    }
