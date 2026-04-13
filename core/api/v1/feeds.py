# sentinel - endpoints de threat intelligence feeds
# c1q_ (M-Society team)

from fastapi import APIRouter, Depends
from pydantic import BaseModel, Field

from auth.seguridad import obtener_usuario_actual
from models.usuarios import Usuario

router = APIRouter(prefix="/feeds", tags=["feeds"])


class FeedConfig(BaseModel):
    nombre: str
    url: str
    tipo: str  # stix, csv, json, txt
    activo: bool = True
    intervalo_minutos: int = Field(default=60, ge=5)


class FeedEstado(BaseModel):
    nombre: str
    url: str
    tipo: str
    activo: bool
    ultima_actualizacion: str = None
    total_iocs: int = 0
    estado: str = "pendiente"


# feeds preconfigurados
FEEDS_DEFAULT = [
    FeedEstado(nombre="abuse.ch URLhaus", url="https://urlhaus.abuse.ch/downloads/csv_recent/", tipo="csv", activo=True),
    FeedEstado(nombre="abuse.ch Feodo Tracker", url="https://feodotracker.abuse.ch/downloads/ipblocklist.csv", tipo="csv", activo=True),
    FeedEstado(nombre="abuse.ch SSL Blacklist", url="https://sslbl.abuse.ch/blacklist/sslblacklist.csv", tipo="csv", activo=True),
    FeedEstado(nombre="AlienVault OTX", url="https://otx.alienvault.com/api/v1/pulses/subscribed", tipo="json", activo=False),
    FeedEstado(nombre="Tor Exit Nodes", url="https://check.torproject.org/torbulkexitlist", tipo="txt", activo=True),
    FeedEstado(nombre="Spamhaus DROP", url="https://www.spamhaus.org/drop/drop.txt", tipo="txt", activo=True),
]


@router.get("", response_model=list[FeedEstado])
async def listar_feeds(
    usuario: Usuario = Depends(obtener_usuario_actual),
):
    """lista todos los feeds de threat intelligence configurados"""
    return FEEDS_DEFAULT


@router.post("", response_model=FeedEstado)
async def agregar_feed(
    feed: FeedConfig,
    usuario: Usuario = Depends(obtener_usuario_actual),
):
    """agrega un nuevo feed de threat intelligence"""
    nuevo = FeedEstado(
        nombre=feed.nombre,
        url=feed.url,
        tipo=feed.tipo,
        activo=feed.activo,
    )
    FEEDS_DEFAULT.append(nuevo)
    return nuevo
