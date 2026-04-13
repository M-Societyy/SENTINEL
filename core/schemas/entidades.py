# sentinel - schemas de entidades
# m-society & c1q_

from datetime import datetime
from typing import Optional
from uuid import UUID

from pydantic import BaseModel, Field


TIPOS_ENTIDAD = [
    "person", "email", "username", "phone", "domain", "ip",
    "organization", "social_profile", "credential", "hash",
    "document", "location"
]

TIPOS_RELACION = [
    "owns", "uses", "associated_with", "located_at", "member_of",
    "leaked_in", "resolves_to", "hosted_on", "registered_by"
]


class EntidadBase(BaseModel):
    tipo: str
    valor: str = Field(..., min_length=1)
    nombre_display: Optional[str] = None
    confianza: float = Field(default=0.5, ge=0.0, le=1.0)
    datos: dict = Field(default_factory=dict)
    tags: list[str] = Field(default_factory=list)


class CrearEntidad(EntidadBase):
    investigacion_id: UUID
    fuentes: list[str] = Field(default_factory=list)


class ActualizarEntidad(BaseModel):
    nombre_display: Optional[str] = None
    confianza: Optional[float] = Field(default=None, ge=0.0, le=1.0)
    datos: Optional[dict] = None
    tags: Optional[list[str]] = None


class RespuestaEntidad(EntidadBase):
    id: UUID
    investigacion_id: UUID
    fuentes: list
    primera_vez: datetime
    ultima_vez: datetime
    creado_en: datetime

    model_config = {"from_attributes": True}


class RelacionBase(BaseModel):
    entidad_origen_id: UUID
    entidad_destino_id: UUID
    tipo_relacion: str
    confianza: float = Field(default=0.5, ge=0.0, le=1.0)
    datos: dict = Field(default_factory=dict)
    fuente: Optional[str] = None


class CrearRelacion(RelacionBase):
    investigacion_id: UUID


class RespuestaRelacion(RelacionBase):
    id: UUID
    investigacion_id: UUID
    creado_en: datetime

    model_config = {"from_attributes": True}


class BusquedaEntidades(BaseModel):
    tipo: Optional[str] = None
    consulta: Optional[str] = None
    confianza_minima: float = Field(default=0.0, ge=0.0, le=1.0)
    limite: int = Field(default=50, ge=1, le=500)
    offset: int = Field(default=0, ge=0)


class GrafoRespuesta(BaseModel):
    nodos: list[RespuestaEntidad]
    aristas: list[RespuestaRelacion]
    total_nodos: int
    total_aristas: int
