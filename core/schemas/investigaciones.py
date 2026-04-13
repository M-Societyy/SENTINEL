# sentinel - schemas de investigaciones
# m-society & c1q_

from datetime import datetime
from typing import Optional
from uuid import UUID

from pydantic import BaseModel, Field


class SemillaBase(BaseModel):
    tipo: str = Field(..., pattern="^(email|domain|ip|username|phone|person|organization)$")
    valor: str = Field(..., min_length=1)
    metadata_extra: dict = Field(default_factory=dict)


class CrearSemilla(SemillaBase):
    pass


class RespuestaSemilla(SemillaBase):
    id: UUID
    investigacion_id: UUID
    creado_en: datetime

    model_config = {"from_attributes": True}


class InvestigacionBase(BaseModel):
    nombre: str = Field(..., min_length=1, max_length=255)
    descripcion: Optional[str] = None
    proposito: str = Field(..., min_length=10)


class CrearInvestigacion(InvestigacionBase):
    semillas: list[CrearSemilla] = Field(default_factory=list)
    configuracion_modulos: dict = Field(default_factory=dict)
    presupuesto_api: int = Field(default=1000, ge=0)
    profundidad_maxima: int = Field(default=2, ge=1, le=5)
    tags: list[str] = Field(default_factory=list)


class ActualizarInvestigacion(BaseModel):
    nombre: Optional[str] = None
    descripcion: Optional[str] = None
    estado: Optional[str] = Field(default=None, pattern="^(active|paused|archived|completed)$")
    configuracion_modulos: Optional[dict] = None
    presupuesto_api: Optional[int] = None
    profundidad_maxima: Optional[int] = None
    tags: Optional[list[str]] = None


class RespuestaInvestigacion(InvestigacionBase):
    id: UUID
    estado: str
    operador_id: UUID
    configuracion_modulos: dict
    presupuesto_api: int
    llamadas_api_usadas: int
    profundidad_maxima: int
    tags: list
    semillas: list[RespuestaSemilla] = []
    creado_en: datetime
    actualizado_en: datetime

    model_config = {"from_attributes": True}


class ListaInvestigaciones(BaseModel):
    total: int
    investigaciones: list[RespuestaInvestigacion]
