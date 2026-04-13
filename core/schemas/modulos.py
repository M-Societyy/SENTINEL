# sentinel - schemas de modulos osint
# c1q_ (M-Society team)

from typing import Optional, Any
from uuid import UUID

from pydantic import BaseModel, Field


class EjecutarModulo(BaseModel):
    investigacion_id: UUID
    modulo: str = Field(..., min_length=1)
    objetivo: str = Field(..., min_length=1)
    parametros: dict = Field(default_factory=dict)


class ResultadoModulo(BaseModel):
    modulo: str
    estado: str  # running, completed, error
    entidades_encontradas: int = 0
    relaciones_creadas: int = 0
    errores: list[str] = Field(default_factory=list)
    datos: dict = Field(default_factory=dict)
    duracion_segundos: Optional[float] = None


class EstadoModulo(BaseModel):
    nombre: str
    categoria: str
    descripcion: str
    requiere_api_key: bool = False
    api_key_configurada: bool = False
    habilitado: bool = True


class ListaModulos(BaseModel):
    modulos: list[EstadoModulo]
    total: int


class ResultadoEnriquecimiento(BaseModel):
    fuente: str
    tipo: str
    datos: dict = Field(default_factory=dict)
    confianza: float = Field(default=0.5, ge=0.0, le=1.0)
    entidades_nuevas: list[dict] = Field(default_factory=list)
    relaciones_nuevas: list[dict] = Field(default_factory=list)
    error: Optional[str] = None
