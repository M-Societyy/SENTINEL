# sentinel - schemas de reportes
# m-society & c1q_

from datetime import datetime
from typing import Optional
from uuid import UUID

from pydantic import BaseModel, Field


class CrearReporte(BaseModel):
    investigacion_id: UUID
    titulo: str = Field(..., min_length=1, max_length=255)
    tipo: str = Field(..., pattern="^(pdf|html|json|csv|stix)$")
    configuracion: dict = Field(default_factory=dict)


class RespuestaReporte(BaseModel):
    id: UUID
    investigacion_id: UUID
    titulo: str
    tipo: str
    resumen_ejecutivo: Optional[str] = None
    ruta_archivo: Optional[str] = None
    generado_por: UUID
    creado_en: datetime

    model_config = {"from_attributes": True}
