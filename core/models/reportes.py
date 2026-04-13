# sentinel - modelo de reportes
# c1q_ (M-Society team)

import uuid
from datetime import datetime

from sqlalchemy import String, DateTime, Text, ForeignKey, JSON
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import Mapped, mapped_column

from db.session import Base


class Reporte(Base):
    __tablename__ = "reportes"

    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), primary_key=True, default=uuid.uuid4
    )
    investigacion_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("investigaciones.id"), nullable=False, index=True
    )
    titulo: Mapped[str] = mapped_column(String(255), nullable=False)
    tipo: Mapped[str] = mapped_column(String(20), nullable=False)  # pdf, html, json, csv, stix
    resumen_ejecutivo: Mapped[str] = mapped_column(Text, nullable=True)
    contenido: Mapped[dict] = mapped_column(JSON, default=dict)
    ruta_archivo: Mapped[str] = mapped_column(Text, nullable=True)
    generado_por: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("usuarios.id"), nullable=False
    )
    configuracion: Mapped[dict] = mapped_column(JSON, default=dict)
    creado_en: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)
