# sentinel - modelo de investigaciones
# m-society & c1q_

import uuid
from datetime import datetime

from sqlalchemy import String, DateTime, Text, ForeignKey, Integer, JSON
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import Mapped, mapped_column, relationship

from db.session import Base


class Investigacion(Base):
    __tablename__ = "investigaciones"

    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), primary_key=True, default=uuid.uuid4
    )
    nombre: Mapped[str] = mapped_column(String(255), nullable=False)
    descripcion: Mapped[str] = mapped_column(Text, nullable=True)
    estado: Mapped[str] = mapped_column(
        String(20), default="active"
    )  # active, paused, archived, completed
    proposito: Mapped[str] = mapped_column(Text, nullable=False)
    operador_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("usuarios.id"), nullable=False
    )
    configuracion_modulos: Mapped[dict] = mapped_column(JSON, default=dict)
    presupuesto_api: Mapped[int] = mapped_column(Integer, default=1000)
    llamadas_api_usadas: Mapped[int] = mapped_column(Integer, default=0)
    profundidad_maxima: Mapped[int] = mapped_column(Integer, default=2)
    tags: Mapped[list] = mapped_column(JSON, default=list)
    creado_en: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)
    actualizado_en: Mapped[datetime] = mapped_column(
        DateTime, default=datetime.utcnow, onupdate=datetime.utcnow
    )

    semillas = relationship("SemillaInvestigacion", back_populates="investigacion")


class SemillaInvestigacion(Base):
    __tablename__ = "semillas_investigacion"

    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), primary_key=True, default=uuid.uuid4
    )
    investigacion_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("investigaciones.id"), nullable=False
    )
    tipo: Mapped[str] = mapped_column(
        String(50), nullable=False
    )  # email, domain, ip, username, phone, person, organization
    valor: Mapped[str] = mapped_column(Text, nullable=False)
    metadata_extra: Mapped[dict] = mapped_column(JSON, default=dict)
    creado_en: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)

    investigacion = relationship("Investigacion", back_populates="semillas")
