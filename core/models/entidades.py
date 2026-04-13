# sentinel - modelo de entidades y relaciones
# m-society & c1q_

import uuid
from datetime import datetime

from sqlalchemy import String, DateTime, Text, ForeignKey, Float, JSON, Index
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import Mapped, mapped_column

from db.session import Base


class Entidad(Base):
    __tablename__ = "entidades"

    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), primary_key=True, default=uuid.uuid4
    )
    investigacion_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("investigaciones.id"), nullable=False, index=True
    )
    tipo: Mapped[str] = mapped_column(
        String(50), nullable=False, index=True
    )  # person, email, username, phone, domain, ip, organization, social_profile, credential, hash, document, location
    valor: Mapped[str] = mapped_column(Text, nullable=False, index=True)
    nombre_display: Mapped[str] = mapped_column(String(255), nullable=True)
    confianza: Mapped[float] = mapped_column(Float, default=0.5)
    datos: Mapped[dict] = mapped_column(JSON, default=dict)
    fuentes: Mapped[list] = mapped_column(JSON, default=list)
    tags: Mapped[list] = mapped_column(JSON, default=list)
    primera_vez: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)
    ultima_vez: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)
    creado_en: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)
    actualizado_en: Mapped[datetime] = mapped_column(
        DateTime, default=datetime.utcnow, onupdate=datetime.utcnow
    )

    __table_args__ = (
        Index("ix_entidades_inv_tipo", "investigacion_id", "tipo"),
        Index("ix_entidades_inv_valor", "investigacion_id", "valor"),
    )


class RelacionEntidad(Base):
    __tablename__ = "relaciones_entidades"

    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), primary_key=True, default=uuid.uuid4
    )
    investigacion_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("investigaciones.id"), nullable=False, index=True
    )
    entidad_origen_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("entidades.id"), nullable=False, index=True
    )
    entidad_destino_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("entidades.id"), nullable=False, index=True
    )
    tipo_relacion: Mapped[str] = mapped_column(
        String(50), nullable=False
    )  # owns, uses, associated_with, located_at, member_of, leaked_in, resolves_to, hosted_on, registered_by
    confianza: Mapped[float] = mapped_column(Float, default=0.5)
    datos: Mapped[dict] = mapped_column(JSON, default=dict)
    fuente: Mapped[str] = mapped_column(String(100), nullable=True)
    creado_en: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)
