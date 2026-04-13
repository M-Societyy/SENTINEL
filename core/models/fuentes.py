# sentinel - modelo de fuentes de datos
# c1q_ (M-Society team)

import uuid
from datetime import datetime

from sqlalchemy import String, DateTime, Text, ForeignKey, JSON
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import Mapped, mapped_column

from db.session import Base


class Fuente(Base):
    __tablename__ = "fuentes"

    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), primary_key=True, default=uuid.uuid4
    )
    investigacion_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("investigaciones.id"), nullable=False, index=True
    )
    modulo: Mapped[str] = mapped_column(String(100), nullable=False)
    tipo_fuente: Mapped[str] = mapped_column(String(50), nullable=False)  # api, scraping, dns, whois, etc
    url: Mapped[str] = mapped_column(Text, nullable=True)
    datos_crudos: Mapped[dict] = mapped_column(JSON, default=dict)
    timestamp: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)
    estado: Mapped[str] = mapped_column(String(20), default="success")  # success, error, timeout
    error_mensaje: Mapped[str] = mapped_column(Text, nullable=True)
