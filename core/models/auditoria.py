# sentinel - log de auditoria inmutable
# m-society & c1q_

import uuid
from datetime import datetime

from sqlalchemy import String, DateTime, Text, ForeignKey, JSON
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import Mapped, mapped_column

from db.session import Base


class LogAuditoria(Base):
    __tablename__ = "log_auditoria"

    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), primary_key=True, default=uuid.uuid4
    )
    usuario_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("usuarios.id"), nullable=True
    )
    accion: Mapped[str] = mapped_column(String(100), nullable=False)
    recurso_tipo: Mapped[str] = mapped_column(String(50), nullable=False)
    recurso_id: Mapped[str] = mapped_column(String(100), nullable=True)
    detalles: Mapped[dict] = mapped_column(JSON, default=dict)
    ip_origen: Mapped[str] = mapped_column(String(45), nullable=True)
    user_agent: Mapped[str] = mapped_column(Text, nullable=True)
    timestamp: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow, index=True)
