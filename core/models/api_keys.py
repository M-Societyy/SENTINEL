# sentinel - almacenamiento seguro de api keys
# c1q_ (M-Society team)

import uuid
from datetime import datetime

from sqlalchemy import String, DateTime, Text, Boolean, LargeBinary
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import Mapped, mapped_column

from db.session import Base


class ApiKeyAlmacenada(Base):
    __tablename__ = "api_keys_almacenadas"

    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), primary_key=True, default=uuid.uuid4
    )
    nombre_servicio: Mapped[str] = mapped_column(
        String(100), unique=True, nullable=False, index=True
    )
    clave_encriptada: Mapped[bytes] = mapped_column(LargeBinary, nullable=False)
    iv: Mapped[bytes] = mapped_column(LargeBinary, nullable=False)
    activa: Mapped[bool] = mapped_column(Boolean, default=True)
    notas: Mapped[str] = mapped_column(Text, nullable=True)
    creado_en: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)
    actualizado_en: Mapped[datetime] = mapped_column(
        DateTime, default=datetime.utcnow, onupdate=datetime.utcnow
    )
