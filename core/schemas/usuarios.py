# sentinel - schemas de usuarios
# c1q_ (M-Society team)

from datetime import datetime
from typing import Optional
from uuid import UUID

from pydantic import BaseModel, EmailStr, Field


class UsuarioBase(BaseModel):
    nombre_usuario: str = Field(..., min_length=3, max_length=100)
    email: str = Field(..., max_length=255)
    nombre_completo: Optional[str] = None


class CrearUsuario(UsuarioBase):
    password: str = Field(..., min_length=8, max_length=128)
    rol: str = Field(default="analyst", pattern="^(admin|analyst|viewer)$")


class ActualizarUsuario(BaseModel):
    nombre_completo: Optional[str] = None
    email: Optional[str] = None
    rol: Optional[str] = Field(default=None, pattern="^(admin|analyst|viewer)$")
    activo: Optional[bool] = None


class RespuestaUsuario(UsuarioBase):
    id: UUID
    rol: str
    activo: bool
    avatar_url: Optional[str] = None
    ultimo_login: Optional[datetime] = None
    creado_en: datetime

    model_config = {"from_attributes": True}


class LoginRequest(BaseModel):
    nombre_usuario: str
    password: str


class TokenRespuesta(BaseModel):
    access_token: str
    refresh_token: str
    tipo_token: str = "bearer"
    expira_en: int


class RefreshTokenRequest(BaseModel):
    refresh_token: str
