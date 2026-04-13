# sentinel - utilidades de seguridad jwt y hashing
# c1q_ (M-Society team)

from datetime import datetime, timedelta
from typing import Optional
from uuid import UUID

from fastapi import Depends, HTTPException, status, Request
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from jose import JWTError, jwt
from passlib.context import CryptContext
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from config import config
from db.session import obtener_sesion
from models.usuarios import Usuario
from models.auditoria import LogAuditoria

contexto_password = CryptContext(schemes=["bcrypt"], deprecated="auto")
esquema_seguridad = HTTPBearer()


def hashear_password(password: str) -> str:
    """genera hash bcrypt del password"""
    return contexto_password.hash(password)


def verificar_password(password_plano: str, password_hash: str) -> bool:
    """verifica un password contra su hash"""
    return contexto_password.verify(password_plano, password_hash)


def crear_token_acceso(datos: dict, expira_delta: Optional[timedelta] = None) -> str:
    """crea un jwt token de acceso"""
    a_codificar = datos.copy()
    if expira_delta:
        expiracion = datetime.utcnow() + expira_delta
    else:
        expiracion = datetime.utcnow() + timedelta(minutes=config.expiracion_token_minutos)
    a_codificar.update({"exp": expiracion, "tipo": "access"})
    token = jwt.encode(a_codificar, config.secret_key, algorithm=config.algoritmo_jwt)
    return token


def crear_refresh_token(datos: dict) -> str:
    """crea un jwt refresh token"""
    a_codificar = datos.copy()
    expiracion = datetime.utcnow() + timedelta(days=config.expiracion_refresh_dias)
    a_codificar.update({"exp": expiracion, "tipo": "refresh"})
    token = jwt.encode(a_codificar, config.secret_key, algorithm=config.algoritmo_jwt)
    return token


def decodificar_token(token: str) -> dict:
    """decodifica y valida un jwt token"""
    try:
        payload = jwt.decode(token, config.secret_key, algorithms=[config.algoritmo_jwt])
        return payload
    except JWTError:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="token invalido o expirado",
            headers={"WWW-Authenticate": "Bearer"},
        )


async def obtener_usuario_actual(
    credenciales: HTTPAuthorizationCredentials = Depends(esquema_seguridad),
    sesion: AsyncSession = Depends(obtener_sesion),
) -> Usuario:
    """obtiene el usuario actual desde el token jwt"""
    payload = decodificar_token(credenciales.credentials)

    if payload.get("tipo") != "access":
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="tipo de token invalido",
        )

    usuario_id = payload.get("sub")
    if usuario_id is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="token sin identificador de usuario",
        )

    resultado = await sesion.execute(
        select(Usuario).where(Usuario.id == UUID(usuario_id))
    )
    usuario = resultado.scalar_one_or_none()

    if usuario is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="usuario no encontrado",
        )

    if not usuario.activo:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="usuario desactivado",
        )

    return usuario


def requiere_rol(roles_permitidos: list[str]):
    """dependencia para verificar roles"""
    async def verificar_rol(usuario: Usuario = Depends(obtener_usuario_actual)):
        if usuario.rol not in roles_permitidos:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"rol '{usuario.rol}' no tiene permisos para esta accion",
            )
        return usuario
    return verificar_rol


async def registrar_auditoria(
    sesion: AsyncSession,
    usuario_id: Optional[UUID],
    accion: str,
    recurso_tipo: str,
    recurso_id: Optional[str] = None,
    detalles: dict = None,
    ip_origen: Optional[str] = None,
    user_agent: Optional[str] = None,
):
    """registra una accion en el log de auditoria"""
    log = LogAuditoria(
        usuario_id=usuario_id,
        accion=accion,
        recurso_tipo=recurso_tipo,
        recurso_id=recurso_id,
        detalles=detalles or {},
        ip_origen=ip_origen,
        user_agent=user_agent,
    )
    sesion.add(log)
    await sesion.flush()
