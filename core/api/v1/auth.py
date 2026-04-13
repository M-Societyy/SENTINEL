# sentinel - endpoints de autenticacion
# m-society & c1q_

from datetime import datetime

from fastapi import APIRouter, Depends, HTTPException, status, Request
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from auth.seguridad import (
    hashear_password,
    verificar_password,
    crear_token_acceso,
    crear_refresh_token,
    decodificar_token,
    obtener_usuario_actual,
    requiere_rol,
    registrar_auditoria,
)
from config import config
from db.session import obtener_sesion
from models.usuarios import Usuario
from schemas.usuarios import (
    CrearUsuario,
    LoginRequest,
    TokenRespuesta,
    RespuestaUsuario,
    RefreshTokenRequest,
)

router = APIRouter(prefix="/auth", tags=["autenticacion"])


@router.post("/registro", response_model=RespuestaUsuario, status_code=201)
async def registrar_usuario(
    datos: CrearUsuario,
    request: Request,
    sesion: AsyncSession = Depends(obtener_sesion),
):
    """registra un nuevo usuario en el sistema"""
    # verificar que no exista
    existente = await sesion.execute(
        select(Usuario).where(
            (Usuario.nombre_usuario == datos.nombre_usuario) |
            (Usuario.email == datos.email)
        )
    )
    if existente.scalar_one_or_none():
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="nombre de usuario o email ya registrado",
        )

    usuario = Usuario(
        nombre_usuario=datos.nombre_usuario,
        email=datos.email,
        hash_password=hashear_password(datos.password),
        nombre_completo=datos.nombre_completo,
        rol=datos.rol,
    )
    sesion.add(usuario)
    await sesion.flush()

    await registrar_auditoria(
        sesion=sesion,
        usuario_id=usuario.id,
        accion="registro",
        recurso_tipo="usuario",
        recurso_id=str(usuario.id),
        ip_origen=request.client.host if request.client else None,
        user_agent=request.headers.get("user-agent"),
    )

    return usuario


@router.post("/login", response_model=TokenRespuesta)
async def login(
    datos: LoginRequest,
    request: Request,
    sesion: AsyncSession = Depends(obtener_sesion),
):
    """autenticacion con credenciales, retorna jwt tokens"""
    resultado = await sesion.execute(
        select(Usuario).where(Usuario.nombre_usuario == datos.nombre_usuario)
    )
    usuario = resultado.scalar_one_or_none()

    if not usuario or not verificar_password(datos.password, usuario.hash_password):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="credenciales incorrectas",
        )

    if not usuario.activo:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="cuenta desactivada",
        )

    # actualizar ultimo login
    usuario.ultimo_login = datetime.utcnow()
    await sesion.flush()

    access_token = crear_token_acceso({"sub": str(usuario.id), "rol": usuario.rol})
    refresh_token = crear_refresh_token({"sub": str(usuario.id)})

    await registrar_auditoria(
        sesion=sesion,
        usuario_id=usuario.id,
        accion="login",
        recurso_tipo="sesion",
        ip_origen=request.client.host if request.client else None,
        user_agent=request.headers.get("user-agent"),
    )

    return TokenRespuesta(
        access_token=access_token,
        refresh_token=refresh_token,
        expira_en=config.expiracion_token_minutos * 60,
    )


@router.post("/refresh", response_model=TokenRespuesta)
async def refresh_token(
    datos: RefreshTokenRequest,
    sesion: AsyncSession = Depends(obtener_sesion),
):
    """renueva el access token usando el refresh token"""
    payload = decodificar_token(datos.refresh_token)

    if payload.get("tipo") != "refresh":
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="token de tipo invalido, se espera refresh token",
        )

    usuario_id = payload.get("sub")
    resultado = await sesion.execute(
        select(Usuario).where(Usuario.id == usuario_id)
    )
    usuario = resultado.scalar_one_or_none()

    if not usuario or not usuario.activo:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="usuario no encontrado o desactivado",
        )

    access_token = crear_token_acceso({"sub": str(usuario.id), "rol": usuario.rol})
    refresh_token = crear_refresh_token({"sub": str(usuario.id)})

    return TokenRespuesta(
        access_token=access_token,
        refresh_token=refresh_token,
        expira_en=config.expiracion_token_minutos * 60,
    )


@router.get("/me", response_model=RespuestaUsuario)
async def perfil_actual(usuario: Usuario = Depends(obtener_usuario_actual)):
    """retorna el perfil del usuario autenticado"""
    return usuario
