# sentinel - endpoints de investigaciones
# c1q_ (M-Society team)

from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, status, Request, Query
from sqlalchemy import select, func
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from auth.seguridad import obtener_usuario_actual, registrar_auditoria
from db.session import obtener_sesion
from models.investigaciones import Investigacion, SemillaInvestigacion
from models.usuarios import Usuario
from schemas.investigaciones import (
    CrearInvestigacion,
    ActualizarInvestigacion,
    RespuestaInvestigacion,
    ListaInvestigaciones,
)

router = APIRouter(prefix="/investigations", tags=["investigaciones"])


@router.get("", response_model=ListaInvestigaciones)
async def listar_investigaciones(
    estado: str = Query(default=None),
    limite: int = Query(default=20, ge=1, le=100),
    offset: int = Query(default=0, ge=0),
    sesion: AsyncSession = Depends(obtener_sesion),
    usuario: Usuario = Depends(obtener_usuario_actual),
):
    """lista todas las investigaciones del usuario"""
    consulta = select(Investigacion).options(selectinload(Investigacion.semillas))

    # los viewers y analysts solo ven sus propias investigaciones
    if usuario.rol != "admin":
        consulta = consulta.where(Investigacion.operador_id == usuario.id)

    if estado:
        consulta = consulta.where(Investigacion.estado == estado)

    # contar total
    total_q = select(func.count()).select_from(consulta.subquery())
    total = (await sesion.execute(total_q)).scalar()

    # paginar
    consulta = consulta.order_by(Investigacion.creado_en.desc()).offset(offset).limit(limite)
    resultado = await sesion.execute(consulta)
    investigaciones = resultado.scalars().all()

    return ListaInvestigaciones(
        total=total,
        investigaciones=investigaciones,
    )


@router.post("", response_model=RespuestaInvestigacion, status_code=201)
async def crear_investigacion(
    datos: CrearInvestigacion,
    request: Request,
    sesion: AsyncSession = Depends(obtener_sesion),
    usuario: Usuario = Depends(obtener_usuario_actual),
):
    """crea una nueva investigacion con sus semillas"""
    investigacion = Investigacion(
        nombre=datos.nombre,
        descripcion=datos.descripcion,
        proposito=datos.proposito,
        operador_id=usuario.id,
        configuracion_modulos=datos.configuracion_modulos,
        presupuesto_api=datos.presupuesto_api,
        profundidad_maxima=datos.profundidad_maxima,
        tags=datos.tags,
    )
    sesion.add(investigacion)
    await sesion.flush()

    # agregar semillas
    for semilla_datos in datos.semillas:
        semilla = SemillaInvestigacion(
            investigacion_id=investigacion.id,
            tipo=semilla_datos.tipo,
            valor=semilla_datos.valor,
            metadata_extra=semilla_datos.metadata_extra,
        )
        sesion.add(semilla)

    await sesion.flush()

    await registrar_auditoria(
        sesion=sesion,
        usuario_id=usuario.id,
        accion="crear_investigacion",
        recurso_tipo="investigacion",
        recurso_id=str(investigacion.id),
        detalles={"nombre": datos.nombre, "semillas": len(datos.semillas)},
        ip_origen=request.client.host if request.client else None,
    )

    # recargar con semillas
    resultado = await sesion.execute(
        select(Investigacion)
        .options(selectinload(Investigacion.semillas))
        .where(Investigacion.id == investigacion.id)
    )
    return resultado.scalar_one()


@router.get("/{investigacion_id}", response_model=RespuestaInvestigacion)
async def obtener_investigacion(
    investigacion_id: UUID,
    sesion: AsyncSession = Depends(obtener_sesion),
    usuario: Usuario = Depends(obtener_usuario_actual),
):
    """obtiene una investigacion por su id"""
    resultado = await sesion.execute(
        select(Investigacion)
        .options(selectinload(Investigacion.semillas))
        .where(Investigacion.id == investigacion_id)
    )
    investigacion = resultado.scalar_one_or_none()

    if not investigacion:
        raise HTTPException(status_code=404, detail="investigacion no encontrada")

    if usuario.rol != "admin" and investigacion.operador_id != usuario.id:
        raise HTTPException(status_code=403, detail="sin permisos para esta investigacion")

    return investigacion


@router.patch("/{investigacion_id}", response_model=RespuestaInvestigacion)
async def actualizar_investigacion(
    investigacion_id: UUID,
    datos: ActualizarInvestigacion,
    request: Request,
    sesion: AsyncSession = Depends(obtener_sesion),
    usuario: Usuario = Depends(obtener_usuario_actual),
):
    """actualiza una investigacion existente"""
    resultado = await sesion.execute(
        select(Investigacion)
        .options(selectinload(Investigacion.semillas))
        .where(Investigacion.id == investigacion_id)
    )
    investigacion = resultado.scalar_one_or_none()

    if not investigacion:
        raise HTTPException(status_code=404, detail="investigacion no encontrada")

    if usuario.rol != "admin" and investigacion.operador_id != usuario.id:
        raise HTTPException(status_code=403, detail="sin permisos")

    campos_actualizar = datos.model_dump(exclude_unset=True)
    for campo, valor in campos_actualizar.items():
        setattr(investigacion, campo, valor)

    await sesion.flush()

    await registrar_auditoria(
        sesion=sesion,
        usuario_id=usuario.id,
        accion="actualizar_investigacion",
        recurso_tipo="investigacion",
        recurso_id=str(investigacion_id),
        detalles=campos_actualizar,
        ip_origen=request.client.host if request.client else None,
    )

    return investigacion


@router.delete("/{investigacion_id}", status_code=204)
async def eliminar_investigacion(
    investigacion_id: UUID,
    request: Request,
    sesion: AsyncSession = Depends(obtener_sesion),
    usuario: Usuario = Depends(obtener_usuario_actual),
):
    """archiva una investigacion (no se elimina fisicamente)"""
    resultado = await sesion.execute(
        select(Investigacion).where(Investigacion.id == investigacion_id)
    )
    investigacion = resultado.scalar_one_or_none()

    if not investigacion:
        raise HTTPException(status_code=404, detail="investigacion no encontrada")

    if usuario.rol != "admin" and investigacion.operador_id != usuario.id:
        raise HTTPException(status_code=403, detail="sin permisos")

    investigacion.estado = "archived"
    await sesion.flush()

    await registrar_auditoria(
        sesion=sesion,
        usuario_id=usuario.id,
        accion="archivar_investigacion",
        recurso_tipo="investigacion",
        recurso_id=str(investigacion_id),
        ip_origen=request.client.host if request.client else None,
    )
