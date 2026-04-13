# sentinel - endpoints de entidades
# m-society & c1q_

from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy import select, func
from sqlalchemy.ext.asyncio import AsyncSession

from auth.seguridad import obtener_usuario_actual
from db.session import obtener_sesion
from models.entidades import Entidad, RelacionEntidad
from models.usuarios import Usuario
from schemas.entidades import (
    CrearEntidad,
    ActualizarEntidad,
    RespuestaEntidad,
    CrearRelacion,
    RespuestaRelacion,
    GrafoRespuesta,
)

router = APIRouter(prefix="/entities", tags=["entidades"])


@router.get("", response_model=list[RespuestaEntidad])
async def listar_entidades(
    investigacion_id: UUID = Query(...),
    tipo: str = Query(default=None),
    consulta: str = Query(default=None),
    confianza_min: float = Query(default=0.0, ge=0.0, le=1.0),
    limite: int = Query(default=50, ge=1, le=500),
    offset: int = Query(default=0, ge=0),
    sesion: AsyncSession = Depends(obtener_sesion),
    usuario: Usuario = Depends(obtener_usuario_actual),
):
    """lista entidades de una investigacion con filtros"""
    q = select(Entidad).where(
        Entidad.investigacion_id == investigacion_id,
        Entidad.confianza >= confianza_min,
    )

    if tipo:
        q = q.where(Entidad.tipo == tipo)
    if consulta:
        q = q.where(Entidad.valor.ilike(f"%{consulta}%"))

    q = q.order_by(Entidad.confianza.desc()).offset(offset).limit(limite)
    resultado = await sesion.execute(q)
    return resultado.scalars().all()


@router.post("", response_model=RespuestaEntidad, status_code=201)
async def crear_entidad(
    datos: CrearEntidad,
    sesion: AsyncSession = Depends(obtener_sesion),
    usuario: Usuario = Depends(obtener_usuario_actual),
):
    """crea una nueva entidad manualmente"""
    entidad = Entidad(
        investigacion_id=datos.investigacion_id,
        tipo=datos.tipo,
        valor=datos.valor,
        nombre_display=datos.nombre_display,
        confianza=datos.confianza,
        datos=datos.datos,
        fuentes=datos.fuentes,
        tags=datos.tags,
    )
    sesion.add(entidad)
    await sesion.flush()
    return entidad


@router.get("/{entidad_id}", response_model=RespuestaEntidad)
async def obtener_entidad(
    entidad_id: UUID,
    sesion: AsyncSession = Depends(obtener_sesion),
    usuario: Usuario = Depends(obtener_usuario_actual),
):
    """obtiene una entidad por id"""
    resultado = await sesion.execute(
        select(Entidad).where(Entidad.id == entidad_id)
    )
    entidad = resultado.scalar_one_or_none()
    if not entidad:
        raise HTTPException(status_code=404, detail="entidad no encontrada")
    return entidad


@router.patch("/{entidad_id}", response_model=RespuestaEntidad)
async def actualizar_entidad(
    entidad_id: UUID,
    datos: ActualizarEntidad,
    sesion: AsyncSession = Depends(obtener_sesion),
    usuario: Usuario = Depends(obtener_usuario_actual),
):
    """actualiza datos de una entidad"""
    resultado = await sesion.execute(
        select(Entidad).where(Entidad.id == entidad_id)
    )
    entidad = resultado.scalar_one_or_none()
    if not entidad:
        raise HTTPException(status_code=404, detail="entidad no encontrada")

    campos = datos.model_dump(exclude_unset=True)
    for campo, valor in campos.items():
        setattr(entidad, campo, valor)
    await sesion.flush()
    return entidad


@router.get("/graph/{investigacion_id}", response_model=GrafoRespuesta)
async def obtener_grafo(
    investigacion_id: UUID,
    tipo: str = Query(default=None),
    confianza_min: float = Query(default=0.0),
    sesion: AsyncSession = Depends(obtener_sesion),
    usuario: Usuario = Depends(obtener_usuario_actual),
):
    """obtiene el grafo completo de entidades y relaciones de una investigacion"""
    q_nodos = select(Entidad).where(
        Entidad.investigacion_id == investigacion_id,
        Entidad.confianza >= confianza_min,
    )
    if tipo:
        q_nodos = q_nodos.where(Entidad.tipo == tipo)

    q_aristas = select(RelacionEntidad).where(
        RelacionEntidad.investigacion_id == investigacion_id,
        RelacionEntidad.confianza >= confianza_min,
    )

    nodos = (await sesion.execute(q_nodos)).scalars().all()
    aristas = (await sesion.execute(q_aristas)).scalars().all()

    return GrafoRespuesta(
        nodos=nodos,
        aristas=aristas,
        total_nodos=len(nodos),
        total_aristas=len(aristas),
    )


@router.post("/relations", response_model=RespuestaRelacion, status_code=201)
async def crear_relacion(
    datos: CrearRelacion,
    sesion: AsyncSession = Depends(obtener_sesion),
    usuario: Usuario = Depends(obtener_usuario_actual),
):
    """crea una relacion entre dos entidades"""
    relacion = RelacionEntidad(
        investigacion_id=datos.investigacion_id,
        entidad_origen_id=datos.entidad_origen_id,
        entidad_destino_id=datos.entidad_destino_id,
        tipo_relacion=datos.tipo_relacion,
        confianza=datos.confianza,
        datos=datos.datos,
        fuente=datos.fuente,
    )
    sesion.add(relacion)
    await sesion.flush()
    return relacion
