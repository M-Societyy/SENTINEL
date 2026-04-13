# sentinel - endpoints de reportes
# c1q_ (M-Society team)

from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Query
from fastapi.responses import FileResponse
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from auth.seguridad import obtener_usuario_actual, registrar_auditoria
from db.session import obtener_sesion
from models.reportes import Reporte
from models.usuarios import Usuario
from schemas.reportes import CrearReporte, RespuestaReporte

router = APIRouter(prefix="/reports", tags=["reportes"])


@router.get("", response_model=list[RespuestaReporte])
async def listar_reportes(
    investigacion_id: UUID = Query(default=None),
    sesion: AsyncSession = Depends(obtener_sesion),
    usuario: Usuario = Depends(obtener_usuario_actual),
):
    """lista reportes generados"""
    q = select(Reporte)
    if investigacion_id:
        q = q.where(Reporte.investigacion_id == investigacion_id)
    q = q.order_by(Reporte.creado_en.desc())

    resultado = await sesion.execute(q)
    return resultado.scalars().all()


@router.post("", response_model=RespuestaReporte, status_code=201)
async def generar_reporte(
    datos: CrearReporte,
    sesion: AsyncSession = Depends(obtener_sesion),
    usuario: Usuario = Depends(obtener_usuario_actual),
):
    """genera un nuevo reporte de una investigacion"""
    reporte = Reporte(
        investigacion_id=datos.investigacion_id,
        titulo=datos.titulo,
        tipo=datos.tipo,
        generado_por=usuario.id,
        configuracion=datos.configuracion,
    )
    sesion.add(reporte)
    await sesion.flush()

    # despachar generacion a celery
    from tasks.celery_app import generar_reporte_task
    generar_reporte_task.delay(str(reporte.id), datos.tipo, datos.configuracion)

    return reporte


@router.get("/{reporte_id}", response_model=RespuestaReporte)
async def obtener_reporte(
    reporte_id: UUID,
    sesion: AsyncSession = Depends(obtener_sesion),
    usuario: Usuario = Depends(obtener_usuario_actual),
):
    """obtiene info de un reporte"""
    resultado = await sesion.execute(
        select(Reporte).where(Reporte.id == reporte_id)
    )
    reporte = resultado.scalar_one_or_none()
    if not reporte:
        raise HTTPException(status_code=404, detail="reporte no encontrado")
    return reporte


@router.get("/{reporte_id}/download")
async def descargar_reporte(
    reporte_id: UUID,
    sesion: AsyncSession = Depends(obtener_sesion),
    usuario: Usuario = Depends(obtener_usuario_actual),
):
    """descarga el archivo del reporte"""
    resultado = await sesion.execute(
        select(Reporte).where(Reporte.id == reporte_id)
    )
    reporte = resultado.scalar_one_or_none()
    if not reporte:
        raise HTTPException(status_code=404, detail="reporte no encontrado")

    if not reporte.ruta_archivo:
        raise HTTPException(status_code=404, detail="archivo del reporte aun no generado")

    return FileResponse(
        reporte.ruta_archivo,
        filename=f"{reporte.titulo}.{reporte.tipo}",
    )
