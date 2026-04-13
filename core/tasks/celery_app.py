# sentinel - configuracion de celery y tareas principales
# m-society & c1q_

from celery import Celery
from config import config

celery_app = Celery(
    "sentinel",
    broker=config.redis_url,
    backend=config.redis_url,
)

celery_app.conf.update(
    task_serializer="json",
    accept_content=["json"],
    result_serializer="json",
    timezone="UTC",
    enable_utc=True,
    task_track_started=True,
    task_acks_late=True,
    worker_prefetch_multiplier=1,
    result_expires=3600,
)


@celery_app.task(name="ejecutar_modulo", bind=True, max_retries=3)
def ejecutar_modulo_task(self, investigacion_id, modulo, objetivo, parametros, usuario_id):
    """tarea para ejecutar un modulo osint de forma asincrona"""
    import asyncio
    from engine.pipeline import ejecutar_modulo_pipeline

    try:
        resultado = asyncio.run(
            ejecutar_modulo_pipeline(investigacion_id, modulo, objetivo, parametros, usuario_id)
        )
        return resultado
    except Exception as exc:
        self.retry(exc=exc, countdown=60 * (self.request.retries + 1))


@celery_app.task(name="generar_reporte", bind=True)
def generar_reporte_task(self, reporte_id, tipo, configuracion):
    """tarea para generar un reporte"""
    import asyncio
    # se implementara en fase 8
    return {"estado": "completado", "reporte_id": reporte_id}


@celery_app.task(name="actualizar_feeds")
def actualizar_feeds_task():
    """tarea periodica para actualizar feeds de threat intel"""
    # se implementara con los feeds
    return {"estado": "completado"}


# tareas periodicas
celery_app.conf.beat_schedule = {
    "actualizar-feeds-cada-hora": {
        "task": "actualizar_feeds",
        "schedule": 3600.0,
    },
}
