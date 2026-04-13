# sentinel - resolucion y deduplicacion de entidades
# c1q_ (M-Society team)

import uuid
from datetime import datetime
from typing import Optional

from sqlalchemy import select, and_
from sqlalchemy.ext.asyncio import AsyncSession
import structlog

from models.entidades import Entidad, RelacionEntidad
from schemas.entidades import TIPOS_ENTIDAD

log = structlog.get_logger()


class ResolverEntidades:
    """normaliza, deduplica y fusiona entidades descubiertas por los modulos"""

    def __init__(self, sesion: AsyncSession, investigacion_id: uuid.UUID):
        self.sesion = sesion
        self.investigacion_id = investigacion_id
        self._cache: dict[str, Entidad] = {}

    async def resolver(self, datos_entidad: dict) -> Entidad:
        """resuelve una entidad: si existe la fusiona, si no la crea"""
        tipo = datos_entidad.get("tipo", "").lower()
        valor = self._normalizar_valor(tipo, datos_entidad.get("valor", ""))
        confianza = datos_entidad.get("confianza", 0.5)
        datos_extra = datos_entidad.get("datos", {})
        fuentes = datos_entidad.get("fuentes", [])
        tags = datos_entidad.get("tags", [])

        if not valor:
            log.warning("entidad sin valor, ignorada", tipo=tipo)
            return None

        # buscar en cache primero
        cache_key = f"{tipo}:{valor}"
        if cache_key in self._cache:
            entidad = self._cache[cache_key]
            entidad = await self._fusionar(entidad, confianza, datos_extra, fuentes, tags)
            return entidad

        # buscar en db
        resultado = await self.sesion.execute(
            select(Entidad).where(
                and_(
                    Entidad.investigacion_id == self.investigacion_id,
                    Entidad.tipo == tipo,
                    Entidad.valor == valor,
                )
            )
        )
        entidad_existente = resultado.scalar_one_or_none()

        if entidad_existente:
            entidad = await self._fusionar(entidad_existente, confianza, datos_extra, fuentes, tags)
            self._cache[cache_key] = entidad
            return entidad

        # crear nueva entidad
        entidad = Entidad(
            investigacion_id=self.investigacion_id,
            tipo=tipo,
            valor=valor,
            nombre_display=datos_entidad.get("nombre_display") or self._generar_display(tipo, valor),
            confianza=confianza,
            datos=datos_extra,
            fuentes=fuentes if isinstance(fuentes, list) else [fuentes],
            tags=tags,
        )
        self.sesion.add(entidad)
        await self.sesion.flush()

        self._cache[cache_key] = entidad
        log.debug("entidad creada", tipo=tipo, valor=valor[:50], confianza=confianza)
        return entidad

    async def resolver_relacion(self, datos_relacion: dict) -> Optional[RelacionEntidad]:
        """resuelve una relacion entre dos entidades"""
        origen_valor = datos_relacion.get("origen_valor", "")
        origen_tipo = datos_relacion.get("origen_tipo", "")
        destino_valor = datos_relacion.get("destino_valor", "")
        destino_tipo = datos_relacion.get("destino_tipo", "")
        tipo_relacion = datos_relacion.get("tipo_relacion", "associated_with")

        if not all([origen_valor, origen_tipo, destino_valor, destino_tipo]):
            return None

        # resolver las entidades primero
        entidad_origen = await self.resolver({
            "tipo": origen_tipo,
            "valor": origen_valor,
            "confianza": datos_relacion.get("confianza", 0.5),
        })
        entidad_destino = await self.resolver({
            "tipo": destino_tipo,
            "valor": destino_valor,
            "confianza": datos_relacion.get("confianza", 0.5),
        })

        if not entidad_origen or not entidad_destino:
            return None

        # verificar si la relacion ya existe
        resultado = await self.sesion.execute(
            select(RelacionEntidad).where(
                and_(
                    RelacionEntidad.investigacion_id == self.investigacion_id,
                    RelacionEntidad.entidad_origen_id == entidad_origen.id,
                    RelacionEntidad.entidad_destino_id == entidad_destino.id,
                    RelacionEntidad.tipo_relacion == tipo_relacion,
                )
            )
        )
        existente = resultado.scalar_one_or_none()

        if existente:
            # actualizar confianza si la nueva es mayor
            nueva_confianza = datos_relacion.get("confianza", 0.5)
            if nueva_confianza > existente.confianza:
                existente.confianza = nueva_confianza
            await self.sesion.flush()
            return existente

        # crear nueva relacion
        relacion = RelacionEntidad(
            investigacion_id=self.investigacion_id,
            entidad_origen_id=entidad_origen.id,
            entidad_destino_id=entidad_destino.id,
            tipo_relacion=tipo_relacion,
            confianza=datos_relacion.get("confianza", 0.5),
            datos=datos_relacion.get("datos", {}),
            fuente=datos_relacion.get("fuente"),
        )
        self.sesion.add(relacion)
        await self.sesion.flush()

        log.debug(
            "relacion creada",
            tipo=tipo_relacion,
            origen=f"{origen_tipo}:{origen_valor[:30]}",
            destino=f"{destino_tipo}:{destino_valor[:30]}",
        )
        return relacion

    async def procesar_resultado_modulo(self, resultado) -> dict:
        """procesa el resultado completo de un modulo osint"""
        entidades_creadas = 0
        relaciones_creadas = 0

        # resolver entidades nuevas
        for ent_data in resultado.entidades_nuevas:
            ent_data["fuentes"] = [resultado.fuente]
            entidad = await self.resolver(ent_data)
            if entidad:
                entidades_creadas += 1

        # resolver relaciones
        for rel_data in resultado.relaciones_nuevas:
            rel_data["fuente"] = resultado.fuente
            relacion = await self.resolver_relacion(rel_data)
            if relacion:
                relaciones_creadas += 1

        await self.sesion.flush()

        return {
            "entidades_creadas": entidades_creadas,
            "relaciones_creadas": relaciones_creadas,
        }

    async def _fusionar(
        self,
        entidad: Entidad,
        nueva_confianza: float,
        nuevos_datos: dict,
        nuevas_fuentes: list,
        nuevos_tags: list,
    ) -> Entidad:
        """fusiona datos nuevos en una entidad existente"""
        # confianza acumulativa (promedio ponderado)
        entidad.confianza = min(
            (entidad.confianza + nueva_confianza) / 2 + 0.05,
            1.0,
        )

        # fusionar datos (merge profundo)
        if nuevos_datos:
            datos_actuales = dict(entidad.datos) if entidad.datos else {}
            for k, v in nuevos_datos.items():
                if k not in datos_actuales or datos_actuales[k] is None:
                    datos_actuales[k] = v
            entidad.datos = datos_actuales

        # agregar fuentes nuevas
        if nuevas_fuentes:
            fuentes_actuales = list(entidad.fuentes) if entidad.fuentes else []
            for f in (nuevas_fuentes if isinstance(nuevas_fuentes, list) else [nuevas_fuentes]):
                if f and f not in fuentes_actuales:
                    fuentes_actuales.append(f)
            entidad.fuentes = fuentes_actuales

        # agregar tags nuevos
        if nuevos_tags:
            tags_actuales = list(entidad.tags) if entidad.tags else []
            for t in nuevos_tags:
                if t not in tags_actuales:
                    tags_actuales.append(t)
            entidad.tags = tags_actuales

        entidad.ultima_vez = datetime.utcnow()
        await self.sesion.flush()
        return entidad

    def _normalizar_valor(self, tipo: str, valor: str) -> str:
        """normaliza el valor de una entidad segun su tipo"""
        valor = valor.strip()

        if tipo == "email":
            return valor.lower()
        elif tipo == "domain":
            return valor.lower().rstrip(".")
        elif tipo == "ip":
            return valor.strip()
        elif tipo == "username":
            return valor.lower()
        elif tipo == "phone":
            return valor.replace(" ", "").replace("-", "")
        elif tipo == "hash":
            return valor.lower()
        elif tipo == "url":
            return valor.rstrip("/")

        return valor

    def _generar_display(self, tipo: str, valor: str) -> str:
        """genera un nombre display legible para la entidad"""
        if tipo == "email":
            return valor
        elif tipo == "ip":
            return f"IP: {valor}"
        elif tipo == "domain":
            return valor
        elif tipo == "person":
            return valor.title()
        elif tipo == "organization":
            return valor.title()
        elif tipo == "username":
            return f"@{valor}"
        elif tipo == "phone":
            return valor
        elif tipo == "social_profile":
            return valor
        elif tipo == "credential":
            return f"[LEAK] {valor[:50]}"
        elif tipo == "hash":
            return f"#{valor[:16]}..."
        elif tipo == "document":
            return valor.split("/")[-1][:50]
        elif tipo == "location":
            return valor

        return valor[:50]
