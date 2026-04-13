# sentinel - consumidor de feeds de threat intelligence
# c1q_ (M-Society team)

import asyncio
import csv
import io
from typing import Optional

import structlog

from modules.base import ModuloBase
from schemas.modulos import ResultadoEnriquecimiento

log = structlog.get_logger()


class ThreatFeeds(ModuloBase):
    nombre = "threat_feeds"
    categoria = "threat"
    descripcion = "consumo de feeds publicos de threat intelligence"

    FEEDS = {
        "urlhaus": "https://urlhaus.abuse.ch/downloads/csv_recent/",
        "feodo_tracker": "https://feodotracker.abuse.ch/downloads/ipblocklist.csv",
        "ssl_blacklist": "https://sslbl.abuse.ch/blacklist/sslblacklist.csv",
        "tor_exit_nodes": "https://check.torproject.org/torbulkexitlist",
        "spamhaus_drop": "https://www.spamhaus.org/drop/drop.txt",
    }

    async def ejecutar(self, objetivo: str, parametros: dict = None) -> ResultadoEnriquecimiento:
        """objetivo es el ioc a buscar en los feeds"""
        ioc = objetivo.strip().lower()
        parametros = parametros or {}
        feeds_seleccionados = parametros.get("feeds", list(self.FEEDS.keys()))

        resultados = {"ioc": ioc}
        encontrado_en = []

        tareas = []
        nombres = []
        for nombre, url in self.FEEDS.items():
            if nombre in feeds_seleccionados:
                tareas.append(self._buscar_en_feed(ioc, nombre, url))
                nombres.append(nombre)

        resultados_tareas = await asyncio.gather(*tareas, return_exceptions=True)

        for i, resultado in enumerate(resultados_tareas):
            if isinstance(resultado, Exception):
                continue
            if resultado and resultado.get("encontrado"):
                encontrado_en.append(nombres[i])
                resultados[nombres[i]] = resultado

        resultados["encontrado_en"] = encontrado_en
        resultados["total_feeds_verificados"] = len(tareas)

        return ResultadoEnriquecimiento(
            fuente=self.nombre, tipo="threat",
            datos=resultados,
            confianza=min(0.3 + (len(encontrado_en) * 0.2), 1.0),
        )

    async def _buscar_en_feed(self, ioc: str, nombre: str, url: str) -> Optional[dict]:
        resp = await self.request_con_rate_limit(url, servicio="default", timeout=30.0)
        if not resp or resp.status_code != 200:
            return None

        contenido = resp.text.lower()

        if ioc in contenido:
            # buscar linea con contexto
            lineas_match = []
            for linea in contenido.split("\n"):
                if ioc in linea and not linea.startswith("#"):
                    lineas_match.append(linea.strip()[:300])

            return {
                "encontrado": True,
                "feed": nombre,
                "url_feed": url,
                "coincidencias": len(lineas_match),
                "contexto": lineas_match[:5],
            }

        return {"encontrado": False, "feed": nombre}
