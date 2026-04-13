# sentinel - enriquecimiento de indicadores de compromiso
# c1q_ (M-Society team)

import asyncio
import re
from typing import Optional

import structlog

from config import config
from modules.base import ModuloBase
from schemas.modulos import ResultadoEnriquecimiento

log = structlog.get_logger()


class IocEnricher(ModuloBase):
    nombre = "ioc_enricher"
    categoria = "threat"
    descripcion = "enriquecimiento de iocs contra multiples fuentes de threat intel"
    requiere_api_key = True

    async def ejecutar(self, objetivo: str, parametros: dict = None) -> ResultadoEnriquecimiento:
        ioc = objetivo.strip()
        tipo_ioc = self._detectar_tipo_ioc(ioc)

        entidades = []
        relaciones = []
        resultados = {"ioc": ioc, "tipo": tipo_ioc}

        tareas = [
            self._otx_alienvault(ioc, tipo_ioc),
            self._urlhaus(ioc, tipo_ioc),
            self._malwarebazaar(ioc, tipo_ioc),
            self._threatfox(ioc, tipo_ioc),
        ]

        if config.virustotal_api_key:
            tareas.append(self._virustotal(ioc, tipo_ioc))
        if config.urlscan_api_key:
            tareas.append(self._urlscan(ioc, tipo_ioc))

        resultados_tareas = await asyncio.gather(*tareas, return_exceptions=True)
        fuentes_con_datos = 0

        nombres_fuentes = ["otx", "urlhaus", "malwarebazaar", "threatfox"]
        if config.virustotal_api_key:
            nombres_fuentes.append("virustotal")
        if config.urlscan_api_key:
            nombres_fuentes.append("urlscan")

        for i, resultado in enumerate(resultados_tareas):
            if isinstance(resultado, Exception):
                continue
            if resultado:
                nombre_fuente = nombres_fuentes[i] if i < len(nombres_fuentes) else f"fuente_{i}"
                resultados[nombre_fuente] = resultado
                fuentes_con_datos += 1

                # extraer tags y ttps de cada fuente
                for tag in resultado.get("tags", []):
                    entidades.append({
                        "tipo": "hash", "valor": f"tag:{tag}",
                        "datos": {"tipo": "threat_tag", "fuente": nombre_fuente},
                        "confianza": 0.6,
                    })

        # calcular score de amenaza
        score_amenaza = min(fuentes_con_datos * 0.2, 1.0)
        resultados["score_amenaza"] = score_amenaza
        resultados["fuentes_con_datos"] = fuentes_con_datos

        self._entidades_encontradas = len(entidades)

        return ResultadoEnriquecimiento(
            fuente=self.nombre, tipo=tipo_ioc,
            datos=resultados, confianza=score_amenaza,
            entidades_nuevas=entidades,
            relaciones_nuevas=relaciones,
        )

    def _detectar_tipo_ioc(self, ioc: str) -> str:
        if re.match(r'^[a-fA-F0-9]{32}$', ioc):
            return "md5"
        if re.match(r'^[a-fA-F0-9]{40}$', ioc):
            return "sha1"
        if re.match(r'^[a-fA-F0-9]{64}$', ioc):
            return "sha256"
        if re.match(r'^https?://', ioc):
            return "url"
        if re.match(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$', ioc):
            return "ip"
        if re.match(r'^[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$', ioc):
            return "domain"
        return "unknown"

    async def _otx_alienvault(self, ioc: str, tipo: str) -> Optional[dict]:
        tipo_map = {"ip": "IPv4", "domain": "domain", "url": "url", "md5": "file", "sha1": "file", "sha256": "file"}
        otx_tipo = tipo_map.get(tipo)
        if not otx_tipo:
            return None

        seccion = "general"
        if tipo in ("md5", "sha1", "sha256"):
            url = f"https://otx.alienvault.com/api/v1/indicators/file/{ioc}/{seccion}"
        elif tipo == "ip":
            url = f"https://otx.alienvault.com/api/v1/indicators/IPv4/{ioc}/{seccion}"
        elif tipo == "domain":
            url = f"https://otx.alienvault.com/api/v1/indicators/domain/{ioc}/{seccion}"
        elif tipo == "url":
            url = f"https://otx.alienvault.com/api/v1/indicators/url/{ioc}/{seccion}"
        else:
            return None

        resp = await self.request_con_rate_limit(url, servicio="default")
        if resp and resp.status_code == 200:
            datos = resp.json()
            pulses = datos.get("pulse_info", {}).get("pulses", [])
            return {
                "encontrado": True,
                "total_pulses": len(pulses),
                "pulses": [{"nombre": p.get("name"), "descripcion": p.get("description", "")[:200], "tags": p.get("tags", []), "creado": p.get("created")} for p in pulses[:10]],
                "tags": datos.get("pulse_info", {}).get("related", {}).get("alienvault", {}).get("tags", []),
                "reputacion": datos.get("reputation"),
            }
        return None

    async def _urlhaus(self, ioc: str, tipo: str) -> Optional[dict]:
        if tipo not in ("url", "domain", "ip", "md5", "sha256"):
            return None

        if tipo == "url":
            url = "https://urlhaus-api.abuse.ch/v1/url/"
            data = {"url": ioc}
        elif tipo == "domain":
            url = "https://urlhaus-api.abuse.ch/v1/host/"
            data = {"host": ioc}
        elif tipo == "ip":
            url = "https://urlhaus-api.abuse.ch/v1/host/"
            data = {"host": ioc}
        elif tipo in ("md5", "sha256"):
            url = "https://urlhaus-api.abuse.ch/v1/payload/"
            data = {f"{tipo}_hash": ioc}
        else:
            return None

        resp = await self.request_con_rate_limit(url, servicio="default", metodo="POST", json_data=data)
        if resp and resp.status_code == 200:
            datos = resp.json()
            if datos.get("query_status") == "ok" or datos.get("query_status") == "no_results":
                return {
                    "encontrado": datos.get("query_status") == "ok",
                    "urls_count": datos.get("urls_count", 0),
                    "urls": datos.get("urls", [])[:10],
                    "tags": datos.get("tags", []),
                    "threat": datos.get("threat"),
                    "blacklists": datos.get("blacklists", {}),
                }
        return None

    async def _malwarebazaar(self, ioc: str, tipo: str) -> Optional[dict]:
        if tipo not in ("md5", "sha1", "sha256"):
            return None

        url = "https://mb-api.abuse.ch/api/v1/"
        data = {"query": "get_info", "hash": ioc}

        resp = await self.request_con_rate_limit(url, servicio="default", metodo="POST", json_data=data)
        if resp and resp.status_code == 200:
            datos = resp.json()
            if datos.get("query_status") == "ok":
                muestra = datos.get("data", [{}])[0] if datos.get("data") else {}
                return {
                    "encontrado": True,
                    "nombre": muestra.get("file_name"),
                    "tipo": muestra.get("file_type"),
                    "tamano": muestra.get("file_size"),
                    "firma": muestra.get("signature"),
                    "tags": muestra.get("tags", []),
                    "primera_vez": muestra.get("first_seen"),
                    "ultima_vez": muestra.get("last_seen"),
                    "pais_origen": muestra.get("origin_country"),
                    "reporter": muestra.get("reporter"),
                }
        return None

    async def _threatfox(self, ioc: str, tipo: str) -> Optional[dict]:
        url = "https://threatfox-api.abuse.ch/api/v1/"
        data = {"query": "search_ioc", "search_term": ioc}

        resp = await self.request_con_rate_limit(url, servicio="default", metodo="POST", json_data=data)
        if resp and resp.status_code == 200:
            datos = resp.json()
            if datos.get("query_status") == "ok":
                items = datos.get("data", [])
                return {
                    "encontrado": True,
                    "total": len(items),
                    "indicadores": [{
                        "tipo_ioc": i.get("ioc_type"),
                        "tipo_amenaza": i.get("threat_type"),
                        "malware": i.get("malware"),
                        "confianza": i.get("confidence_level"),
                        "primera_vez": i.get("first_seen_utc"),
                        "tags": i.get("tags", []),
                    } for i in items[:10]],
                    "tags": list(set(t for i in items for t in (i.get("tags") or []))),
                }
        return None

    async def _virustotal(self, ioc: str, tipo: str) -> Optional[dict]:
        from modules.threat.virustotal_client import VirusTotalClient
        vt = VirusTotalClient()
        resultado = await vt.ejecutar(ioc, {"tipo": tipo})
        if resultado and resultado.datos:
            return resultado.datos.get("analisis")
        return None

    async def _urlscan(self, ioc: str, tipo: str) -> Optional[dict]:
        if tipo not in ("url", "domain", "ip"):
            return None

        url = "https://urlscan.io/api/v1/search/"
        headers = {"API-Key": config.urlscan_api_key}
        query = f"page.domain:{ioc}" if tipo == "domain" else f"page.ip:{ioc}" if tipo == "ip" else f"page.url:{ioc}"
        params = {"q": query, "size": 10}

        resp = await self.request_con_rate_limit(url, servicio="urlscan", headers=headers, params=params)
        if resp and resp.status_code == 200:
            datos = resp.json()
            resultados = datos.get("results", [])
            return {
                "total": datos.get("total", 0),
                "scans": [{
                    "url": r.get("page", {}).get("url"),
                    "dominio": r.get("page", {}).get("domain"),
                    "ip": r.get("page", {}).get("ip"),
                    "pais": r.get("page", {}).get("country"),
                    "servidor": r.get("page", {}).get("server"),
                    "fecha": r.get("task", {}).get("time"),
                    "screenshot": r.get("screenshot"),
                } for r in resultados[:10]],
            }
        return None
