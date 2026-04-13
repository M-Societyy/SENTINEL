# sentinel - cliente virustotal api v3
# c1q_ (M-Society team)

import asyncio
from typing import Optional

import structlog

from config import config
from modules.base import ModuloBase
from schemas.modulos import ResultadoEnriquecimiento

log = structlog.get_logger()


class VirusTotalClient(ModuloBase):
    nombre = "virustotal_client"
    categoria = "threat"
    descripcion = "analisis en virustotal: hashes, urls, ips, dominios"
    requiere_api_key = True

    async def ejecutar(self, objetivo: str, parametros: dict = None) -> ResultadoEnriquecimiento:
        objetivo = objetivo.strip()
        parametros = parametros or {}
        tipo = parametros.get("tipo", self._detectar_tipo(objetivo))

        entidades = []
        relaciones = []
        resultados = {"objetivo": objetivo, "tipo": tipo}

        if tipo == "hash":
            datos = await self._analizar_hash(objetivo)
        elif tipo == "url":
            datos = await self._analizar_url(objetivo)
        elif tipo == "ip":
            datos = await self._analizar_ip(objetivo)
        elif tipo == "domain":
            datos = await self._analizar_dominio(objetivo)
        else:
            datos = None

        if datos:
            resultados["analisis"] = datos
            malicioso = datos.get("malicioso", 0)
            sospechoso = datos.get("sospechoso", 0)

            if malicioso > 0:
                entidades.append({
                    "tipo": "hash" if tipo == "hash" else tipo,
                    "valor": objetivo,
                    "datos": {
                        "fuente": "virustotal",
                        "malicioso": malicioso,
                        "sospechoso": sospechoso,
                        "inofensivo": datos.get("inofensivo", 0),
                    },
                    "confianza": min(0.5 + (malicioso * 0.05), 1.0),
                })

        self._entidades_encontradas = len(entidades)

        return ResultadoEnriquecimiento(
            fuente=self.nombre, tipo=tipo,
            datos=resultados, confianza=0.85,
            entidades_nuevas=entidades,
            relaciones_nuevas=relaciones,
        )

    def _detectar_tipo(self, objetivo: str) -> str:
        import re
        if re.match(r'^[a-fA-F0-9]{32}$', objetivo):
            return "hash"  # md5
        if re.match(r'^[a-fA-F0-9]{40}$', objetivo):
            return "hash"  # sha1
        if re.match(r'^[a-fA-F0-9]{64}$', objetivo):
            return "hash"  # sha256
        if re.match(r'^https?://', objetivo):
            return "url"
        if re.match(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$', objetivo):
            return "ip"
        return "domain"

    async def _analizar_hash(self, file_hash: str) -> Optional[dict]:
        if not config.virustotal_api_key:
            return None
        url = f"https://www.virustotal.com/api/v3/files/{file_hash}"
        headers = {"x-apikey": config.virustotal_api_key}
        resp = await self.request_con_rate_limit(url, servicio="virustotal", headers=headers)
        if resp and resp.status_code == 200:
            attrs = resp.json().get("data", {}).get("attributes", {})
            stats = attrs.get("last_analysis_stats", {})
            return {
                "nombre": attrs.get("meaningful_name"),
                "tipo_archivo": attrs.get("type_description"),
                "tamano": attrs.get("size"),
                "sha256": attrs.get("sha256"),
                "sha1": attrs.get("sha1"),
                "md5": attrs.get("md5"),
                "malicioso": stats.get("malicious", 0),
                "sospechoso": stats.get("suspicious", 0),
                "inofensivo": stats.get("harmless", 0),
                "no_detectado": stats.get("undetected", 0),
                "tags": attrs.get("tags", []),
                "primera_vez": attrs.get("first_submission_date"),
                "ultima_vez": attrs.get("last_submission_date"),
                "nombres_conocidos": attrs.get("names", [])[:10],
                "total_motores": sum(stats.values()),
            }
        return None

    async def _analizar_url(self, url_objetivo: str) -> Optional[dict]:
        if not config.virustotal_api_key:
            return None
        import base64
        url_id = base64.urlsafe_b64encode(url_objetivo.encode()).decode().rstrip("=")
        url = f"https://www.virustotal.com/api/v3/urls/{url_id}"
        headers = {"x-apikey": config.virustotal_api_key}
        resp = await self.request_con_rate_limit(url, servicio="virustotal", headers=headers)
        if resp and resp.status_code == 200:
            attrs = resp.json().get("data", {}).get("attributes", {})
            stats = attrs.get("last_analysis_stats", {})
            return {
                "url": attrs.get("url"),
                "titulo": attrs.get("title"),
                "malicioso": stats.get("malicious", 0),
                "sospechoso": stats.get("suspicious", 0),
                "inofensivo": stats.get("harmless", 0),
                "no_detectado": stats.get("undetected", 0),
                "categorias": attrs.get("categories", {}),
                "url_final": attrs.get("last_final_url"),
            }
        return None

    async def _analizar_ip(self, ip: str) -> Optional[dict]:
        if not config.virustotal_api_key:
            return None
        url = f"https://www.virustotal.com/api/v3/ip_addresses/{ip}"
        headers = {"x-apikey": config.virustotal_api_key}
        resp = await self.request_con_rate_limit(url, servicio="virustotal", headers=headers)
        if resp and resp.status_code == 200:
            attrs = resp.json().get("data", {}).get("attributes", {})
            stats = attrs.get("last_analysis_stats", {})
            return {
                "malicioso": stats.get("malicious", 0),
                "sospechoso": stats.get("suspicious", 0),
                "inofensivo": stats.get("harmless", 0),
                "reputacion": attrs.get("reputation"),
                "as_owner": attrs.get("as_owner"),
                "asn": attrs.get("asn"),
                "pais": attrs.get("country"),
            }
        return None

    async def _analizar_dominio(self, dominio: str) -> Optional[dict]:
        if not config.virustotal_api_key:
            return None
        url = f"https://www.virustotal.com/api/v3/domains/{dominio}"
        headers = {"x-apikey": config.virustotal_api_key}
        resp = await self.request_con_rate_limit(url, servicio="virustotal", headers=headers)
        if resp and resp.status_code == 200:
            attrs = resp.json().get("data", {}).get("attributes", {})
            stats = attrs.get("last_analysis_stats", {})
            return {
                "malicioso": stats.get("malicious", 0),
                "sospechoso": stats.get("suspicious", 0),
                "inofensivo": stats.get("harmless", 0),
                "reputacion": attrs.get("reputation"),
                "categorias": attrs.get("categories", {}),
                "registrador": attrs.get("registrar"),
                "fecha_creacion": attrs.get("creation_date"),
            }
        return None
