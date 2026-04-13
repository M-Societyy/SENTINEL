# sentinel - inteligencia de asn y bgp
# m-society & c1q_

import asyncio
from typing import Optional

import structlog

from modules.base import ModuloBase
from schemas.modulos import ResultadoEnriquecimiento

log = structlog.get_logger()


class AsnBgp(ModuloBase):
    nombre = "asn_bgp"
    categoria = "network"
    descripcion = "analisis de asn, prefijos bgp, peers y rangos de red"

    async def ejecutar(self, objetivo: str, parametros: dict = None) -> ResultadoEnriquecimiento:
        """objetivo puede ser un numero asn (ej: AS15169) o una ip"""
        asn = objetivo.strip().upper().replace("AS", "")

        entidades = []
        relaciones = []
        resultados = {"asn_query": asn}

        tareas = [
            self._info_asn(asn),
            self._prefijos_asn(asn),
            self._peers_asn(asn),
        ]

        resultados_tareas = await asyncio.gather(*tareas, return_exceptions=True)

        # info basica
        if not isinstance(resultados_tareas[0], Exception):
            info = resultados_tareas[0]
            if info:
                resultados["info"] = info
                if info.get("nombre"):
                    entidades.append({
                        "tipo": "organization", "valor": info["nombre"],
                        "datos": {"asn": f"AS{asn}", "pais": info.get("pais")},
                        "confianza": 0.9,
                    })

        # prefijos
        if not isinstance(resultados_tareas[1], Exception):
            prefijos = resultados_tareas[1]
            if prefijos:
                resultados["prefijos"] = prefijos

        # peers
        if not isinstance(resultados_tareas[2], Exception):
            peers = resultados_tareas[2]
            if peers:
                resultados["peers"] = peers

        self._entidades_encontradas = len(entidades)

        return ResultadoEnriquecimiento(
            fuente=self.nombre, tipo="asn",
            datos=resultados, confianza=0.85,
            entidades_nuevas=entidades,
            relaciones_nuevas=relaciones,
        )

    async def _info_asn(self, asn: str) -> Optional[dict]:
        resp = await self.request_con_rate_limit(
            f"https://api.bgpview.io/asn/{asn}", servicio="default",
        )
        if resp and resp.status_code == 200:
            datos = resp.json().get("data", {})
            return {
                "asn": datos.get("asn"),
                "nombre": datos.get("name"),
                "descripcion": datos.get("description_short"),
                "pais": datos.get("country_code"),
                "email_contacto": datos.get("email_contacts", []),
                "url_web": datos.get("website"),
                "rir": datos.get("rir_allocation", {}).get("rir_name"),
                "fecha_asignacion": datos.get("rir_allocation", {}).get("date_allocated"),
            }
        return None

    async def _prefijos_asn(self, asn: str) -> Optional[dict]:
        resp = await self.request_con_rate_limit(
            f"https://api.bgpview.io/asn/{asn}/prefixes", servicio="default",
        )
        if resp and resp.status_code == 200:
            datos = resp.json().get("data", {})
            ipv4 = [{"prefix": p.get("prefix"), "nombre": p.get("name"), "descripcion": p.get("description")} for p in datos.get("ipv4_prefixes", [])]
            ipv6 = [{"prefix": p.get("prefix"), "nombre": p.get("name")} for p in datos.get("ipv6_prefixes", [])]
            return {"ipv4": ipv4, "ipv6": ipv6, "total_v4": len(ipv4), "total_v6": len(ipv6)}
        return None

    async def _peers_asn(self, asn: str) -> Optional[dict]:
        resp = await self.request_con_rate_limit(
            f"https://api.bgpview.io/asn/{asn}/peers", servicio="default",
        )
        if resp and resp.status_code == 200:
            datos = resp.json().get("data", {})
            peers = [{"asn": p.get("asn"), "nombre": p.get("name"), "pais": p.get("country_code")} for p in datos.get("ipv4_peers", [])]
            return {"peers": peers[:50], "total": len(datos.get("ipv4_peers", []))}
        return None
