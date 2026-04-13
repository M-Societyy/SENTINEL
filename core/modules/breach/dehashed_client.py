# sentinel - cliente dehashed
# m-society & c1q_

from typing import Optional

import structlog

from config import config
from modules.base import ModuloBase
from schemas.modulos import ResultadoEnriquecimiento
from utils.user_agent_rotator import obtener_headers_api

log = structlog.get_logger()


class DehashedClient(ModuloBase):
    nombre = "dehashed_client"
    categoria = "breach"
    descripcion = "busqueda de credenciales filtradas en dehashed"
    requiere_api_key = True

    async def ejecutar(self, objetivo: str, parametros: dict = None) -> ResultadoEnriquecimiento:
        consulta = objetivo.strip()
        parametros = parametros or {}
        tipo_busqueda = parametros.get("tipo", "email")  # email, username, ip, domain, name, phone

        entidades = []
        relaciones = []

        resultado = await self._buscar(consulta, tipo_busqueda)

        if resultado:
            for entrada in resultado.get("entradas", []):
                if entrada.get("email"):
                    entidades.append({
                        "tipo": "email", "valor": entrada["email"],
                        "datos": {"fuente": "dehashed", "database": entrada.get("database_name")},
                        "confianza": 0.85,
                    })
                if entrada.get("username"):
                    entidades.append({
                        "tipo": "username", "valor": entrada["username"],
                        "datos": {"fuente": "dehashed"},
                        "confianza": 0.7,
                    })
                if entrada.get("ip_address"):
                    entidades.append({
                        "tipo": "ip", "valor": entrada["ip_address"],
                        "datos": {"fuente": "dehashed"},
                        "confianza": 0.6,
                    })

        self._entidades_encontradas = len(entidades)

        return ResultadoEnriquecimiento(
            fuente=self.nombre, tipo="credential",
            datos=resultado or {}, confianza=0.8,
            entidades_nuevas=entidades,
            relaciones_nuevas=relaciones,
        )

    async def _buscar(self, consulta: str, tipo: str) -> Optional[dict]:
        if not config.dehashed_api_key:
            return None

        url = "https://api.dehashed.com/search"
        headers = obtener_headers_api(config.dehashed_api_key, bearer=True)
        params = {"query": f"{tipo}:{consulta}", "size": 100}

        resp = await self.request_con_rate_limit(url, servicio="default", headers=headers, params=params)

        if resp and resp.status_code == 200:
            datos = resp.json()
            return {
                "total": datos.get("total", 0),
                "entradas": datos.get("entries", [])[:50],
            }
        return None
