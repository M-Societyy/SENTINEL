# sentinel - mapeo de subsidiarias y estructura corporativa
# c1q_ (M-Society team)

from typing import Optional

import structlog

from modules.base import ModuloBase
from schemas.modulos import ResultadoEnriquecimiento

log = structlog.get_logger()


class SubsidiaryMapper(ModuloBase):
    nombre = "subsidiary_mapper"
    categoria = "company"
    descripcion = "mapeo de subsidiarias y relaciones corporativas"
    requiere_api_key = False

    async def ejecutar(self, objetivo: str, parametros: dict = None) -> ResultadoEnriquecimiento:
        empresa = objetivo.strip()
        entidades = []
        relaciones = []

        # buscar registros corporativos publicos
        info = await self._buscar_registros_publicos(empresa)

        if info:
            for sub in info.get("subsidiarias", []):
                entidades.append({
                    "tipo": "organization",
                    "valor": sub["nombre"],
                    "datos": {"tipo": "subsidiaria", "parent": empresa},
                    "confianza": 0.6,
                })
                relaciones.append({
                    "tipo_relacion": "associated_with",
                    "origen_valor": empresa,
                    "origen_tipo": "organization",
                    "destino_valor": sub["nombre"],
                    "destino_tipo": "organization",
                    "confianza": 0.6,
                })

        self._entidades_encontradas = len(entidades)
        self._relaciones_creadas = len(relaciones)

        return ResultadoEnriquecimiento(
            fuente=self.nombre,
            tipo="organization",
            datos={"empresa": empresa, "info": info or {}},
            confianza=0.5,
            entidades_nuevas=entidades,
            relaciones_nuevas=relaciones,
        )

    async def _buscar_registros_publicos(self, empresa: str) -> Optional[dict]:
        """busca en fuentes publicas de registro corporativo"""
        # buscar en opencorporates
        url = f"https://api.opencorporates.com/v0.4/companies/search?q={empresa}"
        resp = await self.request_con_rate_limit(url, servicio="default")
        if resp and resp.status_code == 200:
            datos = resp.json()
            companias = datos.get("results", {}).get("companies", [])
            subsidiarias = []
            for c in companias[:20]:
                info = c.get("company", {})
                subsidiarias.append({
                    "nombre": info.get("name"),
                    "jurisdiccion": info.get("jurisdiction_code"),
                    "estado": info.get("current_status"),
                    "fecha_incorporacion": info.get("incorporation_date"),
                })
            return {"subsidiarias": subsidiarias, "total": len(subsidiarias)}
        return None
