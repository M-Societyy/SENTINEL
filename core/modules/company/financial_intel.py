# sentinel - inteligencia financiera corporativa
# c1q_ (M-Society team)

from typing import Optional

import structlog

from modules.base import ModuloBase
from schemas.modulos import ResultadoEnriquecimiento

log = structlog.get_logger()


class FinancialIntel(ModuloBase):
    nombre = "financial_intel"
    categoria = "company"
    descripcion = "informacion financiera publica de organizaciones"
    requiere_api_key = False

    async def ejecutar(self, objetivo: str, parametros: dict = None) -> ResultadoEnriquecimiento:
        empresa = objetivo.strip()
        resultados = {}

        # buscar en sec edgar (empresas publicas usa)
        sec_data = await self._buscar_sec_edgar(empresa)
        if sec_data:
            resultados["sec_edgar"] = sec_data

        return ResultadoEnriquecimiento(
            fuente=self.nombre,
            tipo="organization",
            datos={"empresa": empresa, "resultados": resultados},
            confianza=0.5,
        )

    async def _buscar_sec_edgar(self, empresa: str) -> Optional[dict]:
        """busca filings en sec edgar"""
        url = f"https://efts.sec.gov/LATEST/search-index?q={empresa}&dateRange=custom&startdt=2020-01-01"
        headers = {"User-Agent": "SENTINEL-OSINT sentinel@research.local"}
        resp = await self.request_con_rate_limit(url, servicio="default", headers=headers)
        if resp and resp.status_code == 200:
            datos = resp.json()
            filings = []
            for hit in datos.get("hits", {}).get("hits", [])[:10]:
                src = hit.get("_source", {})
                filings.append({
                    "tipo": src.get("form_type"),
                    "empresa": src.get("entity_name"),
                    "fecha": src.get("file_date"),
                })
            return {"filings": filings, "total": len(filings)}
        return None
