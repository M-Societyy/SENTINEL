# sentinel - indexador de sitios onion
# c1q_ (M-Society team)
# modulo complementario al tor_crawler - desactivado por defecto

import asyncio
from typing import Optional
from datetime import datetime

import httpx
import structlog
from bs4 import BeautifulSoup

from config import config
from modules.base import ModuloBase
from schemas.modulos import ResultadoEnriquecimiento

log = structlog.get_logger()


class OnionIndexer(ModuloBase):
    nombre = "onion_indexer"
    categoria = "darkweb"
    descripcion = "indexa y cataloga sitios onion descubiertos"
    requiere_api_key = False

    _activado = False

    async def ejecutar(self, objetivo: str, parametros: dict = None) -> ResultadoEnriquecimiento:
        parametros = parametros or {}

        if not parametros.get("activacion_explicita", False) and not self._activado:
            return ResultadoEnriquecimiento(
                fuente=self.nombre, tipo="darkweb",
                error="modulo de dark web desactivado. requiere activacion_explicita=true",
                confianza=0.0,
            )

        # verificar si el objetivo es un dominio .onion
        if not objetivo.endswith(".onion"):
            return ResultadoEnriquecimiento(
                fuente=self.nombre, tipo="darkweb",
                error="el objetivo debe ser un dominio .onion",
                confianza=0.0,
            )

        info_sitio = await self._indexar_onion(objetivo)

        return ResultadoEnriquecimiento(
            fuente=self.nombre,
            tipo="darkweb",
            datos={
                "dominio": objetivo,
                "info": info_sitio or {},
                "indexado_en": datetime.utcnow().isoformat(),
                "disclaimer": "contenido de dark web - uso exclusivo para investigacion autorizada",
            },
            confianza=0.3,
        )

    async def _indexar_onion(self, dominio: str) -> Optional[dict]:
        """intenta extraer metadata basica de un sitio onion"""
        try:
            async with httpx.AsyncClient(
                proxies=config.tor_socks_proxy,
                timeout=httpx.Timeout(60.0, connect=30.0),
                verify=False,
            ) as cliente:
                url = f"http://{dominio}"
                resp = await cliente.get(url)
                if resp.status_code == 200:
                    soup = BeautifulSoup(resp.text, "lxml")
                    titulo = soup.title.string if soup.title else "sin titulo"
                    meta_desc = ""
                    meta_tag = soup.find("meta", attrs={"name": "description"})
                    if meta_tag:
                        meta_desc = meta_tag.get("content", "")

                    # extraer links internos y externos
                    links = []
                    for a in soup.find_all("a", href=True):
                        href = a.get("href", "")
                        if ".onion" in href:
                            links.append(href)

                    return {
                        "titulo": titulo,
                        "descripcion": meta_desc,
                        "status_code": resp.status_code,
                        "headers_servidor": dict(resp.headers),
                        "links_onion": list(set(links))[:50],
                        "accesible": True,
                    }
                return {"accesible": False, "status_code": resp.status_code}
        except Exception as e:
            return {"accesible": False, "error": str(e)}
