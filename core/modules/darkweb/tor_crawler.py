# sentinel - modulo de crawling en la dark web via tor
# m-society & c1q_
# modulo desactivado por defecto - requiere activacion explicita

import asyncio
from typing import Optional

import httpx
import structlog
from bs4 import BeautifulSoup

from config import config
from modules.base import ModuloBase
from schemas.modulos import ResultadoEnriquecimiento
from utils.tor_controller import controlador_tor

log = structlog.get_logger()

MOTORES_ONION = {
    "ahmia": "https://ahmia.fi/search/?q=",
    "torch": "http://xmh57jrknzkhv6y3ls3ubitzfqnkrwxhopf5aygthi7d6rplyvk3noyd.onion/cgi-bin/omega/omega?P=",
}

DIRECTORIOS_ONION = [
    "http://zqktlwiuavvvqqt4ybvgvi7tyo4hjl5xgfuvpdf6otjiycgwqbym2qad.onion/wiki/",
    "http://juhanurmihxlp77nkq76byazcldy2hlmovfu2epvl5ankdibsot4csyd.onion/",
]


class TorCrawler(ModuloBase):
    nombre = "tor_crawler"
    categoria = "darkweb"
    descripcion = "crawling en dark web via tor - desactivado por defecto"
    requiere_api_key = False

    # este modulo requiere activacion explicita
    _activado = False

    async def ejecutar(self, objetivo: str, parametros: dict = None) -> ResultadoEnriquecimiento:
        parametros = parametros or {}

        # verificar que el operador activo explicitamente este modulo
        if not parametros.get("activacion_explicita", False) and not self._activado:
            return ResultadoEnriquecimiento(
                fuente=self.nombre, tipo="darkweb",
                error="modulo de dark web desactivado. requiere activacion_explicita=true",
                confianza=0.0,
            )

        resultados = {}
        entidades = []
        relaciones = []

        # buscar en motores onion via clearnet (ahmia)
        menciones_ahmia = await self._buscar_ahmia(objetivo)
        if menciones_ahmia:
            resultados["ahmia"] = menciones_ahmia
            for mencion in menciones_ahmia.get("resultados", []):
                entidades.append({
                    "tipo": "document",
                    "valor": mencion.get("url", ""),
                    "datos": {"titulo": mencion.get("titulo"), "fuente": "ahmia", "red": "tor"},
                    "confianza": 0.5,
                })

        # si tor esta disponible, buscar directamente
        if config.tor_socks_proxy:
            menciones_tor = await self._buscar_via_tor(objetivo)
            if menciones_tor:
                resultados["tor_directo"] = menciones_tor
                for mencion in menciones_tor.get("resultados", []):
                    entidades.append({
                        "tipo": "document",
                        "valor": mencion.get("url", ""),
                        "datos": {"titulo": mencion.get("titulo"), "fuente": "tor_directo", "red": "tor"},
                        "confianza": 0.4,
                    })

        self._entidades_encontradas = len(entidades)
        self._relaciones_creadas = len(relaciones)

        return ResultadoEnriquecimiento(
            fuente=self.nombre,
            tipo="darkweb",
            datos={
                "objetivo": objetivo,
                "disclaimer": "resultados de dark web - usar con precaucion legal",
                "resultados": resultados,
            },
            confianza=0.4,
            entidades_nuevas=entidades,
            relaciones_nuevas=relaciones,
        )

    async def _buscar_ahmia(self, query: str) -> Optional[dict]:
        """busca en ahmia.fi (motor de busqueda onion via clearnet)"""
        url = f"https://ahmia.fi/search/?q={query}"
        resp = await self.request_con_rate_limit(url, servicio="default")
        if resp and resp.status_code == 200:
            soup = BeautifulSoup(resp.text, "lxml")
            resultados = []
            for item in soup.select(".result")[:20]:
                titulo_elem = item.select_one("h4")
                link_elem = item.select_one("a")
                descripcion_elem = item.select_one("p")
                if titulo_elem and link_elem:
                    resultados.append({
                        "titulo": titulo_elem.get_text(strip=True),
                        "url": link_elem.get("href", ""),
                        "descripcion": descripcion_elem.get_text(strip=True) if descripcion_elem else "",
                    })
            return {"total": len(resultados), "resultados": resultados}
        return None

    async def _buscar_via_tor(self, query: str) -> Optional[dict]:
        """busca directamente a traves de la red tor"""
        try:
            async with httpx.AsyncClient(
                proxies=config.tor_socks_proxy,
                timeout=httpx.Timeout(60.0, connect=30.0),
                verify=False,
            ) as cliente:
                resultados = []
                for nombre, url_base in MOTORES_ONION.items():
                    try:
                        resp = await cliente.get(f"{url_base}{query}")
                        if resp.status_code == 200:
                            soup = BeautifulSoup(resp.text, "lxml")
                            links = soup.find_all("a", href=True)
                            for link in links[:10]:
                                href = link.get("href", "")
                                if ".onion" in href:
                                    resultados.append({
                                        "titulo": link.get_text(strip=True),
                                        "url": href,
                                        "motor": nombre,
                                    })
                    except Exception as e:
                        log.warning("error buscando en motor onion", motor=nombre, error=str(e))
                        continue

                return {"total": len(resultados), "resultados": resultados}
        except Exception as e:
            log.warning("error conectando a tor", error=str(e))
            return None
