# sentinel - inteligencia de instagram
# m-society & c1q_

import asyncio
from typing import Optional

from bs4 import BeautifulSoup
import structlog

from modules.base import ModuloBase
from schemas.modulos import ResultadoEnriquecimiento

log = structlog.get_logger()


class InstagramIntel(ModuloBase):
    nombre = "instagram_intel"
    categoria = "social"
    descripcion = "inteligencia de instagram: perfil, actividad"

    async def ejecutar(self, objetivo: str, parametros: dict = None) -> ResultadoEnriquecimiento:
        username = objetivo.strip().replace("@", "")

        entidades = []
        relaciones = []
        resultados = {"username": username}

        tareas = [
            self._verificar_perfil(username),
            self._buscar_google(username),
        ]

        resultados_tareas = await asyncio.gather(*tareas, return_exceptions=True)

        if not isinstance(resultados_tareas[0], Exception) and resultados_tareas[0]:
            resultados["perfil"] = resultados_tareas[0]

        if not isinstance(resultados_tareas[1], Exception) and resultados_tareas[1]:
            resultados["google"] = resultados_tareas[1]

        entidades.append({
            "tipo": "social_profile",
            "valor": f"instagram:{username}",
            "datos": {"plataforma": "instagram", "url": f"https://www.instagram.com/{username}/"},
            "confianza": 0.7,
        })

        self._entidades_encontradas = len(entidades)

        return ResultadoEnriquecimiento(
            fuente=self.nombre, tipo="social_profile",
            datos=resultados, confianza=0.6,
            entidades_nuevas=entidades,
            relaciones_nuevas=relaciones,
        )

    async def _verificar_perfil(self, username: str) -> Optional[dict]:
        url = f"https://www.instagram.com/{username}/"
        resp = await self.request_con_rate_limit(url, servicio="default")
        if resp:
            return {"existe": resp.status_code == 200, "url": url, "status": resp.status_code}
        return None

    async def _buscar_google(self, username: str) -> Optional[dict]:
        url = f'https://www.google.com/search?q=site:instagram.com+"{username}"&num=5'
        resp = await self.request_con_rate_limit(url, servicio="default")
        if resp and resp.status_code == 200:
            soup = BeautifulSoup(resp.text, "html.parser")
            resultados = []
            for div in soup.find_all("div", class_="g"):
                link = div.find("a")
                titulo = div.find("h3")
                if link and titulo:
                    resultados.append({"titulo": titulo.get_text(), "url": link.get("href")})
            return {"resultados": resultados[:5]}
        return None
