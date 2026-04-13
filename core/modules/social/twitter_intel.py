# sentinel - inteligencia de twitter/x
# m-society & c1q_

import asyncio
from typing import Optional

from bs4 import BeautifulSoup
import structlog

from modules.base import ModuloBase
from schemas.modulos import ResultadoEnriquecimiento

log = structlog.get_logger()


class TwitterIntel(ModuloBase):
    nombre = "twitter_intel"
    categoria = "social"
    descripcion = "inteligencia de twitter/x: perfil, actividad, conexiones"

    async def ejecutar(self, objetivo: str, parametros: dict = None) -> ResultadoEnriquecimiento:
        username = objetivo.strip().replace("@", "")

        entidades = []
        relaciones = []
        resultados = {"username": username}

        tareas = [
            self._perfil_via_web(username),
            self._buscar_google(username),
            self._wayback_perfil(username),
        ]

        resultados_tareas = await asyncio.gather(*tareas, return_exceptions=True)

        if not isinstance(resultados_tareas[0], Exception) and resultados_tareas[0]:
            resultados["perfil"] = resultados_tareas[0]

        if not isinstance(resultados_tareas[1], Exception) and resultados_tareas[1]:
            resultados["google_meniones"] = resultados_tareas[1]

        if not isinstance(resultados_tareas[2], Exception) and resultados_tareas[2]:
            resultados["wayback"] = resultados_tareas[2]

        # entidad del perfil
        entidades.append({
            "tipo": "social_profile",
            "valor": f"twitter:{username}",
            "datos": {"plataforma": "twitter", "url": f"https://x.com/{username}"},
            "confianza": 0.7,
        })

        self._entidades_encontradas = len(entidades)
        self._relaciones_creadas = len(relaciones)

        return ResultadoEnriquecimiento(
            fuente=self.nombre, tipo="social_profile",
            datos=resultados, confianza=0.6,
            entidades_nuevas=entidades,
            relaciones_nuevas=relaciones,
        )

    async def _perfil_via_web(self, username: str) -> Optional[dict]:
        """intenta obtener info basica del perfil via web"""
        url = f"https://x.com/{username}"
        resp = await self.request_con_rate_limit(url, servicio="default")
        if resp and resp.status_code == 200:
            return {"url": url, "existe": True, "status": resp.status_code}
        return {"url": url, "existe": False}

    async def _buscar_google(self, username: str) -> Optional[dict]:
        """busca menciones en google"""
        url = f'https://www.google.com/search?q=site:twitter.com+OR+site:x.com+"{username}"&num=10'
        resp = await self.request_con_rate_limit(url, servicio="default")
        if resp and resp.status_code == 200:
            soup = BeautifulSoup(resp.text, "html.parser")
            resultados = []
            for div in soup.find_all("div", class_="g"):
                link = div.find("a")
                titulo = div.find("h3")
                if link and titulo:
                    resultados.append({
                        "titulo": titulo.get_text(),
                        "url": link.get("href"),
                    })
            return {"menciones": resultados[:10]}
        return None

    async def _wayback_perfil(self, username: str) -> Optional[dict]:
        """busca snapshots historicos en wayback machine"""
        url = f"https://web.archive.org/web/timemap/json?url=twitter.com/{username}&limit=10"
        resp = await self.request_con_rate_limit(url, servicio="default")
        if resp and resp.status_code == 200:
            try:
                datos = resp.json()
                if len(datos) > 1:
                    snapshots = [{"fecha": s[1], "url": f"https://web.archive.org/web/{s[1]}/https://twitter.com/{username}"} for s in datos[1:]]
                    return {"snapshots": snapshots, "total": len(snapshots)}
            except Exception:
                pass
        return None
