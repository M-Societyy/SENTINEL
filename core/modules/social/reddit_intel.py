# sentinel - inteligencia de reddit
# c1q_ (M-Society team)

import asyncio
from typing import Optional

import structlog

from modules.base import ModuloBase
from schemas.modulos import ResultadoEnriquecimiento

log = structlog.get_logger()


class RedditIntel(ModuloBase):
    nombre = "reddit_intel"
    categoria = "social"
    descripcion = "inteligencia de reddit: perfil, posts, comentarios, subreddits"

    async def ejecutar(self, objetivo: str, parametros: dict = None) -> ResultadoEnriquecimiento:
        username = objetivo.strip().replace("u/", "")

        entidades = []
        relaciones = []
        resultados = {"username": username}

        tareas = [
            self._perfil(username),
            self._posts_recientes(username),
            self._comentarios_recientes(username),
        ]

        resultados_tareas = await asyncio.gather(*tareas, return_exceptions=True)

        if not isinstance(resultados_tareas[0], Exception) and resultados_tareas[0]:
            resultados["perfil"] = resultados_tareas[0]

        if not isinstance(resultados_tareas[1], Exception) and resultados_tareas[1]:
            resultados["posts"] = resultados_tareas[1]
            # extraer subreddits activos
            subs = set()
            for p in resultados_tareas[1]:
                subs.add(p.get("subreddit", ""))
            resultados["subreddits_activos"] = list(subs)

        if not isinstance(resultados_tareas[2], Exception) and resultados_tareas[2]:
            resultados["comentarios"] = resultados_tareas[2]

        entidades.append({
            "tipo": "social_profile",
            "valor": f"reddit:{username}",
            "datos": resultados.get("perfil", {}),
            "confianza": 0.8,
        })

        self._entidades_encontradas = len(entidades)

        return ResultadoEnriquecimiento(
            fuente=self.nombre, tipo="social_profile",
            datos=resultados, confianza=0.75,
            entidades_nuevas=entidades,
            relaciones_nuevas=relaciones,
        )

    async def _perfil(self, username: str) -> Optional[dict]:
        url = f"https://www.reddit.com/user/{username}/about.json"
        resp = await self.request_con_rate_limit(url, servicio="default")
        if resp and resp.status_code == 200:
            d = resp.json().get("data", {})
            return {
                "nombre": d.get("name"),
                "id": d.get("id"),
                "karma_total": d.get("total_karma", 0),
                "karma_link": d.get("link_karma", 0),
                "karma_comentarios": d.get("comment_karma", 0),
                "creado_utc": d.get("created_utc"),
                "tiene_premium": d.get("is_gold", False),
                "es_moderador": d.get("is_mod", False),
                "verificado": d.get("verified", False),
                "avatar": d.get("icon_img"),
                "descripcion": d.get("subreddit", {}).get("public_description"),
            }
        return None

    async def _posts_recientes(self, username: str) -> Optional[list]:
        url = f"https://www.reddit.com/user/{username}/submitted.json?limit=25&sort=new"
        resp = await self.request_con_rate_limit(url, servicio="default")
        if resp and resp.status_code == 200:
            posts = []
            for child in resp.json().get("data", {}).get("children", []):
                d = child.get("data", {})
                posts.append({
                    "titulo": d.get("title"),
                    "subreddit": d.get("subreddit"),
                    "score": d.get("score", 0),
                    "num_comentarios": d.get("num_comments", 0),
                    "url": d.get("url"),
                    "permalink": f"https://reddit.com{d.get('permalink', '')}",
                    "creado_utc": d.get("created_utc"),
                    "nsfw": d.get("over_18", False),
                })
            return posts
        return None

    async def _comentarios_recientes(self, username: str) -> Optional[list]:
        url = f"https://www.reddit.com/user/{username}/comments.json?limit=25&sort=new"
        resp = await self.request_con_rate_limit(url, servicio="default")
        if resp and resp.status_code == 200:
            comentarios = []
            for child in resp.json().get("data", {}).get("children", []):
                d = child.get("data", {})
                comentarios.append({
                    "cuerpo": (d.get("body", ""))[:300],
                    "subreddit": d.get("subreddit"),
                    "score": d.get("score", 0),
                    "permalink": f"https://reddit.com{d.get('permalink', '')}",
                    "creado_utc": d.get("created_utc"),
                })
            return comentarios
        return None
