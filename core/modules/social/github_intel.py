# sentinel - inteligencia de github
# m-society & c1q_

import re
import asyncio
from typing import Optional

import httpx
import structlog

from modules.base import ModuloBase
from schemas.modulos import ResultadoEnriquecimiento

log = structlog.get_logger()

# patrones regex para deteccion de secretos en codigo
PATRONES_SECRETOS = [
    {"nombre": "aws_access_key", "patron": r"AKIA[0-9A-Z]{16}", "severidad": "critica"},
    {"nombre": "aws_secret_key", "patron": r"(?i)aws(.{0,20})?['\"][0-9a-zA-Z/+]{40}['\"]", "severidad": "critica"},
    {"nombre": "github_token", "patron": r"gh[ps]_[A-Za-z0-9_]{36,}", "severidad": "critica"},
    {"nombre": "github_oauth", "patron": r"gho_[A-Za-z0-9_]{36,}", "severidad": "alta"},
    {"nombre": "google_api_key", "patron": r"AIza[0-9A-Za-z\\-_]{35}", "severidad": "alta"},
    {"nombre": "google_oauth", "patron": r"[0-9]+-[0-9A-Za-z_]{32}\\.apps\\.googleusercontent\\.com", "severidad": "alta"},
    {"nombre": "slack_token", "patron": r"xox[baprs]-[0-9]{10,13}-[0-9]{10,13}[a-zA-Z0-9-]*", "severidad": "alta"},
    {"nombre": "slack_webhook", "patron": r"https://hooks\\.slack\\.com/services/T[a-zA-Z0-9_]+/B[a-zA-Z0-9_]+/[a-zA-Z0-9_]+", "severidad": "alta"},
    {"nombre": "stripe_live_key", "patron": r"sk_live_[0-9a-zA-Z]{24,}", "severidad": "critica"},
    {"nombre": "stripe_test_key", "patron": r"sk_test_[0-9a-zA-Z]{24,}", "severidad": "media"},
    {"nombre": "twilio_sid", "patron": r"AC[a-zA-Z0-9_\-]{32}", "severidad": "alta"},
    {"nombre": "twilio_auth", "patron": r"(?i)twilio(.{0,20})?['\"][0-9a-f]{32}['\"]", "severidad": "alta"},
    {"nombre": "sendgrid_key", "patron": r"SG\\.[a-zA-Z0-9_-]{22}\\.[a-zA-Z0-9_-]{43}", "severidad": "alta"},
    {"nombre": "heroku_api_key", "patron": r"(?i)heroku(.{0,20})?[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}", "severidad": "alta"},
    {"nombre": "mailgun_key", "patron": r"key-[0-9a-zA-Z]{32}", "severidad": "alta"},
    {"nombre": "jwt_token", "patron": r"eyJ[A-Za-z0-9-_]+\\.eyJ[A-Za-z0-9-_]+\\.[A-Za-z0-9-_.+/]*", "severidad": "media"},
    {"nombre": "private_key", "patron": r"-----BEGIN (RSA |EC |DSA )?PRIVATE KEY-----", "severidad": "critica"},
    {"nombre": "password_inline", "patron": r"(?i)(password|passwd|pwd)\s*[=:]\s*['\"][^'\"]{8,}['\"]", "severidad": "alta"},
    {"nombre": "generic_secret", "patron": r"(?i)(api[_-]?key|apikey|secret[_-]?key|access[_-]?token)\s*[=:]\s*['\"][a-zA-Z0-9_\-]{20,}['\"]", "severidad": "media"},
    {"nombre": "discord_token", "patron": r"[MN][A-Za-z\\d]{23,}\\.[\w-]{6}\\.[\w-]{27}", "severidad": "critica"},
    {"nombre": "telegram_bot_token", "patron": r"[0-9]{8,10}:[a-zA-Z0-9_-]{35}", "severidad": "alta"},
    {"nombre": "firebase_url", "patron": r"https://[a-z0-9-]+\\.firebaseio\\.com", "severidad": "media"},
    {"nombre": "gcp_service_account", "patron": r"\"type\":\\s*\"service_account\"", "severidad": "critica"},
    {"nombre": "azure_storage_key", "patron": r"(?i)DefaultEndpointsProtocol=https;AccountName=[^;]+;AccountKey=[A-Za-z0-9+/=]{88}", "severidad": "critica"},
    {"nombre": "npm_token", "patron": r"(?i)//registry\\.npmjs\\.org/:_authToken=[a-zA-Z0-9-]+", "severidad": "alta"},
]


class GithubIntel(ModuloBase):
    nombre = "github_intel"
    categoria = "social"
    descripcion = "inteligencia de github: perfil, repos, secretos, emails de commits"

    async def ejecutar(self, objetivo: str, parametros: dict = None) -> ResultadoEnriquecimiento:
        username = objetivo.strip()

        entidades = []
        relaciones = []
        resultados = {"username": username}

        tareas = [
            self._perfil(username),
            self._repos(username),
            self._gists(username),
            self._organizaciones(username),
            self._eventos(username),
            self._emails_commits(username),
        ]

        resultados_tareas = await asyncio.gather(*tareas, return_exceptions=True)
        idx = 0

        # perfil
        if not isinstance(resultados_tareas[idx], Exception):
            perfil = resultados_tareas[idx]
            if perfil:
                resultados["perfil"] = perfil
                if perfil.get("email"):
                    entidades.append({
                        "tipo": "email", "valor": perfil["email"],
                        "datos": {"fuente": "github_perfil"},
                        "confianza": 0.9,
                    })
                    relaciones.append({
                        "tipo_relacion": "owns",
                        "origen_valor": username, "origen_tipo": "username",
                        "destino_valor": perfil["email"], "destino_tipo": "email",
                        "confianza": 0.9,
                    })
                if perfil.get("empresa"):
                    entidades.append({
                        "tipo": "organization", "valor": perfil["empresa"],
                        "datos": {"fuente": "github_perfil"},
                        "confianza": 0.7,
                    })
                    relaciones.append({
                        "tipo_relacion": "member_of",
                        "origen_valor": username, "origen_tipo": "username",
                        "destino_valor": perfil["empresa"], "destino_tipo": "organization",
                        "confianza": 0.7,
                    })
                if perfil.get("ubicacion"):
                    entidades.append({
                        "tipo": "location", "valor": perfil["ubicacion"],
                        "datos": {"fuente": "github_perfil"},
                        "confianza": 0.5,
                    })
                    relaciones.append({
                        "tipo_relacion": "located_at",
                        "origen_valor": username, "origen_tipo": "username",
                        "destino_valor": perfil["ubicacion"], "destino_tipo": "location",
                        "confianza": 0.5,
                    })
                if perfil.get("nombre"):
                    entidades.append({
                        "tipo": "person", "valor": perfil["nombre"],
                        "datos": {"fuente": "github_perfil", "username": username},
                        "confianza": 0.8,
                    })
                    relaciones.append({
                        "tipo_relacion": "owns",
                        "origen_valor": perfil["nombre"], "origen_tipo": "person",
                        "destino_valor": username, "destino_tipo": "username",
                        "confianza": 0.8,
                    })
                if perfil.get("blog"):
                    entidades.append({
                        "tipo": "domain", "valor": perfil["blog"].replace("https://","").replace("http://","").split("/")[0],
                        "datos": {"fuente": "github_perfil", "url_completa": perfil["blog"]},
                        "confianza": 0.8,
                    })
                    relaciones.append({
                        "tipo_relacion": "owns",
                        "origen_valor": username, "origen_tipo": "username",
                        "destino_valor": perfil["blog"].replace("https://","").replace("http://","").split("/")[0], "destino_tipo": "domain",
                        "confianza": 0.7,
                    })
        idx += 1

        # repos
        if not isinstance(resultados_tareas[idx], Exception):
            repos = resultados_tareas[idx]
            if repos:
                resultados["repos"] = repos
                # buscar secretos en los repos mas recientes
                secretos = await self._escanear_secretos_repos(username, repos.get("repos", [])[:5])
                if secretos:
                    resultados["secretos_detectados"] = secretos
        idx += 1

        # gists
        if not isinstance(resultados_tareas[idx], Exception):
            gists = resultados_tareas[idx]
            if gists:
                resultados["gists"] = gists
        idx += 1

        # orgs
        if not isinstance(resultados_tareas[idx], Exception):
            orgs = resultados_tareas[idx]
            if orgs:
                resultados["organizaciones"] = orgs
                for org in orgs:
                    entidades.append({
                        "tipo": "organization", "valor": org.get("login", ""),
                        "datos": {"fuente": "github_orgs", "url": org.get("url")},
                        "confianza": 0.85,
                    })
                    relaciones.append({
                        "tipo_relacion": "member_of",
                        "origen_valor": username, "origen_tipo": "username",
                        "destino_valor": org.get("login", ""), "destino_tipo": "organization",
                        "confianza": 0.9,
                    })
        idx += 1

        # eventos
        if not isinstance(resultados_tareas[idx], Exception):
            eventos = resultados_tareas[idx]
            if eventos:
                resultados["actividad_reciente"] = eventos
        idx += 1

        # emails de commits
        if not isinstance(resultados_tareas[idx], Exception):
            emails = resultados_tareas[idx]
            if emails:
                resultados["emails_commits"] = emails
                for email in emails:
                    if email and "@" in email:
                        entidades.append({
                            "tipo": "email", "valor": email,
                            "datos": {"fuente": "github_commits"},
                            "confianza": 0.85,
                        })
                        relaciones.append({
                            "tipo_relacion": "owns",
                            "origen_valor": username, "origen_tipo": "username",
                            "destino_valor": email, "destino_tipo": "email",
                            "confianza": 0.85,
                        })

        self._entidades_encontradas = len(entidades)
        self._relaciones_creadas = len(relaciones)

        return ResultadoEnriquecimiento(
            fuente=self.nombre, tipo="username",
            datos=resultados, confianza=0.85,
            entidades_nuevas=entidades,
            relaciones_nuevas=relaciones,
        )

    async def _perfil(self, username: str) -> Optional[dict]:
        url = f"https://api.github.com/users/{username}"
        headers = {"Accept": "application/vnd.github.v3+json"}
        resp = await self.request_con_rate_limit(url, servicio="github", headers=headers)
        if resp and resp.status_code == 200:
            d = resp.json()
            return {
                "nombre": d.get("name"),
                "bio": d.get("bio"),
                "empresa": d.get("company"),
                "ubicacion": d.get("location"),
                "email": d.get("email"),
                "blog": d.get("blog"),
                "twitter": d.get("twitter_username"),
                "avatar": d.get("avatar_url"),
                "repos_publicos": d.get("public_repos"),
                "gists_publicos": d.get("public_gists"),
                "seguidores": d.get("followers"),
                "siguiendo": d.get("following"),
                "creado": d.get("created_at"),
                "actualizado": d.get("updated_at"),
                "tipo": d.get("type"),
                "hireable": d.get("hireable"),
                "url": d.get("html_url"),
            }
        return None

    async def _repos(self, username: str) -> Optional[dict]:
        url = f"https://api.github.com/users/{username}/repos"
        headers = {"Accept": "application/vnd.github.v3+json"}
        resp = await self.request_con_rate_limit(
            url, servicio="github", headers=headers,
            params={"sort": "updated", "per_page": 100},
        )
        if resp and resp.status_code == 200:
            repos_raw = resp.json()
            repos = []
            lenguajes = {}
            total_stars = 0
            total_forks = 0

            for r in repos_raw:
                repos.append({
                    "nombre": r.get("full_name"),
                    "descripcion": r.get("description"),
                    "url": r.get("html_url"),
                    "lenguaje": r.get("language"),
                    "stars": r.get("stargazers_count", 0),
                    "forks": r.get("forks_count", 0),
                    "es_fork": r.get("fork", False),
                    "creado": r.get("created_at"),
                    "actualizado": r.get("updated_at"),
                    "topics": r.get("topics", []),
                })
                lang = r.get("language")
                if lang:
                    lenguajes[lang] = lenguajes.get(lang, 0) + 1
                total_stars += r.get("stargazers_count", 0)
                total_forks += r.get("forks_count", 0)

            return {
                "repos": repos,
                "total": len(repos),
                "lenguajes": lenguajes,
                "total_stars": total_stars,
                "total_forks": total_forks,
            }
        return None

    async def _gists(self, username: str) -> Optional[list]:
        url = f"https://api.github.com/users/{username}/gists"
        headers = {"Accept": "application/vnd.github.v3+json"}
        resp = await self.request_con_rate_limit(url, servicio="github", headers=headers, params={"per_page": 30})
        if resp and resp.status_code == 200:
            gists_raw = resp.json()
            return [{
                "id": g.get("id"),
                "descripcion": g.get("description"),
                "url": g.get("html_url"),
                "archivos": list(g.get("files", {}).keys()),
                "publico": g.get("public"),
                "creado": g.get("created_at"),
            } for g in gists_raw]
        return None

    async def _organizaciones(self, username: str) -> Optional[list]:
        url = f"https://api.github.com/users/{username}/orgs"
        headers = {"Accept": "application/vnd.github.v3+json"}
        resp = await self.request_con_rate_limit(url, servicio="github", headers=headers)
        if resp and resp.status_code == 200:
            return [{
                "login": o.get("login"),
                "url": o.get("url"),
                "avatar": o.get("avatar_url"),
                "descripcion": o.get("description"),
            } for o in resp.json()]
        return None

    async def _eventos(self, username: str) -> Optional[list]:
        url = f"https://api.github.com/users/{username}/events/public"
        headers = {"Accept": "application/vnd.github.v3+json"}
        resp = await self.request_con_rate_limit(url, servicio="github", headers=headers, params={"per_page": 30})
        if resp and resp.status_code == 200:
            return [{
                "tipo": e.get("type"),
                "repo": e.get("repo", {}).get("name"),
                "fecha": e.get("created_at"),
            } for e in resp.json()[:30]]
        return None

    async def _emails_commits(self, username: str) -> list[str]:
        """extrae emails unicos de los commits publicos"""
        emails = set()
        url = f"https://api.github.com/search/commits?q=author:{username}"
        headers = {
            "Accept": "application/vnd.github.cloak-preview+json",
        }
        resp = await self.request_con_rate_limit(url, servicio="github", headers=headers)
        if resp and resp.status_code == 200:
            for item in resp.json().get("items", [])[:50]:
                commit = item.get("commit", {})
                autor = commit.get("author", {})
                email = autor.get("email", "")
                if email and "@" in email and "noreply" not in email:
                    emails.add(email.lower())
        return list(emails)

    async def _escanear_secretos_repos(self, username: str, repos: list) -> list[dict]:
        """escanea los repos mas recientes buscando secretos expuestos"""
        secretos_encontrados = []

        for repo in repos:
            nombre_repo = repo.get("nombre", "")
            if not nombre_repo:
                continue

            # buscar en el codigo via search api
            for patron_info in PATRONES_SECRETOS[:10]:  # limitar para no abusar api
                url = f"https://api.github.com/search/code?q={patron_info['nombre']}+repo:{nombre_repo}"
                headers = {"Accept": "application/vnd.github.v3+json"}
                resp = await self.request_con_rate_limit(url, servicio="github", headers=headers)
                if resp and resp.status_code == 200:
                    items = resp.json().get("items", [])
                    if items:
                        for item in items[:3]:
                            secretos_encontrados.append({
                                "tipo_secreto": patron_info["nombre"],
                                "severidad": patron_info["severidad"],
                                "repo": nombre_repo,
                                "archivo": item.get("path"),
                                "url": item.get("html_url"),
                            })

                await asyncio.sleep(0.5)  # no abusar del api

        return secretos_encontrados
