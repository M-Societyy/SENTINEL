# sentinel - busqueda de personas con correlacion cruzada
# m-society & c1q_

import asyncio
import re
from typing import Optional

import httpx
from bs4 import BeautifulSoup
import structlog

from modules.base import ModuloBase
from schemas.modulos import ResultadoEnriquecimiento
from utils.user_agent_rotator import obtener_headers_completos

log = structlog.get_logger()


class PersonSearch(ModuloBase):
    nombre = "person_search"
    categoria = "identity"
    descripcion = "busqueda de personas: google dorks, correlacion de identidad digital"

    async def ejecutar(self, objetivo: str, parametros: dict = None) -> ResultadoEnriquecimiento:
        nombre = objetivo.strip()
        parametros = parametros or {}
        ubicacion = parametros.get("ubicacion", "")

        entidades = []
        relaciones = []
        resultados = {"nombre": nombre, "ubicacion": ubicacion}

        # ejecutar busquedas en paralelo
        tareas = [
            self._google_dorks(nombre, ubicacion),
            self._buscar_linkedin(nombre, ubicacion),
            self._buscar_github(nombre),
            self._extraer_emails_google(nombre),
        ]

        resultados_tareas = await asyncio.gather(*tareas, return_exceptions=True)

        # google dorks
        if not isinstance(resultados_tareas[0], Exception):
            dorks = resultados_tareas[0]
            if dorks:
                resultados["google_dorks"] = dorks
                for hallazgo in dorks.get("perfiles", []):
                    plataforma = hallazgo.get("plataforma", "web")
                    entidades.append({
                        "tipo": "social_profile",
                        "valor": hallazgo.get("url", ""),
                        "datos": hallazgo,
                        "confianza": 0.5,
                    })
                    relaciones.append({
                        "tipo_relacion": "associated_with",
                        "origen_valor": nombre,
                        "origen_tipo": "person",
                        "destino_valor": hallazgo.get("url", ""),
                        "destino_tipo": "social_profile",
                        "confianza": 0.5,
                    })

        # linkedin
        if not isinstance(resultados_tareas[1], Exception):
            linkedin = resultados_tareas[1]
            if linkedin:
                resultados["linkedin"] = linkedin
                for perfil in linkedin.get("perfiles", []):
                    entidades.append({
                        "tipo": "social_profile",
                        "valor": perfil.get("url", ""),
                        "datos": perfil,
                        "confianza": 0.6,
                    })
                    relaciones.append({
                        "tipo_relacion": "owns",
                        "origen_valor": nombre,
                        "origen_tipo": "person",
                        "destino_valor": perfil.get("url", ""),
                        "destino_tipo": "social_profile",
                        "confianza": 0.5,
                    })

        # github
        if not isinstance(resultados_tareas[2], Exception):
            github = resultados_tareas[2]
            if github:
                resultados["github"] = github
                for usuario in github.get("usuarios", []):
                    entidades.append({
                        "tipo": "username",
                        "valor": usuario.get("login", ""),
                        "datos": usuario,
                        "confianza": 0.5,
                    })
                    relaciones.append({
                        "tipo_relacion": "associated_with",
                        "origen_valor": nombre,
                        "origen_tipo": "person",
                        "destino_valor": usuario.get("login", ""),
                        "destino_tipo": "username",
                        "confianza": 0.4,
                    })

        # emails
        if not isinstance(resultados_tareas[3], Exception):
            emails = resultados_tareas[3]
            if emails:
                resultados["emails_encontrados"] = emails
                for email in emails:
                    entidades.append({
                        "tipo": "email",
                        "valor": email,
                        "datos": {"fuente": "google_search"},
                        "confianza": 0.5,
                    })
                    relaciones.append({
                        "tipo_relacion": "owns",
                        "origen_valor": nombre,
                        "origen_tipo": "person",
                        "destino_valor": email,
                        "destino_tipo": "email",
                        "confianza": 0.4,
                    })

        self._entidades_encontradas = len(entidades)
        self._relaciones_creadas = len(relaciones)

        return ResultadoEnriquecimiento(
            fuente=self.nombre,
            tipo="person",
            datos=resultados,
            confianza=min(0.3 + (len(entidades) * 0.05), 0.9),
            entidades_nuevas=entidades,
            relaciones_nuevas=relaciones,
        )

    async def _google_dorks(self, nombre: str, ubicacion: str = "") -> Optional[dict]:
        """ejecuta google dorks automatizados para buscar a la persona"""
        dorks = [
            f'"{nombre}" site:linkedin.com/in',
            f'"{nombre}" site:github.com',
            f'"{nombre}" site:twitter.com OR site:x.com',
            f'"{nombre}" site:facebook.com',
            f'"{nombre}" site:instagram.com',
            f'"{nombre}" resume OR cv filetype:pdf',
            f'"{nombre}" email OR contact',
        ]

        if ubicacion:
            dorks.append(f'"{nombre}" "{ubicacion}"')

        perfiles = []
        for dork in dorks:
            url = f"https://www.google.com/search?q={dork}&num=5"
            resp = await self.request_con_rate_limit(url, servicio="default")

            if resp and resp.status_code == 200:
                soup = BeautifulSoup(resp.text, "html.parser")
                for resultado in soup.find_all("div", class_="g"):
                    link = resultado.find("a")
                    if link and link.get("href"):
                        href = link.get("href", "")
                        titulo = resultado.find("h3")
                        titulo_texto = titulo.get_text() if titulo else ""

                        plataforma = self._detectar_plataforma(href)
                        if plataforma:
                            perfiles.append({
                                "plataforma": plataforma,
                                "url": href,
                                "titulo": titulo_texto,
                                "dork": dork,
                            })

            await asyncio.sleep(2)  # evitar rate limit de google

        return {"perfiles": perfiles, "total": len(perfiles)} if perfiles else None

    async def _buscar_linkedin(self, nombre: str, ubicacion: str = "") -> Optional[dict]:
        """busca perfiles de linkedin via google"""
        query = f'site:linkedin.com/in "{nombre}"'
        if ubicacion:
            query += f' "{ubicacion}"'

        url = f"https://www.google.com/search?q={query}&num=10"
        resp = await self.request_con_rate_limit(url, servicio="default")

        perfiles = []
        if resp and resp.status_code == 200:
            soup = BeautifulSoup(resp.text, "html.parser")
            for link in soup.find_all("a"):
                href = link.get("href", "")
                if "linkedin.com/in/" in href:
                    titulo = link.get_text()
                    perfiles.append({
                        "url": href,
                        "titulo": titulo,
                        "plataforma": "linkedin",
                    })

        return {"perfiles": perfiles[:5], "total": len(perfiles)} if perfiles else None

    async def _buscar_github(self, nombre: str) -> Optional[dict]:
        """busca usuarios en github por nombre"""
        url = f"https://api.github.com/search/users?q={nombre}+type:user&per_page=10"
        headers = {"Accept": "application/vnd.github.v3+json"}

        resp = await self.request_con_rate_limit(url, servicio="github", headers=headers)
        if resp and resp.status_code == 200:
            datos = resp.json()
            usuarios = []
            for item in datos.get("items", [])[:10]:
                usuarios.append({
                    "login": item.get("login"),
                    "url": item.get("html_url"),
                    "avatar": item.get("avatar_url"),
                    "score": item.get("score"),
                })
            return {"usuarios": usuarios, "total": datos.get("total_count", 0)}
        return None

    async def _extraer_emails_google(self, nombre: str) -> list[str]:
        """extrae emails asociados al nombre desde google"""
        url = f'https://www.google.com/search?q="{nombre}"+email+%40&num=10'
        resp = await self.request_con_rate_limit(url, servicio="default")

        emails = set()
        if resp and resp.status_code == 200:
            patron_email = r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}'
            encontrados = re.findall(patron_email, resp.text)
            for email in encontrados:
                email = email.lower()
                # filtrar emails de google y otros no relevantes
                dominios_excluir = ["google.com", "gstatic.com", "googleapis.com", "schema.org", "w3.org"]
                if not any(d in email for d in dominios_excluir):
                    emails.add(email)

        return list(emails)[:10]

    def _detectar_plataforma(self, url: str) -> Optional[str]:
        """detecta la plataforma basandose en la url"""
        plataformas_map = {
            "linkedin.com": "linkedin",
            "github.com": "github",
            "twitter.com": "twitter",
            "x.com": "twitter",
            "facebook.com": "facebook",
            "instagram.com": "instagram",
            "reddit.com": "reddit",
            "medium.com": "medium",
            "youtube.com": "youtube",
            "tiktok.com": "tiktok",
        }
        for dominio, nombre in plataformas_map.items():
            if dominio in url:
                return nombre
        return None
