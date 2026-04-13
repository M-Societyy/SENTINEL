# sentinel - monitoreo de paste sites
# m-society & c1q_

import re
import asyncio
from typing import Optional

from bs4 import BeautifulSoup
import structlog

from modules.base import ModuloBase
from schemas.modulos import ResultadoEnriquecimiento

log = structlog.get_logger()

# patrones para deteccion de credenciales
PATRONES_CREDENCIALES = [
    r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}\s*[:;|]\s*\S+',  # email:password
    r'(?i)username\s*[:=]\s*\S+',
    r'(?i)password\s*[:=]\s*\S+',
    r'(?i)api[_-]?key\s*[:=]\s*[a-zA-Z0-9_\-]{20,}',
]


class PasteMonitor(ModuloBase):
    nombre = "paste_monitor"
    categoria = "breach"
    descripcion = "monitoreo de paste sites: pastebin, github gists, rentry"

    async def ejecutar(self, objetivo: str, parametros: dict = None) -> ResultadoEnriquecimiento:
        keywords = [objetivo.strip()]
        parametros = parametros or {}

        # keywords adicionales
        if parametros.get("keywords_extra"):
            keywords.extend(parametros["keywords_extra"])

        entidades = []
        relaciones = []
        resultados = {"keywords": keywords}

        tareas = [
            self._buscar_pastebin(keywords),
            self._buscar_github_gists(keywords),
            self._buscar_google_pastes(keywords),
        ]

        resultados_tareas = await asyncio.gather(*tareas, return_exceptions=True)

        pastes_encontrados = []

        for resultado in resultados_tareas:
            if isinstance(resultado, Exception):
                continue
            if resultado:
                pastes_encontrados.extend(resultado)

        # analizar cada paste encontrado
        for paste in pastes_encontrados:
            contenido = paste.get("contenido", "")
            credenciales = self._extraer_credenciales(contenido)
            paste["credenciales_detectadas"] = len(credenciales)
            paste["credenciales"] = credenciales[:20]

            # emails encontrados en el paste
            emails = re.findall(r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}', contenido)
            for email in set(emails):
                email = email.lower()
                excluir = ["example.com", "email.com", "test.com"]
                if not any(e in email for e in excluir):
                    entidades.append({
                        "tipo": "email", "valor": email,
                        "datos": {"fuente": "paste", "paste_url": paste.get("url")},
                        "confianza": 0.6,
                    })

        resultados["pastes"] = pastes_encontrados
        resultados["total"] = len(pastes_encontrados)

        self._entidades_encontradas = len(entidades)

        return ResultadoEnriquecimiento(
            fuente=self.nombre, tipo="credential",
            datos=resultados, confianza=0.7,
            entidades_nuevas=entidades,
            relaciones_nuevas=relaciones,
        )

    async def _buscar_pastebin(self, keywords: list[str]) -> list[dict]:
        """busca en pastebin via google dorks"""
        pastes = []
        for kw in keywords:
            url = f'https://www.google.com/search?q=site:pastebin.com+"{kw}"&num=10'
            resp = await self.request_con_rate_limit(url, servicio="default")

            if resp and resp.status_code == 200:
                soup = BeautifulSoup(resp.text, "html.parser")
                for div in soup.find_all("div", class_="g"):
                    link = div.find("a")
                    titulo = div.find("h3")
                    snippet = div.find("div", class_="VwiC3b")
                    if link and "pastebin.com" in link.get("href", ""):
                        paste_url = link.get("href")
                        # intentar obtener contenido
                        raw_url = paste_url.replace("pastebin.com/", "pastebin.com/raw/")
                        contenido = ""
                        resp_raw = await self.request_con_rate_limit(raw_url, servicio="default")
                        if resp_raw and resp_raw.status_code == 200:
                            contenido = resp_raw.text[:5000]

                        pastes.append({
                            "fuente": "pastebin",
                            "url": paste_url,
                            "titulo": titulo.get_text() if titulo else "",
                            "snippet": snippet.get_text() if snippet else "",
                            "contenido": contenido,
                            "keyword": kw,
                        })
            await asyncio.sleep(2)
        return pastes

    async def _buscar_github_gists(self, keywords: list[str]) -> list[dict]:
        """busca en github gists"""
        pastes = []
        for kw in keywords:
            url = f"https://api.github.com/search/code?q={kw}+in:file&type=Code"
            headers = {"Accept": "application/vnd.github.v3+json"}
            resp = await self.request_con_rate_limit(url, servicio="github", headers=headers)

            if resp and resp.status_code == 200:
                for item in resp.json().get("items", [])[:5]:
                    pastes.append({
                        "fuente": "github_gist",
                        "url": item.get("html_url"),
                        "nombre": item.get("name"),
                        "repo": item.get("repository", {}).get("full_name"),
                        "contenido": "",
                        "keyword": kw,
                    })
            await asyncio.sleep(1)
        return pastes

    async def _buscar_google_pastes(self, keywords: list[str]) -> list[dict]:
        """busca en multiples paste sites via google"""
        pastes = []
        sites = ["hastebin.com", "rentry.co", "privatebin.net"]

        for kw in keywords:
            for site in sites:
                url = f'https://www.google.com/search?q=site:{site}+"{kw}"&num=5'
                resp = await self.request_con_rate_limit(url, servicio="default")

                if resp and resp.status_code == 200:
                    soup = BeautifulSoup(resp.text, "html.parser")
                    for div in soup.find_all("div", class_="g"):
                        link = div.find("a")
                        if link and site in link.get("href", ""):
                            pastes.append({
                                "fuente": site.split(".")[0],
                                "url": link.get("href"),
                                "contenido": "",
                                "keyword": kw,
                            })
                await asyncio.sleep(2)
        return pastes

    def _extraer_credenciales(self, texto: str) -> list[dict]:
        """extrae credenciales del texto de un paste"""
        credenciales = []
        for patron in PATRONES_CREDENCIALES:
            matches = re.findall(patron, texto)
            for match in matches[:10]:
                credenciales.append({
                    "patron": patron[:30],
                    "valor": match[:100],  # truncar por seguridad
                })
        return credenciales
