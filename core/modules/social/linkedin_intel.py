# sentinel - inteligencia de linkedin
# c1q_ (M-Society team)

import asyncio
from typing import Optional

from bs4 import BeautifulSoup
import structlog

from modules.base import ModuloBase
from schemas.modulos import ResultadoEnriquecimiento
from utils.user_agent_rotator import obtener_headers_completos

log = structlog.get_logger()


class LinkedinIntel(ModuloBase):
    nombre = "linkedin_intel"
    categoria = "social"
    descripcion = "inteligencia de linkedin: perfil, empresa, historial laboral"

    async def ejecutar(self, objetivo: str, parametros: dict = None) -> ResultadoEnriquecimiento:
        username = objetivo.strip()

        entidades = []
        relaciones = []
        resultados = {"username": username}

        # buscar perfil via google
        perfil = await self._buscar_perfil_google(username)
        if perfil:
            resultados["perfil"] = perfil
            if perfil.get("nombre"):
                entidades.append({
                    "tipo": "person", "valor": perfil["nombre"],
                    "datos": {"fuente": "linkedin", "cargo": perfil.get("cargo")},
                    "confianza": 0.8,
                })
            if perfil.get("empresa"):
                entidades.append({
                    "tipo": "organization", "valor": perfil["empresa"],
                    "datos": {"fuente": "linkedin"},
                    "confianza": 0.7,
                })
                relaciones.append({
                    "tipo_relacion": "member_of",
                    "origen_valor": perfil.get("nombre", username), "origen_tipo": "person",
                    "destino_valor": perfil["empresa"], "destino_tipo": "organization",
                    "confianza": 0.75,
                })
            if perfil.get("ubicacion"):
                entidades.append({
                    "tipo": "location", "valor": perfil["ubicacion"],
                    "datos": {"fuente": "linkedin"},
                    "confianza": 0.6,
                })

        self._entidades_encontradas = len(entidades)
        self._relaciones_creadas = len(relaciones)

        return ResultadoEnriquecimiento(
            fuente=self.nombre, tipo="social_profile",
            datos=resultados, confianza=0.7,
            entidades_nuevas=entidades,
            relaciones_nuevas=relaciones,
        )

    async def _buscar_perfil_google(self, username: str) -> Optional[dict]:
        """busca perfil linkedin via google para evitar bloqueo directo"""
        url = f'https://www.google.com/search?q=site:linkedin.com/in/+"{username}"'
        resp = await self.request_con_rate_limit(url, servicio="default")

        if resp and resp.status_code == 200:
            soup = BeautifulSoup(resp.text, "html.parser")
            for resultado in soup.find_all("div", class_="g"):
                link = resultado.find("a")
                titulo = resultado.find("h3")
                snippet = resultado.find("div", class_="VwiC3b")

                if link and "linkedin.com/in/" in link.get("href", ""):
                    titulo_texto = titulo.get_text() if titulo else ""
                    snippet_texto = snippet.get_text() if snippet else ""

                    # extraer nombre del titulo (formato: "Nombre - Cargo - Empresa | LinkedIn")
                    partes = titulo_texto.replace(" | LinkedIn", "").split(" - ")
                    nombre = partes[0].strip() if partes else ""
                    cargo = partes[1].strip() if len(partes) > 1 else ""
                    empresa = partes[2].strip() if len(partes) > 2 else ""

                    return {
                        "nombre": nombre,
                        "cargo": cargo,
                        "empresa": empresa,
                        "url": link.get("href"),
                        "snippet": snippet_texto,
                        "ubicacion": self._extraer_ubicacion(snippet_texto),
                    }
        return None

    def _extraer_ubicacion(self, texto: str) -> Optional[str]:
        """intenta extraer ubicacion del snippet"""
        import re
        # patrones comunes de ubicacion en linkedin
        patrones = [
            r"(?:ubicaci[oó]n|location|area)\s*[:·]\s*([^·\n]+)",
            r"([A-Z][a-z]+(?:\s[A-Z][a-z]+)*,\s*[A-Z][a-z]+(?:\s[A-Z][a-z]+)*)",
        ]
        for patron in patrones:
            match = re.search(patron, texto, re.IGNORECASE)
            if match:
                return match.group(1).strip()
        return None
