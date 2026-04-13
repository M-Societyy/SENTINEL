# sentinel - inteligencia de ofertas de trabajo
# c1q_ (M-Society team)

import asyncio
import re
from typing import Optional

import httpx
import structlog
from bs4 import BeautifulSoup

from config import config
from modules.base import ModuloBase
from schemas.modulos import ResultadoEnriquecimiento

log = structlog.get_logger()

# tecnologias comunes para detectar en postings
TECNOLOGIAS_CONOCIDAS = [
    "python", "java", "javascript", "typescript", "go", "rust", "c++", "c#", "ruby", "php",
    "react", "angular", "vue", "node.js", "django", "flask", "spring", "kubernetes", "docker",
    "aws", "gcp", "azure", "terraform", "ansible", "jenkins", "gitlab", "github actions",
    "postgresql", "mysql", "mongodb", "redis", "elasticsearch", "kafka", "rabbitmq",
    "linux", "nginx", "graphql", "rest api", "microservices", "ci/cd",
]


class JobIntel(ModuloBase):
    nombre = "job_intel"
    categoria = "company"
    descripcion = "analisis de ofertas de trabajo para inferir stack tecnologico"
    requiere_api_key = False

    async def ejecutar(self, objetivo: str, parametros: dict = None) -> ResultadoEnriquecimiento:
        empresa = objetivo.strip()
        resultados = {}
        entidades = []

        # buscar en google por ofertas de trabajo
        ofertas = await self._buscar_ofertas_google(empresa)
        if ofertas:
            resultados["ofertas"] = ofertas

        # analizar tecnologias mencionadas
        stack = self._extraer_tecnologias(resultados)
        if stack:
            resultados["stack_tecnologico"] = stack
            entidades.append({
                "tipo": "organization",
                "valor": empresa,
                "datos": {"stack_tecnologico": stack, "fuente": "job_postings"},
                "confianza": 0.6,
            })

        self._entidades_encontradas = len(entidades)

        return ResultadoEnriquecimiento(
            fuente=self.nombre,
            tipo="organization",
            datos={
                "empresa": empresa,
                "ofertas_encontradas": len(resultados.get("ofertas", {}).get("resultados", [])),
                "stack_inferido": stack,
                "resultados": resultados,
            },
            confianza=0.5,
            entidades_nuevas=entidades,
        )

    async def _buscar_ofertas_google(self, empresa: str) -> Optional[dict]:
        """busca ofertas de empleo via google"""
        queries = [
            f'"{empresa}" site:linkedin.com/jobs',
            f'"{empresa}" careers hiring',
        ]
        resultados = []

        for query in queries:
            url = f"https://www.google.com/search?q={query}&num=10"
            resp = await self.request_con_rate_limit(url, servicio="google")
            if resp and resp.status_code == 200:
                soup = BeautifulSoup(resp.text, "lxml")
                for item in soup.select("div.g")[:10]:
                    titulo_elem = item.select_one("h3")
                    link_elem = item.select_one("a")
                    snippet_elem = item.select_one("span.st, div.VwiC3b")
                    if titulo_elem:
                        resultados.append({
                            "titulo": titulo_elem.get_text(strip=True),
                            "url": link_elem.get("href", "") if link_elem else "",
                            "snippet": snippet_elem.get_text(strip=True) if snippet_elem else "",
                        })

        return {"total": len(resultados), "resultados": resultados}

    def _extraer_tecnologias(self, resultados: dict) -> list[str]:
        """extrae tecnologias mencionadas en las ofertas encontradas"""
        texto_completo = ""
        for oferta in resultados.get("ofertas", {}).get("resultados", []):
            texto_completo += f" {oferta.get('titulo', '')} {oferta.get('snippet', '')}"

        texto_lower = texto_completo.lower()
        encontradas = []
        for tech in TECNOLOGIAS_CONOCIDAS:
            if tech in texto_lower:
                encontradas.append(tech)

        return encontradas
