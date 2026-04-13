# sentinel - enumeracion de empleados de una organizacion
# c1q_ (M-Society team)

import asyncio
from typing import Optional

import httpx
import structlog

from config import config
from modules.base import ModuloBase
from schemas.modulos import ResultadoEnriquecimiento
from utils.user_agent_rotator import obtener_headers_api

log = structlog.get_logger()


class EmployeeEnum(ModuloBase):
    nombre = "employee_enum"
    categoria = "company"
    descripcion = "enumeracion de empleados via hunter.io, github y fuentes publicas"
    requiere_api_key = True

    async def ejecutar(self, objetivo: str, parametros: dict = None) -> ResultadoEnriquecimiento:
        dominio = objetivo.strip().lower()
        resultados = {}
        entidades = []
        relaciones = []

        tareas = [
            self._buscar_hunter_dominio(dominio),
            self._buscar_github_org(dominio),
        ]

        resultados_tareas = await asyncio.gather(*tareas, return_exceptions=True)

        # hunter.io - emails por dominio
        if not isinstance(resultados_tareas[0], Exception) and resultados_tareas[0]:
            hunter = resultados_tareas[0]
            resultados["hunter"] = hunter
            for emp in hunter.get("empleados", []):
                if emp.get("email"):
                    entidades.append({
                        "tipo": "email",
                        "valor": emp["email"],
                        "datos": {
                            "nombre": emp.get("nombre"),
                            "cargo": emp.get("cargo"),
                            "departamento": emp.get("departamento"),
                            "fuente": "hunter.io",
                        },
                        "confianza": 0.8,
                    })
                    relaciones.append({
                        "tipo_relacion": "member_of",
                        "origen_valor": emp["email"],
                        "origen_tipo": "email",
                        "destino_valor": dominio,
                        "destino_tipo": "organization",
                        "confianza": 0.8,
                    })
                if emp.get("nombre"):
                    entidades.append({
                        "tipo": "person",
                        "valor": emp["nombre"],
                        "datos": {"cargo": emp.get("cargo"), "empresa": dominio},
                        "confianza": 0.7,
                    })

        # github org
        if not isinstance(resultados_tareas[1], Exception) and resultados_tareas[1]:
            github = resultados_tareas[1]
            resultados["github"] = github
            for miembro in github.get("miembros", []):
                entidades.append({
                    "tipo": "username",
                    "valor": miembro["login"],
                    "datos": {"plataforma": "github", "fuente": "org_members"},
                    "confianza": 0.75,
                })

        # inferir patron de email
        patron = self._inferir_patron_email(resultados.get("hunter", {}).get("empleados", []), dominio)
        if patron:
            resultados["patron_email"] = patron

        self._entidades_encontradas = len(entidades)
        self._relaciones_creadas = len(relaciones)

        return ResultadoEnriquecimiento(
            fuente=self.nombre,
            tipo="organization",
            datos={
                "dominio": dominio,
                "total_empleados_encontrados": len(entidades),
                "patron_email": resultados.get("patron_email"),
                "resultados": resultados,
            },
            confianza=0.7,
            entidades_nuevas=entidades,
            relaciones_nuevas=relaciones,
        )

    async def _buscar_hunter_dominio(self, dominio: str) -> Optional[dict]:
        """busca emails de un dominio en hunter.io"""
        if not config.hunter_api_key:
            return None

        url = "https://api.hunter.io/v2/domain-search"
        params = {"domain": dominio, "api_key": config.hunter_api_key, "limit": 100}

        resp = await self.request_con_rate_limit(url, servicio="hunter", params=params)
        if resp and resp.status_code == 200:
            datos = resp.json().get("data", {})
            empleados = []
            for email_info in datos.get("emails", []):
                empleados.append({
                    "email": email_info.get("value"),
                    "nombre": f"{email_info.get('first_name', '')} {email_info.get('last_name', '')}".strip(),
                    "cargo": email_info.get("position"),
                    "departamento": email_info.get("department"),
                    "confianza": email_info.get("confidence", 0),
                })
            return {
                "organizacion": datos.get("organization"),
                "total": datos.get("total", 0),
                "patron": datos.get("pattern"),
                "empleados": empleados,
            }
        return None

    async def _buscar_github_org(self, dominio: str) -> Optional[dict]:
        """busca organizacion en github y lista miembros publicos"""
        # limpiar dominio para buscar como org
        org_nombre = dominio.split(".")[0]
        url = f"https://api.github.com/orgs/{org_nombre}/members"
        headers = {"Accept": "application/vnd.github.v3+json", "User-Agent": "SENTINEL-OSINT/1.0"}

        resp = await self.request_con_rate_limit(url, servicio="github", headers=headers)
        if resp and resp.status_code == 200:
            miembros = resp.json()
            return {
                "organizacion": org_nombre,
                "miembros": [{"login": m.get("login"), "avatar": m.get("avatar_url")} for m in miembros[:50]],
                "total_publicos": len(miembros),
            }
        return None

    def _inferir_patron_email(self, empleados: list, dominio: str) -> Optional[str]:
        """intenta inferir el patron de emails corporativos"""
        patrones = {}
        for emp in empleados:
            email = emp.get("email", "")
            nombre = emp.get("nombre", "")
            if not email or not nombre or "@" not in email:
                continue

            local = email.split("@")[0].lower()
            partes_nombre = nombre.lower().split()
            if len(partes_nombre) >= 2:
                nombre_p = partes_nombre[0]
                apellido_p = partes_nombre[-1]

                if local == f"{nombre_p}.{apellido_p}":
                    patrones["nombre.apellido"] = patrones.get("nombre.apellido", 0) + 1
                elif local == f"{nombre_p[0]}{apellido_p}":
                    patrones["n_apellido"] = patrones.get("n_apellido", 0) + 1
                elif local == f"{nombre_p}{apellido_p[0]}":
                    patrones["nombre_a"] = patrones.get("nombre_a", 0) + 1
                elif local == nombre_p:
                    patrones["nombre"] = patrones.get("nombre", 0) + 1

        if patrones:
            patron_mas_comun = max(patrones, key=patrones.get)
            return f"{patron_mas_comun}@{dominio}"
        return None
