# sentinel - cliente haveibeenpwned
# m-society & c1q_

import hashlib
import asyncio
from typing import Optional

import structlog

from config import config
from modules.base import ModuloBase
from schemas.modulos import ResultadoEnriquecimiento

log = structlog.get_logger()


class HibpClient(ModuloBase):
    nombre = "hibp_client"
    categoria = "breach"
    descripcion = "busqueda en haveibeenpwned: breaches, pastes, passwords comprometidos"
    requiere_api_key = True

    async def ejecutar(self, objetivo: str, parametros: dict = None) -> ResultadoEnriquecimiento:
        email = objetivo.strip().lower()
        parametros = parametros or {}
        verificar_password = parametros.get("verificar_password")

        entidades = []
        relaciones = []
        resultados = {"email": email}

        tareas = [
            self._buscar_breaches(email),
            self._buscar_pastes(email),
        ]

        if verificar_password:
            tareas.append(self._verificar_password(verificar_password))

        resultados_tareas = await asyncio.gather(*tareas, return_exceptions=True)

        # breaches
        if not isinstance(resultados_tareas[0], Exception) and resultados_tareas[0]:
            resultados["breaches"] = resultados_tareas[0]
            for breach in resultados_tareas[0].get("lista", []):
                entidades.append({
                    "tipo": "credential",
                    "valor": f"breach:{breach.get('Name')}:{email}",
                    "datos": {
                        "breach_nombre": breach.get("Name"),
                        "breach_dominio": breach.get("Domain"),
                        "fecha_breach": breach.get("BreachDate"),
                        "datos_comprometidos": breach.get("DataClasses", []),
                        "total_cuentas": breach.get("PwnCount"),
                        "verificado": breach.get("IsVerified"),
                    },
                    "confianza": 0.95,
                })
                relaciones.append({
                    "tipo_relacion": "leaked_in",
                    "origen_valor": email, "origen_tipo": "email",
                    "destino_valor": f"breach:{breach.get('Name')}", "destino_tipo": "credential",
                    "confianza": 0.95,
                })
                if breach.get("Domain"):
                    entidades.append({
                        "tipo": "domain", "valor": breach["Domain"],
                        "datos": {"fuente": "hibp_breach", "breach": breach.get("Name")},
                        "confianza": 0.9,
                    })

        # pastes
        if not isinstance(resultados_tareas[1], Exception) and resultados_tareas[1]:
            resultados["pastes"] = resultados_tareas[1]

        # password
        if verificar_password and len(resultados_tareas) > 2:
            if not isinstance(resultados_tareas[2], Exception) and resultados_tareas[2]:
                resultados["password_check"] = resultados_tareas[2]

        self._entidades_encontradas = len(entidades)
        self._relaciones_creadas = len(relaciones)

        return ResultadoEnriquecimiento(
            fuente=self.nombre, tipo="email",
            datos=resultados, confianza=0.9,
            entidades_nuevas=entidades,
            relaciones_nuevas=relaciones,
        )

    async def _buscar_breaches(self, email: str) -> Optional[dict]:
        if not config.hibp_api_key:
            return None

        url = f"https://haveibeenpwned.com/api/v3/breachedaccount/{email}"
        headers = {
            "hibp-api-key": config.hibp_api_key,
            "User-Agent": "SENTINEL-OSINT-Platform",
        }

        resp = await self.request_con_rate_limit(
            url, servicio="hibp", headers=headers,
            params={"truncateResponse": "false"},
        )

        if resp and resp.status_code == 200:
            breaches = resp.json()
            return {"encontrado": True, "total": len(breaches), "lista": breaches}
        elif resp and resp.status_code == 404:
            return {"encontrado": False, "total": 0, "lista": []}
        return None

    async def _buscar_pastes(self, email: str) -> Optional[dict]:
        if not config.hibp_api_key:
            return None

        url = f"https://haveibeenpwned.com/api/v3/pasteaccount/{email}"
        headers = {
            "hibp-api-key": config.hibp_api_key,
            "User-Agent": "SENTINEL-OSINT-Platform",
        }

        resp = await self.request_con_rate_limit(url, servicio="hibp", headers=headers)

        if resp and resp.status_code == 200:
            pastes = resp.json()
            return {"encontrado": True, "total": len(pastes), "lista": pastes}
        elif resp and resp.status_code == 404:
            return {"encontrado": False, "total": 0, "lista": []}
        return None

    async def _verificar_password(self, password: str) -> dict:
        """verifica si un password esta comprometido usando k-anonymity"""
        sha1 = hashlib.sha1(password.encode()).hexdigest().upper()
        prefijo = sha1[:5]
        sufijo = sha1[5:]

        url = f"https://api.pwnedpasswords.com/range/{prefijo}"
        resp = await self.request_con_rate_limit(url, servicio="hibp")

        if resp and resp.status_code == 200:
            for linea in resp.text.split("\r\n"):
                partes = linea.split(":")
                if len(partes) == 2 and partes[0] == sufijo:
                    return {
                        "comprometido": True,
                        "veces_visto": int(partes[1]),
                    }
            return {"comprometido": False, "veces_visto": 0}
        return {"comprometido": None, "error": "no se pudo verificar"}
