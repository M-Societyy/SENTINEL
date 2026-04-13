# sentinel - modulo de inteligencia de email
# c1q_ (M-Society team)

import re
import hashlib
import asyncio
import socket
from typing import Optional

import httpx
import dns.resolver
import structlog

from config import config
from modules.base import ModuloBase
from schemas.modulos import ResultadoEnriquecimiento
from utils.user_agent_rotator import obtener_headers_api

log = structlog.get_logger()


class EmailIntel(ModuloBase):
    nombre = "email_intel"
    categoria = "identity"
    descripcion = "inteligencia de email: validacion, breaches, gravatar, github, hunter, correlacion"
    requiere_api_key = True

    async def ejecutar(self, objetivo: str, parametros: dict = None) -> ResultadoEnriquecimiento:
        email = objetivo.strip().lower()

        if not self._validar_sintaxis(email):
            return ResultadoEnriquecimiento(
                fuente=self.nombre, tipo="email",
                error="email con formato invalido", confianza=0.0,
            )

        resultados = {}
        entidades = []
        relaciones = []

        # ejecutar todas las verificaciones en paralelo
        tareas = [
            self._verificar_mx(email),
            self._verificar_smtp(email),
            self._buscar_gravatar(email),
            self._buscar_github_commits(email),
        ]

        # agregar tareas que requieren api key solo si estan configuradas
        if config.hibp_api_key:
            tareas.append(self._buscar_hibp(email))
        if config.dehashed_api_key:
            tareas.append(self._buscar_dehashed(email))
        if config.hunter_api_key:
            tareas.append(self._buscar_hunter(email))

        resultados_tareas = await asyncio.gather(*tareas, return_exceptions=True)

        # procesar resultados de mx
        idx = 0
        if not isinstance(resultados_tareas[idx], Exception):
            resultados["mx"] = resultados_tareas[idx]
        idx += 1

        # smtp
        if not isinstance(resultados_tareas[idx], Exception):
            resultados["smtp"] = resultados_tareas[idx]
        idx += 1

        # gravatar
        if not isinstance(resultados_tareas[idx], Exception):
            gravatar = resultados_tareas[idx]
            if gravatar:
                resultados["gravatar"] = gravatar
                entidades.append({
                    "tipo": "social_profile",
                    "valor": f"gravatar:{email}",
                    "datos": gravatar,
                    "confianza": 0.8,
                })
                relaciones.append({
                    "tipo_relacion": "owns",
                    "origen_valor": email,
                    "origen_tipo": "email",
                    "destino_valor": f"gravatar:{email}",
                    "destino_tipo": "social_profile",
                    "confianza": 0.9,
                })
        idx += 1

        # github commits
        if not isinstance(resultados_tareas[idx], Exception):
            github = resultados_tareas[idx]
            if github:
                resultados["github"] = github
                for usuario_gh in github.get("usuarios", []):
                    entidades.append({
                        "tipo": "username",
                        "valor": usuario_gh,
                        "datos": {"plataforma": "github", "fuente": "commits"},
                        "confianza": 0.85,
                    })
                    relaciones.append({
                        "tipo_relacion": "owns",
                        "origen_valor": email,
                        "origen_tipo": "email",
                        "destino_valor": usuario_gh,
                        "destino_tipo": "username",
                        "confianza": 0.85,
                    })
        idx += 1

        # hibp
        if config.hibp_api_key and not isinstance(resultados_tareas[idx], Exception):
            hibp = resultados_tareas[idx]
            if hibp:
                resultados["hibp"] = hibp
                for breach in hibp.get("breaches", []):
                    entidades.append({
                        "tipo": "credential",
                        "valor": f"breach:{breach.get('Name', 'desconocido')}:{email}",
                        "datos": breach,
                        "confianza": 0.95,
                    })
                    relaciones.append({
                        "tipo_relacion": "leaked_in",
                        "origen_valor": email,
                        "origen_tipo": "email",
                        "destino_valor": f"breach:{breach.get('Name', 'desconocido')}",
                        "destino_tipo": "credential",
                        "confianza": 0.95,
                    })
            idx += 1

        # dehashed
        if config.dehashed_api_key and not isinstance(resultados_tareas[idx], Exception):
            dehashed = resultados_tareas[idx]
            if dehashed:
                resultados["dehashed"] = dehashed
            idx += 1

        # hunter
        if config.hunter_api_key and not isinstance(resultados_tareas[idx], Exception):
            hunter = resultados_tareas[idx]
            if hunter:
                resultados["hunter"] = hunter
                if hunter.get("organizacion"):
                    entidades.append({
                        "tipo": "organization",
                        "valor": hunter["organizacion"],
                        "datos": {"fuente": "hunter.io", "dominio": hunter.get("dominio")},
                        "confianza": 0.8,
                    })
                    relaciones.append({
                        "tipo_relacion": "member_of",
                        "origen_valor": email,
                        "origen_tipo": "email",
                        "destino_valor": hunter["organizacion"],
                        "destino_tipo": "organization",
                        "confianza": 0.75,
                    })
                if hunter.get("nombre"):
                    entidades.append({
                        "tipo": "person",
                        "valor": hunter["nombre"],
                        "datos": {"fuente": "hunter.io", "cargo": hunter.get("cargo")},
                        "confianza": 0.7,
                    })
                    relaciones.append({
                        "tipo_relacion": "owns",
                        "origen_valor": hunter["nombre"],
                        "origen_tipo": "person",
                        "destino_valor": email,
                        "destino_tipo": "email",
                        "confianza": 0.7,
                    })

        # calcular score de confianza general
        confianza = self._calcular_confianza(resultados)

        self._entidades_encontradas = len(entidades)
        self._relaciones_creadas = len(relaciones)

        return ResultadoEnriquecimiento(
            fuente=self.nombre,
            tipo="email",
            datos={
                "email": email,
                "dominio": email.split("@")[1],
                "valido_sintaxis": True,
                "mx_valido": resultados.get("mx", {}).get("valido", False),
                "smtp_valido": resultados.get("smtp", {}).get("existe", None),
                "resultados_detalle": resultados,
            },
            confianza=confianza,
            entidades_nuevas=entidades,
            relaciones_nuevas=relaciones,
        )

    def _validar_sintaxis(self, email: str) -> bool:
        patron = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
        return bool(re.match(patron, email))

    async def _verificar_mx(self, email: str) -> dict:
        """verifica registros mx del dominio del email"""
        dominio = email.split("@")[1]
        try:
            resolver = dns.resolver.Resolver()
            resolver.timeout = 10
            resolver.lifetime = 10
            respuesta = resolver.resolve(dominio, "MX")
            registros = []
            for rdata in respuesta:
                registros.append({
                    "prioridad": rdata.preference,
                    "servidor": str(rdata.exchange).rstrip("."),
                })
            return {"valido": True, "registros_mx": registros, "dominio": dominio}
        except dns.resolver.NXDOMAIN:
            return {"valido": False, "error": "dominio no existe"}
        except dns.resolver.NoAnswer:
            return {"valido": False, "error": "sin registros mx"}
        except Exception as e:
            return {"valido": False, "error": str(e)}

    async def _verificar_smtp(self, email: str) -> dict:
        """verifica existencia del email via smtp handshake sin enviar correo"""
        dominio = email.split("@")[1]
        try:
            resolver = dns.resolver.Resolver()
            registros_mx = resolver.resolve(dominio, "MX")
            servidor_mx = str(list(registros_mx)[0].exchange).rstrip(".")

            loop = asyncio.get_event_loop()
            resultado = await loop.run_in_executor(
                None, self._smtp_check_sync, email, servidor_mx
            )
            return resultado
        except Exception as e:
            return {"existe": None, "error": str(e)}

    def _smtp_check_sync(self, email: str, servidor_mx: str) -> dict:
        """verificacion smtp sincrona (se ejecuta en thread pool)"""
        import smtplib
        try:
            smtp = smtplib.SMTP(timeout=10)
            smtp.connect(servidor_mx, 25)
            smtp.helo("sentinel.local")
            smtp.mail("check@sentinel.local")
            codigo, mensaje = smtp.rcpt(email)
            smtp.quit()

            if codigo == 250:
                return {"existe": True, "codigo": codigo, "servidor": servidor_mx}
            else:
                return {"existe": False, "codigo": codigo, "mensaje": mensaje.decode()}
        except smtplib.SMTPServerDisconnected:
            return {"existe": None, "error": "servidor desconecto"}
        except smtplib.SMTPConnectError:
            return {"existe": None, "error": "no se pudo conectar al smtp"}
        except socket.timeout:
            return {"existe": None, "error": "timeout smtp"}
        except Exception as e:
            return {"existe": None, "error": str(e)}

    async def _buscar_gravatar(self, email: str) -> Optional[dict]:
        """busca perfil de gravatar usando hash md5 del email"""
        hash_email = hashlib.md5(email.encode()).hexdigest()
        url_perfil = f"https://www.gravatar.com/{hash_email}.json"
        url_avatar = f"https://www.gravatar.com/avatar/{hash_email}?d=404"

        resp = await self.request_con_rate_limit(url_perfil, servicio="default")
        if resp and resp.status_code == 200:
            try:
                datos = resp.json()
                entrada = datos.get("entry", [{}])[0]
                return {
                    "hash": hash_email,
                    "nombre_display": entrada.get("displayName"),
                    "url_perfil": entrada.get("profileUrl"),
                    "url_avatar": url_avatar,
                    "fotos": entrada.get("photos", []),
                    "ubicacion": entrada.get("currentLocation"),
                    "sobre_mi": entrada.get("aboutMe"),
                    "cuentas": entrada.get("accounts", []),
                }
            except Exception:
                pass

        # al menos verificar si tiene avatar
        resp_avatar = await self.request_con_rate_limit(url_avatar, servicio="default")
        if resp_avatar and resp_avatar.status_code == 200:
            return {
                "hash": hash_email,
                "url_avatar": url_avatar,
                "tiene_avatar": True,
            }

        return None

    async def _buscar_github_commits(self, email: str) -> Optional[dict]:
        """busca commits en github asociados a este email"""
        url = f"https://api.github.com/search/commits?q=author-email:{email}"
        headers = {
            "Accept": "application/vnd.github.cloak-preview+json",
            "User-Agent": "SENTINEL-OSINT/1.0",
        }

        resp = await self.request_con_rate_limit(url, servicio="github", headers=headers)
        if resp and resp.status_code == 200:
            datos = resp.json()
            usuarios = set()
            repos = []

            for item in datos.get("items", [])[:20]:
                autor = item.get("author")
                if autor:
                    usuarios.add(autor.get("login", ""))
                repo = item.get("repository", {})
                if repo:
                    repos.append({
                        "nombre": repo.get("full_name"),
                        "url": repo.get("html_url"),
                    })

            usuarios.discard("")
            return {
                "total_commits": datos.get("total_count", 0),
                "usuarios": list(usuarios),
                "repos": repos[:10],
            }
        return None

    async def _buscar_hibp(self, email: str) -> Optional[dict]:
        """busca el email en haveibeenpwned"""
        url = f"https://haveibeenpwned.com/api/v3/breachedaccount/{email}"
        headers = {
            "hibp-api-key": config.hibp_api_key,
            "User-Agent": "SENTINEL-OSINT/1.0",
        }

        resp = await self.request_con_rate_limit(
            url, servicio="hibp", headers=headers,
            params={"truncateResponse": "false"},
        )

        if resp and resp.status_code == 200:
            breaches = resp.json()
            return {
                "encontrado": True,
                "total_breaches": len(breaches),
                "breaches": breaches,
            }
        elif resp and resp.status_code == 404:
            return {"encontrado": False, "total_breaches": 0, "breaches": []}

        return None

    async def _buscar_dehashed(self, email: str) -> Optional[dict]:
        """busca credenciales filtradas en dehashed"""
        url = "https://api.dehashed.com/search"
        headers = obtener_headers_api(config.dehashed_api_key, bearer=True)

        resp = await self.request_con_rate_limit(
            url, servicio="default", headers=headers,
            params={"query": f"email:{email}", "size": 100},
        )

        if resp and resp.status_code == 200:
            datos = resp.json()
            return {
                "total": datos.get("total", 0),
                "entradas": datos.get("entries", [])[:50],
            }
        return None

    async def _buscar_hunter(self, email: str) -> Optional[dict]:
        """busca informacion del email en hunter.io"""
        url = "https://api.hunter.io/v2/email-verifier"
        params = {
            "email": email,
            "api_key": config.hunter_api_key,
        }

        resp = await self.request_con_rate_limit(url, servicio="hunter", params=params)

        if resp and resp.status_code == 200:
            datos = resp.json().get("data", {})
            return {
                "estado": datos.get("status"),
                "score": datos.get("score"),
                "nombre": f"{datos.get('first_name', '')} {datos.get('last_name', '')}".strip() or None,
                "cargo": datos.get("position"),
                "organizacion": datos.get("organization"),
                "dominio": datos.get("domain"),
                "twitter": datos.get("twitter"),
                "linkedin": datos.get("linkedin_url"),
            }
        return None

    def _calcular_confianza(self, resultados: dict) -> float:
        """calcula score de confianza basado en cuantas fuentes confirmaron datos"""
        score = 0.3  # base

        if resultados.get("mx", {}).get("valido"):
            score += 0.1
        if resultados.get("smtp", {}).get("existe"):
            score += 0.15
        if resultados.get("gravatar"):
            score += 0.1
        if resultados.get("github"):
            score += 0.1
        if resultados.get("hibp", {}).get("encontrado"):
            score += 0.1
        if resultados.get("hunter", {}).get("nombre"):
            score += 0.1
        if resultados.get("dehashed", {}).get("total", 0) > 0:
            score += 0.05

        return min(score, 1.0)
