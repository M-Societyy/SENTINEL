# sentinel - enumeracion de subdominios pasiva y activa
# c1q_ (M-Society team)

import asyncio
from typing import Optional

import dns.resolver
import httpx
import structlog

from config import config
from modules.base import ModuloBase
from schemas.modulos import ResultadoEnriquecimiento

log = structlog.get_logger()


class SubdomainEnum(ModuloBase):
    nombre = "subdomain_enum"
    categoria = "network"
    descripcion = "enumeracion de subdominios pasiva y activa"

    async def ejecutar(self, objetivo: str, parametros: dict = None) -> ResultadoEnriquecimiento:
        dominio = objetivo.strip().lower()
        parametros = parametros or {}
        modo = parametros.get("modo", "pasivo")  # pasivo, activo, ambos

        entidades = []
        relaciones = []
        subdominios_encontrados = set()

        # fuentes pasivas siempre se ejecutan
        tareas_pasivas = [
            self._crtsh(dominio),
            self._buscar_virustotal(dominio),
            self._buscar_hackertarget(dominio),
            self._buscar_rapiddns(dominio),
            self._buscar_webarchive(dominio),
        ]

        if config.securitytrails_api_key:
            tareas_pasivas.append(self._buscar_securitytrails(dominio))

        resultados_pasivos = await asyncio.gather(*tareas_pasivas, return_exceptions=True)

        for resultado in resultados_pasivos:
            if isinstance(resultado, Exception):
                continue
            if resultado:
                subdominios_encontrados.update(resultado)

        # brute force activo si se solicita
        if modo in ("activo", "ambos"):
            wordlist = parametros.get("wordlist", self._wordlist_default())
            activos = await self._brute_force_dns(dominio, wordlist)
            subdominios_encontrados.update(activos)

        # permutaciones automaticas
        permutaciones = self._generar_permutaciones(dominio)
        perm_result = await self._resolver_batch(permutaciones)
        subdominios_encontrados.update(perm_result)

        # resolver todos los subdominios encontrados
        resultados_resueltos = await self._resolver_batch(list(subdominios_encontrados))

        # construir entidades
        for sub in resultados_resueltos:
            entidades.append({
                "tipo": "domain",
                "valor": sub["subdominio"],
                "datos": {
                    "ips": sub.get("ips", []),
                    "activo": sub.get("activo", False),
                    "fuente": "subdomain_enum",
                    "dominio_padre": dominio,
                },
                "confianza": 0.85,
            })
            relaciones.append({
                "tipo_relacion": "associated_with",
                "origen_valor": dominio, "origen_tipo": "domain",
                "destino_valor": sub["subdominio"], "destino_tipo": "domain",
                "confianza": 0.9,
            })
            for ip in sub.get("ips", []):
                entidades.append({
                    "tipo": "ip", "valor": ip,
                    "datos": {"fuente": "dns_resolution", "subdominio": sub["subdominio"]},
                    "confianza": 0.9,
                })
                relaciones.append({
                    "tipo_relacion": "resolves_to",
                    "origen_valor": sub["subdominio"], "origen_tipo": "domain",
                    "destino_valor": ip, "destino_tipo": "ip",
                    "confianza": 0.95,
                })

        self._entidades_encontradas = len(entidades)
        self._relaciones_creadas = len(relaciones)

        return ResultadoEnriquecimiento(
            fuente=self.nombre, tipo="domain",
            datos={
                "dominio": dominio,
                "total_subdominios": len(subdominios_encontrados),
                "subdominios": [s for s in resultados_resueltos],
                "modo": modo,
            },
            confianza=0.85,
            entidades_nuevas=entidades,
            relaciones_nuevas=relaciones,
        )

    async def _crtsh(self, dominio: str) -> set[str]:
        """busca subdominios en certificate transparency via crt.sh"""
        subdominios = set()
        url = f"https://crt.sh/?q=%.{dominio}&output=json"

        resp = await self.request_con_rate_limit(url, servicio="default", timeout=30.0)
        if resp and resp.status_code == 200:
            try:
                datos = resp.json()
                for entrada in datos:
                    nombre = entrada.get("name_value", "")
                    for linea in nombre.split("\n"):
                        linea = linea.strip().lower()
                        if linea.endswith(f".{dominio}") or linea == dominio:
                            if "*" not in linea:
                                subdominios.add(linea)
            except Exception as e:
                log.debug("error parseando crt.sh", error=str(e))

        return subdominios

    async def _buscar_virustotal(self, dominio: str) -> set[str]:
        """busca subdominios en virustotal"""
        if not config.virustotal_api_key:
            return set()

        subdominios = set()
        url = f"https://www.virustotal.com/api/v3/domains/{dominio}/subdomains"
        headers = {"x-apikey": config.virustotal_api_key}

        resp = await self.request_con_rate_limit(url, servicio="virustotal", headers=headers)
        if resp and resp.status_code == 200:
            datos = resp.json()
            for item in datos.get("data", []):
                sub = item.get("id", "")
                if sub:
                    subdominios.add(sub)

        return subdominios

    async def _buscar_securitytrails(self, dominio: str) -> set[str]:
        """busca subdominios en securitytrails"""
        subdominios = set()
        url = f"https://api.securitytrails.com/v1/domain/{dominio}/subdomains"
        headers = {"APIKEY": config.securitytrails_api_key}

        resp = await self.request_con_rate_limit(url, servicio="securitytrails", headers=headers)
        if resp and resp.status_code == 200:
            datos = resp.json()
            for sub in datos.get("subdomains", []):
                subdominios.add(f"{sub}.{dominio}")

        return subdominios

    async def _buscar_hackertarget(self, dominio: str) -> set[str]:
        """busca subdominios en hackertarget"""
        subdominios = set()
        url = f"https://api.hackertarget.com/hostsearch/?q={dominio}"

        resp = await self.request_con_rate_limit(url, servicio="default")
        if resp and resp.status_code == 200:
            for linea in resp.text.split("\n"):
                partes = linea.strip().split(",")
                if partes and partes[0].endswith(f".{dominio}"):
                    subdominios.add(partes[0])

        return subdominios

    async def _buscar_rapiddns(self, dominio: str) -> set[str]:
        """busca subdominios en rapiddns"""
        subdominios = set()
        url = f"https://rapiddns.io/subdomain/{dominio}?full=1"

        resp = await self.request_con_rate_limit(url, servicio="default")
        if resp and resp.status_code == 200:
            from bs4 import BeautifulSoup
            soup = BeautifulSoup(resp.text, "html.parser")
            tabla = soup.find("table")
            if tabla:
                for fila in tabla.find_all("tr"):
                    celdas = fila.find_all("td")
                    if celdas:
                        sub = celdas[0].get_text().strip()
                        if sub.endswith(f".{dominio}"):
                            subdominios.add(sub)

        return subdominios

    async def _buscar_webarchive(self, dominio: str) -> set[str]:
        """busca subdominios en web.archive.org"""
        subdominios = set()
        url = f"https://web.archive.org/cdx/search/cdx?url=*.{dominio}&output=text&fl=original&collapse=urlkey"

        resp = await self.request_con_rate_limit(url, servicio="default", timeout=30.0)
        if resp and resp.status_code == 200:
            import re
            patron = r'https?://([a-zA-Z0-9.-]+\.' + re.escape(dominio) + ')'
            encontrados = re.findall(patron, resp.text)
            for sub in encontrados:
                subdominios.add(sub.lower())

        return subdominios

    async def _brute_force_dns(self, dominio: str, wordlist: list[str]) -> set[str]:
        """brute force de subdominios via dns"""
        encontrados = set()
        semaforo = asyncio.Semaphore(50)

        async def resolver_uno(palabra: str):
            async with semaforo:
                sub = f"{palabra}.{dominio}"
                try:
                    resolver = dns.resolver.Resolver()
                    resolver.timeout = 3
                    resolver.lifetime = 3
                    loop = asyncio.get_event_loop()
                    await loop.run_in_executor(None, resolver.resolve, sub, "A")
                    encontrados.add(sub)
                except Exception:
                    pass

        tareas = [resolver_uno(p) for p in wordlist[:5000]]
        await asyncio.gather(*tareas, return_exceptions=True)
        return encontrados

    async def _resolver_batch(self, subdominios: list[str] | set[str]) -> list[dict]:
        """resuelve un batch de subdominios"""
        resultados = []
        semaforo = asyncio.Semaphore(30)

        async def resolver_uno(sub: str):
            async with semaforo:
                try:
                    resolver = dns.resolver.Resolver()
                    resolver.timeout = 5
                    resolver.lifetime = 5
                    loop = asyncio.get_event_loop()
                    resp = await loop.run_in_executor(None, resolver.resolve, sub, "A")
                    ips = [str(r) for r in resp]
                    resultados.append({"subdominio": sub, "ips": ips, "activo": True})
                except Exception:
                    resultados.append({"subdominio": sub, "ips": [], "activo": False})

        tareas = [resolver_uno(s) for s in subdominios]
        await asyncio.gather(*tareas, return_exceptions=True)
        return resultados

    def _generar_permutaciones(self, dominio: str) -> list[str]:
        """genera permutaciones comunes de subdominios"""
        prefijos = [
            "dev", "staging", "stage", "test", "testing", "qa", "uat",
            "api", "api-v1", "api-v2", "api2", "api3",
            "admin", "administrator", "panel", "dashboard", "portal",
            "mail", "email", "smtp", "imap", "pop3", "webmail", "mx",
            "vpn", "remote", "gateway", "proxy",
            "ftp", "sftp", "files", "upload", "cdn", "media", "assets", "static",
            "db", "database", "mysql", "postgres", "redis", "mongo", "elastic",
            "git", "gitlab", "jenkins", "ci", "cd", "deploy",
            "www", "www2", "www3", "web", "app", "m", "mobile",
            "blog", "shop", "store", "pay", "payment", "checkout",
            "internal", "intranet", "corp", "secure",
            "ns1", "ns2", "ns3", "dns", "dns1", "dns2",
            "backup", "bak", "old", "new", "beta", "alpha",
            "monitor", "status", "health", "metrics", "grafana", "prometheus",
            "auth", "oauth", "sso", "login", "accounts",
            "docs", "wiki", "help", "support", "kb",
            "sandbox", "demo", "preview", "canary",
        ]
        return [f"{p}.{dominio}" for p in prefijos]

    def _wordlist_default(self) -> list[str]:
        """wordlist basica para brute force"""
        return [
            "www", "mail", "ftp", "localhost", "webmail", "smtp", "pop", "ns1", "ns2",
            "dns", "dns1", "dns2", "mx", "mx1", "mx2", "vpn", "api", "dev", "staging",
            "test", "admin", "portal", "blog", "shop", "cdn", "app", "mobile", "m",
            "secure", "login", "gateway", "proxy", "git", "gitlab", "jenkins", "ci",
            "db", "database", "redis", "elastic", "kibana", "grafana", "prometheus",
            "monitor", "status", "docs", "wiki", "help", "support", "beta", "alpha",
            "demo", "sandbox", "internal", "intranet", "corp", "backup", "old", "new",
            "web", "web1", "web2", "web3", "app1", "app2", "api2", "api3",
            "assets", "static", "media", "upload", "files", "images", "img",
            "sso", "auth", "oauth", "accounts", "billing", "pay", "payment",
            "crm", "erp", "hr", "sales", "marketing",
        ]
