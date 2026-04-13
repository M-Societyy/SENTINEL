# sentinel - inteligencia de direcciones ip
# c1q_ (M-Society team)

import asyncio
from typing import Optional

import dns.resolver
import dns.reversename
import httpx
import structlog

from config import config
from modules.base import ModuloBase
from schemas.modulos import ResultadoEnriquecimiento

log = structlog.get_logger()


class IpIntel(ModuloBase):
    nombre = "ip_intel"
    categoria = "network"
    descripcion = "inteligencia de ip: geolocalizacion, asn, reputacion, servicios, cloud detection"
    requiere_api_key = True

    async def ejecutar(self, objetivo: str, parametros: dict = None) -> ResultadoEnriquecimiento:
        ip = objetivo.strip()

        entidades = []
        relaciones = []
        resultados = {"ip": ip}

        tareas = [
            self._ptr_lookup(ip),
            self._geolocalizacion(ip),
            self._asn_info(ip),
            self._reputacion(ip),
            self._detectar_cloud(ip),
            self._detectar_tor(ip),
            self._detectar_vpn_proxy(ip),
        ]

        if config.shodan_api_key:
            tareas.append(self._shodan(ip))
        if config.virustotal_api_key:
            tareas.append(self._virustotal_ip(ip))
        if config.abuseipdb_api_key:
            tareas.append(self._abuseipdb(ip))

        resultados_tareas = await asyncio.gather(*tareas, return_exceptions=True)
        idx = 0

        # ptr
        if not isinstance(resultados_tareas[idx], Exception):
            ptr = resultados_tareas[idx]
            if ptr:
                resultados["ptr"] = ptr
                if ptr.get("hostname"):
                    entidades.append({
                        "tipo": "domain", "valor": ptr["hostname"],
                        "datos": {"fuente": "ptr_lookup", "ip": ip},
                        "confianza": 0.85,
                    })
                    relaciones.append({
                        "tipo_relacion": "resolves_to",
                        "origen_valor": ptr["hostname"], "origen_tipo": "domain",
                        "destino_valor": ip, "destino_tipo": "ip",
                        "confianza": 0.85,
                    })
        idx += 1

        # geo
        if not isinstance(resultados_tareas[idx], Exception):
            geo = resultados_tareas[idx]
            if geo:
                resultados["geolocalizacion"] = geo
                ubicacion = f"{geo.get('ciudad', '')}, {geo.get('region', '')}, {geo.get('pais', '')}".strip(", ")
                if ubicacion:
                    entidades.append({
                        "tipo": "location", "valor": ubicacion,
                        "datos": {
                            "lat": geo.get("latitud"), "lon": geo.get("longitud"),
                            "pais_codigo": geo.get("pais_codigo"),
                            "fuente": "geoip",
                        },
                        "confianza": 0.7,
                    })
                    relaciones.append({
                        "tipo_relacion": "located_at",
                        "origen_valor": ip, "origen_tipo": "ip",
                        "destino_valor": ubicacion, "destino_tipo": "location",
                        "confianza": 0.7,
                    })
        idx += 1

        # asn
        if not isinstance(resultados_tareas[idx], Exception):
            asn = resultados_tareas[idx]
            if asn:
                resultados["asn"] = asn
                if asn.get("organizacion"):
                    entidades.append({
                        "tipo": "organization", "valor": asn["organizacion"],
                        "datos": {
                            "asn": asn.get("asn"), "cidr": asn.get("cidr"),
                            "rir": asn.get("rir"), "fuente": "bgp",
                        },
                        "confianza": 0.8,
                    })
                    relaciones.append({
                        "tipo_relacion": "hosted_on",
                        "origen_valor": ip, "origen_tipo": "ip",
                        "destino_valor": asn["organizacion"], "destino_tipo": "organization",
                        "confianza": 0.8,
                    })
        idx += 1

        # reputacion
        if not isinstance(resultados_tareas[idx], Exception):
            rep = resultados_tareas[idx]
            if rep:
                resultados["reputacion"] = rep
        idx += 1

        # cloud
        if not isinstance(resultados_tareas[idx], Exception):
            cloud = resultados_tareas[idx]
            if cloud:
                resultados["cloud"] = cloud
        idx += 1

        # tor
        if not isinstance(resultados_tareas[idx], Exception):
            tor = resultados_tareas[idx]
            if tor:
                resultados["tor"] = tor
        idx += 1

        # vpn/proxy
        if not isinstance(resultados_tareas[idx], Exception):
            vpn = resultados_tareas[idx]
            if vpn:
                resultados["vpn_proxy"] = vpn
        idx += 1

        # shodan
        if config.shodan_api_key and idx < len(resultados_tareas):
            if not isinstance(resultados_tareas[idx], Exception):
                shodan = resultados_tareas[idx]
                if shodan:
                    resultados["shodan"] = shodan
                    for puerto in shodan.get("puertos", []):
                        if puerto.get("cve"):
                            for cve in puerto["cve"][:5]:
                                entidades.append({
                                    "tipo": "hash", "valor": cve,
                                    "datos": {"tipo": "cve", "ip": ip, "puerto": puerto.get("puerto")},
                                    "confianza": 0.8,
                                })
            idx += 1

        # virustotal
        if config.virustotal_api_key and idx < len(resultados_tareas):
            if not isinstance(resultados_tareas[idx], Exception):
                vt = resultados_tareas[idx]
                if vt:
                    resultados["virustotal"] = vt
            idx += 1

        # abuseipdb
        if config.abuseipdb_api_key and idx < len(resultados_tareas):
            if not isinstance(resultados_tareas[idx], Exception):
                abuse = resultados_tareas[idx]
                if abuse:
                    resultados["abuseipdb"] = abuse

        self._entidades_encontradas = len(entidades)
        self._relaciones_creadas = len(relaciones)

        return ResultadoEnriquecimiento(
            fuente=self.nombre, tipo="ip",
            datos=resultados,
            confianza=0.8,
            entidades_nuevas=entidades,
            relaciones_nuevas=relaciones,
        )

    async def _ptr_lookup(self, ip: str) -> Optional[dict]:
        """reverse dns lookup"""
        try:
            addr = dns.reversename.from_address(ip)
            resolver = dns.resolver.Resolver()
            resolver.timeout = 10
            loop = asyncio.get_event_loop()
            resp = await loop.run_in_executor(None, resolver.resolve, addr, "PTR")
            hostname = str(list(resp)[0]).rstrip(".")
            return {"hostname": hostname, "ip": ip}
        except Exception:
            return None

    async def _geolocalizacion(self, ip: str) -> Optional[dict]:
        """geolocalizacion con multiples apis y consenso"""
        resultados = []

        # ipinfo
        if config.ipinfo_token:
            resp = await self.request_con_rate_limit(
                f"https://ipinfo.io/{ip}/json",
                servicio="default",
                params={"token": config.ipinfo_token},
            )
            if resp and resp.status_code == 200:
                datos = resp.json()
                loc = datos.get("loc", "0,0").split(",")
                resultados.append({
                    "fuente": "ipinfo",
                    "pais": datos.get("country"),
                    "region": datos.get("region"),
                    "ciudad": datos.get("city"),
                    "latitud": float(loc[0]) if len(loc) == 2 else None,
                    "longitud": float(loc[1]) if len(loc) == 2 else None,
                    "org": datos.get("org"),
                    "timezone": datos.get("timezone"),
                })

        # ip-api.com 
        resp = await self.request_con_rate_limit(
            f"http://ip-api.com/json/{ip}",
            servicio="default",
            params={"fields": "status,message,country,countryCode,region,regionName,city,zip,lat,lon,timezone,isp,org,as,asname,reverse,mobile,proxy,hosting,query"},
        )
        if resp and resp.status_code == 200:
            datos = resp.json()
            if datos.get("status") == "success":
                resultados.append({
                    "fuente": "ip-api",
                    "pais": datos.get("country"),
                    "pais_codigo": datos.get("countryCode"),
                    "region": datos.get("regionName"),
                    "ciudad": datos.get("city"),
                    "latitud": datos.get("lat"),
                    "longitud": datos.get("lon"),
                    "isp": datos.get("isp"),
                    "org": datos.get("org"),
                    "as_number": datos.get("as"),
                    "timezone": datos.get("timezone"),
                    "es_proxy": datos.get("proxy"),
                    "es_hosting": datos.get("hosting"),
                    "es_movil": datos.get("mobile"),
                })

        if not resultados:
            return None

        # usar el primer resultado como base, enriquecer con los demas
        base = resultados[0]
        if len(resultados) > 1:
            for extra in resultados[1:]:
                for k, v in extra.items():
                    if k not in base or base[k] is None:
                        base[k] = v

        return base

    async def _asn_info(self, ip: str) -> Optional[dict]:
        """info de asn via bgpview"""
        resp = await self.request_con_rate_limit(
            f"https://api.bgpview.io/ip/{ip}",
            servicio="default",
        )
        if resp and resp.status_code == 200:
            datos = resp.json().get("data", {})
            prefijos = datos.get("prefixes", [])
            if prefijos:
                prefix = prefijos[0]
                asn_data = prefix.get("asn", {})
                return {
                    "asn": asn_data.get("asn"),
                    "organizacion": asn_data.get("name"),
                    "descripcion": asn_data.get("description"),
                    "cidr": prefix.get("prefix"),
                    "pais_codigo": asn_data.get("country_code"),
                    "rir": prefix.get("rir_allocation", {}).get("rir_name"),
                }
        return None

    async def _reputacion(self, ip: str) -> dict:
        """verifica reputacion en listas negras publicas"""
        listas = []

        # spamhaus
        try:
            octetos = ip.split(".")
            query = f"{octetos[3]}.{octetos[2]}.{octetos[1]}.{octetos[0]}.zen.spamhaus.org"
            resolver = dns.resolver.Resolver()
            resolver.timeout = 5
            loop = asyncio.get_event_loop()
            await loop.run_in_executor(None, resolver.resolve, query, "A")
            listas.append("spamhaus")
        except Exception:
            pass

        # sorbs
        try:
            octetos = ip.split(".")
            query = f"{octetos[3]}.{octetos[2]}.{octetos[1]}.{octetos[0]}.dnsbl.sorbs.net"
            resolver = dns.resolver.Resolver()
            resolver.timeout = 5
            loop = asyncio.get_event_loop()
            await loop.run_in_executor(None, resolver.resolve, query, "A")
            listas.append("sorbs")
        except Exception:
            pass

        return {
            "en_lista_negra": len(listas) > 0,
            "listas": listas,
            "total_listas_verificadas": 2,
        }

    async def _detectar_cloud(self, ip: str) -> dict:
        """detecta si la ip pertenece a un proveedor cloud"""
        cloud_ranges = {
            "aws": ["amazonaws.com", "aws.amazon.com"],
            "gcp": ["googleusercontent.com", "google.com", "1e100.net"],
            "azure": ["azure.com", "microsoft.com", "windowsazure.com"],
            "cloudflare": ["cloudflare.com", "cloudflare.net"],
            "digitalocean": ["digitalocean.com"],
            "linode": ["linode.com"],
            "vultr": ["vultr.com"],
            "hetzner": ["hetzner.com", "hetzner.de"],
            "ovh": ["ovh.net", "ovh.com"],
            "fastly": ["fastly.net"],
        }

        # revisar ptr para detectar proveedor
        ptr = await self._ptr_lookup(ip)
        proveedor = None
        if ptr and ptr.get("hostname"):
            hostname = ptr["hostname"].lower()
            for cloud, dominios in cloud_ranges.items():
                if any(d in hostname for d in dominios):
                    proveedor = cloud
                    break

        # revisar asn
        if not proveedor:
            asn = await self._asn_info(ip)
            if asn:
                org = (asn.get("organizacion") or "").lower()
                asn_providers = {
                    "amazon": "aws", "google": "gcp", "microsoft": "azure",
                    "cloudflare": "cloudflare", "digitalocean": "digitalocean",
                    "linode": "linode", "vultr": "vultr", "hetzner": "hetzner",
                    "ovh": "ovh", "fastly": "fastly",
                }
                for nombre, cloud in asn_providers.items():
                    if nombre in org:
                        proveedor = cloud
                        break

        return {
            "es_cloud": proveedor is not None,
            "proveedor": proveedor,
        }

    async def _detectar_tor(self, ip: str) -> dict:
        """detecta si la ip es un nodo tor de salida"""
        try:
            resp = await self.request_con_rate_limit(
                "https://check.torproject.org/torbulkexitlist",
                servicio="default",
            )
            if resp and resp.status_code == 200:
                nodos = set(resp.text.strip().split("\n"))
                return {"es_tor_exit": ip in nodos}
        except Exception:
            pass
        return {"es_tor_exit": False}

    async def _detectar_vpn_proxy(self, ip: str) -> dict:
        """detecta si la ip es vpn/proxy/datacenter"""
        resultado = {"es_vpn": False, "es_proxy": False, "es_datacenter": False}

        resp = await self.request_con_rate_limit(
            f"http://ip-api.com/json/{ip}",
            servicio="default",
            params={"fields": "proxy,hosting"},
        )
        if resp and resp.status_code == 200:
            datos = resp.json()
            resultado["es_proxy"] = datos.get("proxy", False)
            resultado["es_datacenter"] = datos.get("hosting", False)

        return resultado

    async def _shodan(self, ip: str) -> Optional[dict]:
        """consulta shodan para puertos, banners y cves"""
        url = f"https://api.shodan.io/shodan/host/{ip}"
        params = {"key": config.shodan_api_key}

        resp = await self.request_con_rate_limit(url, servicio="shodan", params=params)
        if resp and resp.status_code == 200:
            datos = resp.json()
            puertos = []
            for item in datos.get("data", []):
                puerto_info = {
                    "puerto": item.get("port"),
                    "protocolo": item.get("transport", "tcp"),
                    "producto": item.get("product"),
                    "version": item.get("version"),
                    "banner": (item.get("data", ""))[:500],
                    "cve": item.get("vulns", []),
                }
                puertos.append(puerto_info)

            return {
                "puertos": puertos,
                "total_puertos": len(puertos),
                "os": datos.get("os"),
                "hostnames": datos.get("hostnames", []),
                "domains": datos.get("domains", []),
                "isp": datos.get("isp"),
                "org": datos.get("org"),
                "ultima_actualizacion": datos.get("last_update"),
            }
        return None

    async def _virustotal_ip(self, ip: str) -> Optional[dict]:
        """consulta virustotal para reputacion de ip"""
        url = f"https://www.virustotal.com/api/v3/ip_addresses/{ip}"
        headers = {"x-apikey": config.virustotal_api_key}

        resp = await self.request_con_rate_limit(url, servicio="virustotal", headers=headers)
        if resp and resp.status_code == 200:
            attrs = resp.json().get("data", {}).get("attributes", {})
            return {
                "reputacion": attrs.get("reputation"),
                "votos": attrs.get("total_votes", {}),
                "ultimo_analisis": attrs.get("last_analysis_stats", {}),
                "asn": attrs.get("asn"),
                "as_owner": attrs.get("as_owner"),
                "pais": attrs.get("country"),
            }
        return None

    async def _abuseipdb(self, ip: str) -> Optional[dict]:
        """consulta abuseipdb para reportes de abuso"""
        url = "https://api.abuseipdb.com/api/v2/check"
        headers = {"Key": config.abuseipdb_api_key, "Accept": "application/json"}
        params = {"ipAddress": ip, "maxAgeInDays": 90, "verbose": ""}

        resp = await self.request_con_rate_limit(url, servicio="abuseipdb", headers=headers, params=params)
        if resp and resp.status_code == 200:
            datos = resp.json().get("data", {})
            return {
                "es_publico": datos.get("isPublic"),
                "version_ip": datos.get("ipVersion"),
                "es_whitelisted": datos.get("isWhitelisted"),
                "score_abuso": datos.get("abuseConfidenceScore"),
                "pais": datos.get("countryCode"),
                "isp": datos.get("isp"),
                "dominio": datos.get("domain"),
                "total_reportes": datos.get("totalReports"),
                "ultimo_reporte": datos.get("lastReportedAt"),
                "uso": datos.get("usageType"),
            }
        return None
