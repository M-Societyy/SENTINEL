# sentinel - inteligencia de dominios
# c1q_ (M-Society team)

import asyncio
import re
from typing import Optional
from datetime import datetime

import dns.resolver
import httpx
from bs4 import BeautifulSoup
import structlog

from config import config
from modules.base import ModuloBase
from schemas.modulos import ResultadoEnriquecimiento
from utils.user_agent_rotator import obtener_headers_completos, obtener_headers_api

log = structlog.get_logger()


class DomainIntel(ModuloBase):
    nombre = "domain_intel"
    categoria = "network"
    descripcion = "inteligencia completa de dominios: whois, dns, tecnologias, screenshots"

    async def ejecutar(self, objetivo: str, parametros: dict = None) -> ResultadoEnriquecimiento:
        dominio = objetivo.strip().lower().replace("http://", "").replace("https://", "").split("/")[0]

        entidades = []
        relaciones = []
        resultados = {"dominio": dominio}

        tareas = [
            self._consultar_whois(dominio),
            self._enum_dns_completo(dominio),
            self._detectar_tecnologias(dominio),
            self._scrape_web(dominio),
            self._buscar_emails_sitio(dominio),
        ]

        if config.securitytrails_api_key:
            tareas.append(self._securitytrails_info(dominio))
        if config.virustotal_api_key:
            tareas.append(self._virustotal_dominio(dominio))

        resultados_tareas = await asyncio.gather(*tareas, return_exceptions=True)

        idx = 0

        # whois
        if not isinstance(resultados_tareas[idx], Exception):
            whois_data = resultados_tareas[idx]
            if whois_data:
                resultados["whois"] = whois_data
                if whois_data.get("registrante"):
                    entidades.append({
                        "tipo": "person",
                        "valor": whois_data["registrante"],
                        "datos": {"fuente": "whois", "dominio": dominio},
                        "confianza": 0.6,
                    })
                    relaciones.append({
                        "tipo_relacion": "registered_by",
                        "origen_valor": dominio, "origen_tipo": "domain",
                        "destino_valor": whois_data["registrante"], "destino_tipo": "person",
                        "confianza": 0.7,
                    })
                if whois_data.get("organizacion"):
                    entidades.append({
                        "tipo": "organization",
                        "valor": whois_data["organizacion"],
                        "datos": {"fuente": "whois"},
                        "confianza": 0.7,
                    })
                    relaciones.append({
                        "tipo_relacion": "registered_by",
                        "origen_valor": dominio, "origen_tipo": "domain",
                        "destino_valor": whois_data["organizacion"], "destino_tipo": "organization",
                        "confianza": 0.7,
                    })
                if whois_data.get("email_registrante"):
                    entidades.append({
                        "tipo": "email",
                        "valor": whois_data["email_registrante"],
                        "datos": {"fuente": "whois"},
                        "confianza": 0.8,
                    })
                    relaciones.append({
                        "tipo_relacion": "registered_by",
                        "origen_valor": dominio, "origen_tipo": "domain",
                        "destino_valor": whois_data["email_registrante"], "destino_tipo": "email",
                        "confianza": 0.8,
                    })
        idx += 1

        # dns
        if not isinstance(resultados_tareas[idx], Exception):
            dns_data = resultados_tareas[idx]
            if dns_data:
                resultados["dns"] = dns_data
                for ip in dns_data.get("registros_a", []):
                    entidades.append({
                        "tipo": "ip", "valor": ip,
                        "datos": {"fuente": "dns_a", "dominio": dominio},
                        "confianza": 0.95,
                    })
                    relaciones.append({
                        "tipo_relacion": "resolves_to",
                        "origen_valor": dominio, "origen_tipo": "domain",
                        "destino_valor": ip, "destino_tipo": "ip",
                        "confianza": 0.95,
                    })
                for mx in dns_data.get("registros_mx", []):
                    entidades.append({
                        "tipo": "domain", "valor": mx.get("servidor", ""),
                        "datos": {"fuente": "dns_mx", "prioridad": mx.get("prioridad")},
                        "confianza": 0.9,
                    })
                for ns in dns_data.get("registros_ns", []):
                    entidades.append({
                        "tipo": "domain", "valor": ns,
                        "datos": {"fuente": "dns_ns"},
                        "confianza": 0.9,
                    })
        idx += 1

        # tecnologias
        if not isinstance(resultados_tareas[idx], Exception):
            tech = resultados_tareas[idx]
            if tech:
                resultados["tecnologias"] = tech
        idx += 1

        # scrape web
        if not isinstance(resultados_tareas[idx], Exception):
            web = resultados_tareas[idx]
            if web:
                resultados["web"] = web
        idx += 1

        # emails del sitio
        if not isinstance(resultados_tareas[idx], Exception):
            emails = resultados_tareas[idx]
            if emails:
                resultados["emails_encontrados"] = emails
                for email in emails:
                    entidades.append({
                        "tipo": "email", "valor": email,
                        "datos": {"fuente": "web_scraping", "dominio": dominio},
                        "confianza": 0.7,
                    })
                    relaciones.append({
                        "tipo_relacion": "associated_with",
                        "origen_valor": dominio, "origen_tipo": "domain",
                        "destino_valor": email, "destino_tipo": "email",
                        "confianza": 0.7,
                    })
        idx += 1

        # securitytrails
        if config.securitytrails_api_key and idx < len(resultados_tareas):
            if not isinstance(resultados_tareas[idx], Exception):
                st = resultados_tareas[idx]
                if st:
                    resultados["securitytrails"] = st
            idx += 1

        # virustotal
        if config.virustotal_api_key and idx < len(resultados_tareas):
            if not isinstance(resultados_tareas[idx], Exception):
                vt = resultados_tareas[idx]
                if vt:
                    resultados["virustotal"] = vt

        self._entidades_encontradas = len(entidades)
        self._relaciones_creadas = len(relaciones)

        return ResultadoEnriquecimiento(
            fuente=self.nombre, tipo="domain",
            datos=resultados,
            confianza=0.8,
            entidades_nuevas=entidades,
            relaciones_nuevas=relaciones,
        )

    async def _consultar_whois(self, dominio: str) -> Optional[dict]:
        """consulta whois del dominio"""
        try:
            import whois
            loop = asyncio.get_event_loop()
            w = await loop.run_in_executor(None, whois.whois, dominio)

            resultado = {
                "registrador": w.registrar if hasattr(w, "registrar") else None,
                "servidor_whois": w.whois_server if hasattr(w, "whois_server") else None,
                "fecha_creacion": str(w.creation_date) if hasattr(w, "creation_date") and w.creation_date else None,
                "fecha_expiracion": str(w.expiration_date) if hasattr(w, "expiration_date") and w.expiration_date else None,
                "fecha_actualizacion": str(w.updated_date) if hasattr(w, "updated_date") and w.updated_date else None,
                "nameservers": list(w.name_servers) if hasattr(w, "name_servers") and w.name_servers else [],
                "registrante": w.name if hasattr(w, "name") else None,
                "organizacion": w.org if hasattr(w, "org") else None,
                "email_registrante": w.emails[0] if hasattr(w, "emails") and w.emails else None,
                "emails": list(w.emails) if hasattr(w, "emails") and w.emails else [],
                "pais": w.country if hasattr(w, "country") else None,
                "estado": w.state if hasattr(w, "state") else None,
                "ciudad": w.city if hasattr(w, "city") else None,
                "dnssec": w.dnssec if hasattr(w, "dnssec") else None,
                "privacidad_whois": self._detectar_privacidad(w),
            }
            return resultado
        except Exception as e:
            log.warning("error en whois", dominio=dominio, error=str(e))
            return {"error": str(e)}

    def _detectar_privacidad(self, w) -> bool:
        """detecta si el dominio usa servicio de privacidad whois"""
        indicadores = ["privacy", "protect", "proxy", "whoisguard", "domains by proxy", "contactprivacy"]
        texto = str(w).lower()
        return any(i in texto for i in indicadores)

    async def _enum_dns_completo(self, dominio: str) -> dict:
        """enumeracion dns completa de todos los tipos de registro"""
        resolver = dns.resolver.Resolver()
        resolver.timeout = 10
        resolver.lifetime = 10
        resultados = {}

        tipos_registro = {
            "A": "registros_a",
            "AAAA": "registros_aaaa",
            "MX": "registros_mx",
            "NS": "registros_ns",
            "TXT": "registros_txt",
            "SOA": "registros_soa",
            "CNAME": "registros_cname",
            "SRV": "registros_srv",
        }

        for tipo, clave in tipos_registro.items():
            try:
                respuesta = resolver.resolve(dominio, tipo)
                if tipo == "A":
                    resultados[clave] = [str(r) for r in respuesta]
                elif tipo == "AAAA":
                    resultados[clave] = [str(r) for r in respuesta]
                elif tipo == "MX":
                    resultados[clave] = [{"prioridad": r.preference, "servidor": str(r.exchange).rstrip(".")} for r in respuesta]
                elif tipo == "NS":
                    resultados[clave] = [str(r).rstrip(".") for r in respuesta]
                elif tipo == "TXT":
                    resultados[clave] = [str(r) for r in respuesta]
                elif tipo == "SOA":
                    for r in respuesta:
                        resultados[clave] = {
                            "mname": str(r.mname).rstrip("."),
                            "rname": str(r.rname).rstrip("."),
                            "serial": r.serial,
                            "refresh": r.refresh,
                            "retry": r.retry,
                            "expire": r.expire,
                            "minimum": r.minimum,
                        }
                elif tipo == "CNAME":
                    resultados[clave] = [str(r).rstrip(".") for r in respuesta]
                elif tipo == "SRV":
                    resultados[clave] = [{"prioridad": r.priority, "peso": r.weight, "puerto": r.port, "target": str(r.target).rstrip(".")} for r in respuesta]
            except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN, dns.resolver.NoNameservers):
                pass
            except Exception:
                pass

        # verificar registros de seguridad
        resultados["seguridad"] = {}

        # spf
        for txt in resultados.get("registros_txt", []):
            if "v=spf1" in txt:
                resultados["seguridad"]["spf"] = txt

        # dmarc
        try:
            dmarc = resolver.resolve(f"_dmarc.{dominio}", "TXT")
            for r in dmarc:
                texto = str(r)
                if "v=DMARC1" in texto:
                    resultados["seguridad"]["dmarc"] = texto
        except Exception:
            pass

        # dkim (selector comun)
        for selector in ["default", "google", "selector1", "selector2", "k1"]:
            try:
                dkim = resolver.resolve(f"{selector}._domainkey.{dominio}", "TXT")
                for r in dkim:
                    resultados["seguridad"][f"dkim_{selector}"] = str(r)
                break
            except Exception:
                pass

        return resultados

    async def _detectar_tecnologias(self, dominio: str) -> Optional[dict]:
        """detecta tecnologias web usadas por el dominio"""
        url = f"https://{dominio}"
        resp = await self.request_con_rate_limit(url, servicio="default")
        if not resp:
            url = f"http://{dominio}"
            resp = await self.request_con_rate_limit(url, servicio="default")

        if not resp or resp.status_code >= 400:
            return None

        tecnologias = []
        headers = dict(resp.headers)

        # detectar por headers
        server = headers.get("server", "").lower()
        if "nginx" in server:
            tecnologias.append({"nombre": "Nginx", "categoria": "web_server", "version": server})
        elif "apache" in server:
            tecnologias.append({"nombre": "Apache", "categoria": "web_server", "version": server})
        elif "cloudflare" in server:
            tecnologias.append({"nombre": "Cloudflare", "categoria": "cdn"})

        powered_by = headers.get("x-powered-by", "").lower()
        if "php" in powered_by:
            tecnologias.append({"nombre": "PHP", "categoria": "language", "version": powered_by})
        elif "express" in powered_by:
            tecnologias.append({"nombre": "Express.js", "categoria": "framework"})
        elif "asp.net" in powered_by:
            tecnologias.append({"nombre": "ASP.NET", "categoria": "framework"})

        if "x-drupal" in headers:
            tecnologias.append({"nombre": "Drupal", "categoria": "cms"})
        if "x-shopify" in headers or "shopify" in headers.get("x-shopid", ""):
            tecnologias.append({"nombre": "Shopify", "categoria": "ecommerce"})

        # detectar por body
        body = resp.text.lower()
        detecciones_body = [
            ("wp-content", "WordPress", "cms"),
            ("wp-includes", "WordPress", "cms"),
            ("joomla", "Joomla", "cms"),
            ("drupal", "Drupal", "cms"),
            ("react", "React", "frontend"),
            ("vue.js", "Vue.js", "frontend"),
            ("angular", "Angular", "frontend"),
            ("next.js", "Next.js", "framework"),
            ("nuxt", "Nuxt.js", "framework"),
            ("gatsby", "Gatsby", "framework"),
            ("bootstrap", "Bootstrap", "css"),
            ("tailwind", "Tailwind CSS", "css"),
            ("jquery", "jQuery", "javascript"),
            ("google-analytics", "Google Analytics", "analytics"),
            ("gtag", "Google Tag Manager", "analytics"),
            ("cloudflare", "Cloudflare", "cdn"),
            ("recaptcha", "reCAPTCHA", "security"),
            ("stripe", "Stripe", "payment"),
            ("shopify", "Shopify", "ecommerce"),
            ("woocommerce", "WooCommerce", "ecommerce"),
            ("magento", "Magento", "ecommerce"),
            ("laravel", "Laravel", "framework"),
            ("django", "Django", "framework"),
            ("flask", "Flask", "framework"),
            ("rails", "Ruby on Rails", "framework"),
        ]

        for patron, nombre, cat in detecciones_body:
            if patron in body and not any(t["nombre"] == nombre for t in tecnologias):
                tecnologias.append({"nombre": nombre, "categoria": cat})

        return {
            "tecnologias": tecnologias,
            "total": len(tecnologias),
            "headers_servidor": dict(headers),
        }

    async def _scrape_web(self, dominio: str) -> Optional[dict]:
        """scraping basico del sitio web"""
        url = f"https://{dominio}"
        resp = await self.request_con_rate_limit(url, servicio="default")
        if not resp:
            url = f"http://{dominio}"
            resp = await self.request_con_rate_limit(url, servicio="default")
        if not resp:
            return None

        soup = BeautifulSoup(resp.text, "html.parser")

        titulo = soup.find("title")
        titulo_texto = titulo.get_text().strip() if titulo else ""

        meta_desc = soup.find("meta", attrs={"name": "description"})
        descripcion = meta_desc.get("content", "") if meta_desc else ""

        meta_keys = soup.find("meta", attrs={"name": "keywords"})
        keywords = meta_keys.get("content", "") if meta_keys else ""

        # links externos
        links_externos = set()
        for link in soup.find_all("a", href=True):
            href = link["href"]
            if href.startswith("http") and dominio not in href:
                links_externos.add(href)

        # formularios
        formularios = []
        for form in soup.find_all("form"):
            formularios.append({
                "action": form.get("action", ""),
                "method": form.get("method", "GET"),
                "campos": [inp.get("name", "") for inp in form.find_all("input") if inp.get("name")],
            })

        # comentarios html
        import re as re_mod
        comentarios = re_mod.findall(r'<!--(.*?)-->', resp.text, re_mod.DOTALL)
        comentarios_limpios = [c.strip()[:200] for c in comentarios if len(c.strip()) > 5]

        return {
            "titulo": titulo_texto,
            "descripcion": descripcion,
            "keywords": keywords,
            "links_externos": list(links_externos)[:50],
            "formularios": formularios[:10],
            "comentarios_html": comentarios_limpios[:20],
            "status_code": resp.status_code,
            "url_final": str(resp.url),
        }

    async def _buscar_emails_sitio(self, dominio: str) -> list[str]:
        """extrae emails del sitio web"""
        emails = set()
        urls_a_visitar = [f"https://{dominio}", f"https://{dominio}/contact", f"https://{dominio}/about"]

        for url in urls_a_visitar:
            resp = await self.request_con_rate_limit(url, servicio="default")
            if resp and resp.status_code == 200:
                patron = r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}'
                encontrados = re.findall(patron, resp.text)
                for e in encontrados:
                    e = e.lower()
                    excluir = ["example.com", "email.com", "domain.com", "sentry.io", "w3.org", "schema.org"]
                    if not any(x in e for x in excluir):
                        emails.add(e)

        return list(emails)[:20]

    async def _securitytrails_info(self, dominio: str) -> Optional[dict]:
        """consulta securitytrails para info historica"""
        url = f"https://api.securitytrails.com/v1/domain/{dominio}"
        headers = {"APIKEY": config.securitytrails_api_key}

        resp = await self.request_con_rate_limit(url, servicio="securitytrails", headers=headers)
        if resp and resp.status_code == 200:
            return resp.json()
        return None

    async def _virustotal_dominio(self, dominio: str) -> Optional[dict]:
        """consulta virustotal para reputacion del dominio"""
        url = f"https://www.virustotal.com/api/v3/domains/{dominio}"
        headers = {"x-apikey": config.virustotal_api_key}

        resp = await self.request_con_rate_limit(url, servicio="virustotal", headers=headers)
        if resp and resp.status_code == 200:
            datos = resp.json().get("data", {}).get("attributes", {})
            return {
                "reputacion": datos.get("reputation"),
                "categorias": datos.get("categories", {}),
                "votos": datos.get("total_votes", {}),
                "ultimo_analisis": datos.get("last_analysis_stats", {}),
                "registrador": datos.get("registrar"),
                "fecha_creacion": datos.get("creation_date"),
            }
        return None
