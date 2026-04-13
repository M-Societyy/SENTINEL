# sentinel - inteligencia de certificados ssl/tls
# m-society & c1q_

import asyncio
import ssl
import socket
import hashlib
from typing import Optional
from datetime import datetime

import httpx
import structlog

from modules.base import ModuloBase
from schemas.modulos import ResultadoEnriquecimiento

log = structlog.get_logger()


class SslIntel(ModuloBase):
    nombre = "ssl_intel"
    categoria = "network"
    descripcion = "analisis de certificados tls/ssl, fingerprinting, ct logs"

    async def ejecutar(self, objetivo: str, parametros: dict = None) -> ResultadoEnriquecimiento:
        host = objetivo.strip().lower()
        puerto = int((parametros or {}).get("puerto", 443))

        entidades = []
        relaciones = []
        resultados = {"host": host, "puerto": puerto}

        tareas = [
            self._extraer_certificado(host, puerto),
            self._buscar_ct_logs(host),
            self._evaluar_configuracion_tls(host, puerto),
        ]

        resultados_tareas = await asyncio.gather(*tareas, return_exceptions=True)

        # certificado
        if not isinstance(resultados_tareas[0], Exception):
            cert = resultados_tareas[0]
            if cert:
                resultados["certificado"] = cert
                # sans como dominios asociados
                for san in cert.get("sans", []):
                    if san != host and "*" not in san:
                        entidades.append({
                            "tipo": "domain", "valor": san,
                            "datos": {"fuente": "ssl_san", "certificado_de": host},
                            "confianza": 0.9,
                        })
                        relaciones.append({
                            "tipo_relacion": "associated_with",
                            "origen_valor": host, "origen_tipo": "domain",
                            "destino_valor": san, "destino_tipo": "domain",
                            "confianza": 0.85,
                        })
                # emisor como organizacion
                if cert.get("emisor_org"):
                    entidades.append({
                        "tipo": "organization", "valor": cert["emisor_org"],
                        "datos": {"fuente": "ssl_issuer", "tipo": "certificate_authority"},
                        "confianza": 0.95,
                    })

        # ct logs
        if not isinstance(resultados_tareas[1], Exception):
            ct = resultados_tareas[1]
            if ct:
                resultados["ct_logs"] = ct
                for dominio_ct in ct.get("dominios_asociados", []):
                    if dominio_ct != host:
                        entidades.append({
                            "tipo": "domain", "valor": dominio_ct,
                            "datos": {"fuente": "ct_logs"},
                            "confianza": 0.8,
                        })

        # configuracion tls
        if not isinstance(resultados_tareas[2], Exception):
            tls_config = resultados_tareas[2]
            if tls_config:
                resultados["configuracion_tls"] = tls_config

        self._entidades_encontradas = len(entidades)
        self._relaciones_creadas = len(relaciones)

        return ResultadoEnriquecimiento(
            fuente=self.nombre, tipo="domain",
            datos=resultados,
            confianza=0.85,
            entidades_nuevas=entidades,
            relaciones_nuevas=relaciones,
        )

    async def _extraer_certificado(self, host: str, puerto: int = 443) -> Optional[dict]:
        """extrae info completa del certificado tls"""
        try:
            loop = asyncio.get_event_loop()
            resultado = await loop.run_in_executor(None, self._get_cert_sync, host, puerto)
            return resultado
        except Exception as e:
            log.warning("error extrayendo certificado", host=host, error=str(e))
            return None

    def _get_cert_sync(self, host: str, puerto: int) -> Optional[dict]:
        """extraccion sincrona del certificado"""
        try:
            contexto = ssl.create_default_context()
            contexto.check_hostname = False
            contexto.verify_mode = ssl.CERT_NONE

            with socket.create_connection((host, puerto), timeout=10) as sock:
                with contexto.wrap_socket(sock, server_hostname=host) as ssock:
                    cert_bin = ssock.getpeercert(binary_form=True)
                    cert = ssock.getpeercert()
                    version_tls = ssock.version()
                    cipher = ssock.cipher()

                    # fingerprints
                    sha256 = hashlib.sha256(cert_bin).hexdigest()
                    sha1 = hashlib.sha1(cert_bin).hexdigest()
                    md5 = hashlib.md5(cert_bin).hexdigest()

                    # subject
                    subject = {}
                    for campo in cert.get("subject", ()):
                        for k, v in campo:
                            subject[k] = v

                    # issuer
                    issuer = {}
                    for campo in cert.get("issuer", ()):
                        for k, v in campo:
                            issuer[k] = v

                    # sans
                    sans = []
                    for tipo, valor in cert.get("subjectAltName", ()):
                        if tipo == "DNS":
                            sans.append(valor)

                    # validez
                    not_before = cert.get("notBefore", "")
                    not_after = cert.get("notAfter", "")

                    return {
                        "cn": subject.get("commonName"),
                        "organizacion": subject.get("organizationName"),
                        "sans": sans,
                        "emisor_cn": issuer.get("commonName"),
                        "emisor_org": issuer.get("organizationName"),
                        "emisor_pais": issuer.get("countryName"),
                        "valido_desde": not_before,
                        "valido_hasta": not_after,
                        "serial": cert.get("serialNumber"),
                        "version_tls": version_tls,
                        "cipher_suite": cipher[0] if cipher else None,
                        "cipher_bits": cipher[2] if cipher and len(cipher) > 2 else None,
                        "fingerprints": {
                            "sha256": sha256,
                            "sha1": sha1,
                            "md5": md5,
                        },
                        "es_wildcard": any("*" in s for s in sans),
                        "es_ev": "Extended Validation" in issuer.get("organizationName", ""),
                    }
        except Exception as e:
            return {"error": str(e)}

    async def _buscar_ct_logs(self, host: str) -> Optional[dict]:
        """busca dominios asociados en certificate transparency"""
        url = f"https://crt.sh/?q={host}&output=json"
        resp = await self.request_con_rate_limit(url, servicio="default", timeout=30.0)

        if resp and resp.status_code == 200:
            try:
                datos = resp.json()
                dominios = set()
                certificados = []

                for entrada in datos[:100]:
                    nombre = entrada.get("name_value", "")
                    for linea in nombre.split("\n"):
                        linea = linea.strip().lower()
                        if "*" not in linea and linea:
                            dominios.add(linea)

                    certificados.append({
                        "id": entrada.get("id"),
                        "serial": entrada.get("serial_number"),
                        "emisor": entrada.get("issuer_name"),
                        "no_antes": entrada.get("not_before"),
                        "no_despues": entrada.get("not_after"),
                        "dominios": nombre,
                    })

                return {
                    "total_certificados": len(datos),
                    "dominios_asociados": list(dominios)[:100],
                    "certificados_recientes": certificados[:20],
                }
            except Exception as e:
                log.debug("error parseando ct logs", error=str(e))

        return None

    async def _evaluar_configuracion_tls(self, host: str, puerto: int = 443) -> Optional[dict]:
        """evalua la seguridad de la configuracion tls"""
        try:
            loop = asyncio.get_event_loop()
            resultado = await loop.run_in_executor(None, self._eval_tls_sync, host, puerto)
            return resultado
        except Exception as e:
            return {"error": str(e)}

    def _eval_tls_sync(self, host: str, puerto: int) -> dict:
        """evaluacion sincrona de configuracion tls"""
        protocolos_soportados = []
        vulnerabilidades = []

        # verificar tls 1.0
        try:
            ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            ctx.maximum_version = ssl.TLSVersion.TLSv1
            ctx.minimum_version = ssl.TLSVersion.TLSv1
            with socket.create_connection((host, puerto), timeout=5) as sock:
                with ctx.wrap_socket(sock, server_hostname=host) as ssock:
                    protocolos_soportados.append("TLSv1.0")
                    vulnerabilidades.append("tls_1_0_habilitado")
        except Exception:
            pass

        # verificar tls 1.1
        try:
            ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            ctx.maximum_version = ssl.TLSVersion.TLSv1_1
            ctx.minimum_version = ssl.TLSVersion.TLSv1_1
            with socket.create_connection((host, puerto), timeout=5) as sock:
                with ctx.wrap_socket(sock, server_hostname=host) as ssock:
                    protocolos_soportados.append("TLSv1.1")
                    vulnerabilidades.append("tls_1_1_habilitado")
        except Exception:
            pass

        # verificar tls 1.2
        try:
            ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            ctx.maximum_version = ssl.TLSVersion.TLSv1_2
            ctx.minimum_version = ssl.TLSVersion.TLSv1_2
            with socket.create_connection((host, puerto), timeout=5) as sock:
                with ctx.wrap_socket(sock, server_hostname=host) as ssock:
                    protocolos_soportados.append("TLSv1.2")
        except Exception:
            pass

        # verificar tls 1.3
        try:
            ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            ctx.maximum_version = ssl.TLSVersion.TLSv1_3
            ctx.minimum_version = ssl.TLSVersion.TLSv1_3
            with socket.create_connection((host, puerto), timeout=5) as sock:
                with ctx.wrap_socket(sock, server_hostname=host) as ssock:
                    protocolos_soportados.append("TLSv1.3")
        except Exception:
            pass

        # score de seguridad
        score = "A"
        if "TLSv1.0" in protocolos_soportados:
            score = "C"
        elif "TLSv1.1" in protocolos_soportados:
            score = "B"
        elif "TLSv1.3" not in protocolos_soportados:
            score = "B+"

        return {
            "protocolos_soportados": protocolos_soportados,
            "vulnerabilidades": vulnerabilidades,
            "score_seguridad": score,
            "soporta_tls13": "TLSv1.3" in protocolos_soportados,
            "tiene_protocolos_obsoletos": len(vulnerabilidades) > 0,
        }
