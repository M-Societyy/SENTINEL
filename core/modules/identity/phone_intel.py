# sentinel - modulo de inteligencia de numeros telefonicos
# m-society & c1q_

import asyncio
from typing import Optional

import phonenumbers
from phonenumbers import carrier, geocoder, timezone
import httpx
import structlog

from modules.base import ModuloBase
from schemas.modulos import ResultadoEnriquecimiento

log = structlog.get_logger()


class PhoneIntel(ModuloBase):
    nombre = "phone_intel"
    categoria = "identity"
    descripcion = "inteligencia de numeros telefonicos: validacion, carrier, geolocalizacion"

    async def ejecutar(self, objetivo: str, parametros: dict = None) -> ResultadoEnriquecimiento:
        numero_raw = objetivo.strip()
        parametros = parametros or {}
        region_default = parametros.get("region", "US")

        # parsear y validar numero
        info_numero = self._parsear_numero(numero_raw, region_default)
        if not info_numero.get("valido"):
            return ResultadoEnriquecimiento(
                fuente=self.nombre, tipo="phone",
                error=f"numero invalido: {info_numero.get('error', 'formato incorrecto')}",
                confianza=0.0,
            )

        entidades = []
        relaciones = []
        resultados = {"info_basica": info_numero}

        # verificaciones en paralelo
        tareas = [
            self._verificar_whatsapp(info_numero["formato_internacional"]),
            self._buscar_en_pastes(numero_raw),
        ]

        resultados_tareas = await asyncio.gather(*tareas, return_exceptions=True)

        # whatsapp
        if not isinstance(resultados_tareas[0], Exception):
            wa = resultados_tareas[0]
            if wa:
                resultados["whatsapp"] = wa
                if wa.get("activo"):
                    entidades.append({
                        "tipo": "social_profile",
                        "valor": f"whatsapp:{info_numero['formato_internacional']}",
                        "datos": wa,
                        "confianza": 0.7,
                    })
                    relaciones.append({
                        "tipo_relacion": "owns",
                        "origen_valor": info_numero["formato_internacional"],
                        "origen_tipo": "phone",
                        "destino_valor": f"whatsapp:{info_numero['formato_internacional']}",
                        "destino_tipo": "social_profile",
                        "confianza": 0.7,
                    })

        # pastes
        if not isinstance(resultados_tareas[1], Exception):
            pastes = resultados_tareas[1]
            if pastes:
                resultados["pastes"] = pastes

        # entidad de ubicacion si se pudo geolocalizar
        if info_numero.get("ubicacion"):
            entidades.append({
                "tipo": "location",
                "valor": info_numero["ubicacion"],
                "datos": {
                    "pais": info_numero.get("pais_codigo"),
                    "region": info_numero.get("ubicacion"),
                    "fuente": "phonenumbers",
                },
                "confianza": 0.6,
            })
            relaciones.append({
                "tipo_relacion": "located_at",
                "origen_valor": info_numero["formato_internacional"],
                "origen_tipo": "phone",
                "destino_valor": info_numero["ubicacion"],
                "destino_tipo": "location",
                "confianza": 0.6,
            })

        self._entidades_encontradas = len(entidades)
        self._relaciones_creadas = len(relaciones)

        return ResultadoEnriquecimiento(
            fuente=self.nombre,
            tipo="phone",
            datos=resultados,
            confianza=0.6 if info_numero["valido"] else 0.1,
            entidades_nuevas=entidades,
            relaciones_nuevas=relaciones,
        )

    def _parsear_numero(self, numero: str, region: str = "US") -> dict:
        """parsea y extrae toda la info posible del numero"""
        try:
            parsed = phonenumbers.parse(numero, region)

            if not phonenumbers.is_valid_number(parsed):
                return {"valido": False, "error": "numero invalido"}

            nombre_carrier = carrier.name_for_number(parsed, "es") or carrier.name_for_number(parsed, "en")
            ubicacion = geocoder.description_for_number(parsed, "es") or geocoder.description_for_number(parsed, "en")
            zonas_horarias = timezone.time_zones_for_number(parsed)

            tipo_numero = "desconocido"
            tipo_ph = phonenumbers.number_type(parsed)
            tipos_map = {
                phonenumbers.PhoneNumberType.MOBILE: "movil",
                phonenumbers.PhoneNumberType.FIXED_LINE: "fijo",
                phonenumbers.PhoneNumberType.FIXED_LINE_OR_MOBILE: "fijo_o_movil",
                phonenumbers.PhoneNumberType.TOLL_FREE: "gratuito",
                phonenumbers.PhoneNumberType.PREMIUM_RATE: "premium",
                phonenumbers.PhoneNumberType.VOIP: "voip",
            }
            tipo_numero = tipos_map.get(tipo_ph, "desconocido")

            return {
                "valido": True,
                "formato_internacional": phonenumbers.format_number(parsed, phonenumbers.PhoneNumberFormat.INTERNATIONAL),
                "formato_e164": phonenumbers.format_number(parsed, phonenumbers.PhoneNumberFormat.E164),
                "formato_nacional": phonenumbers.format_number(parsed, phonenumbers.PhoneNumberFormat.NATIONAL),
                "codigo_pais": parsed.country_code,
                "pais_codigo": phonenumbers.region_code_for_number(parsed),
                "carrier": nombre_carrier or "desconocido",
                "tipo_linea": tipo_numero,
                "ubicacion": ubicacion or "desconocida",
                "zonas_horarias": list(zonas_horarias) if zonas_horarias else [],
                "es_posible": phonenumbers.is_possible_number(parsed),
            }
        except phonenumbers.NumberParseException as e:
            return {"valido": False, "error": str(e)}

    async def _verificar_whatsapp(self, numero: str) -> Optional[dict]:
        """verifica si el numero tiene whatsapp activo via wa.me"""
        try:
            numero_limpio = numero.replace("+", "").replace(" ", "").replace("-", "")
            url = f"https://wa.me/{numero_limpio}"

            resp = await self.request_con_rate_limit(url, servicio="default")
            if resp and resp.status_code == 200:
                tiene_wa = "api.whatsapp.com" in resp.text or "web.whatsapp.com" in resp.text
                return {
                    "activo": tiene_wa,
                    "url": url,
                    "numero_limpio": numero_limpio,
                }
        except Exception as e:
            log.debug("error verificando whatsapp", error=str(e))
        return None

    async def _buscar_en_pastes(self, numero: str) -> Optional[dict]:
        """busca el numero en pastes publicos"""
        resultados = []
        numero_limpio = numero.replace("+", "").replace(" ", "").replace("-", "")

        # buscar en google
        queries = [
            f'"{numero}" site:pastebin.com',
            f'"{numero_limpio}" site:pastebin.com',
        ]

        for query in queries:
            url = f"https://www.google.com/search?q={query}&num=5"
            resp = await self.request_con_rate_limit(url, servicio="default")
            if resp and resp.status_code == 200:
                from bs4 import BeautifulSoup
                soup = BeautifulSoup(resp.text, "html.parser")
                for link in soup.find_all("a"):
                    href = link.get("href", "")
                    if "pastebin.com" in href or "paste" in href.lower():
                        resultados.append({"url": href, "query": query})

        return {"encontrados": len(resultados), "resultados": resultados} if resultados else None
