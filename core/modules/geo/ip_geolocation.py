# sentinel - geolocalizacion de ip con multiples fuentes
# c1q_ (M-Society team)

import asyncio
from typing import Optional

import structlog

from config import config
from modules.base import ModuloBase
from schemas.modulos import ResultadoEnriquecimiento

log = structlog.get_logger()


class IpGeolocation(ModuloBase):
    nombre = "ip_geolocation"
    categoria = "geo"
    descripcion = "geolocalizacion de ip con consenso de multiples fuentes"
    requiere_api_key = False

    async def ejecutar(self, objetivo: str, parametros: dict = None) -> ResultadoEnriquecimiento:
        ip = objetivo.strip()
        entidades = []
        relaciones = []

        # consultar multiples fuentes de geolocalizacion
        tareas = [
            self._consultar_ipapi(ip),
            self._consultar_ipinfo(ip),
            self._consultar_ipwhois(ip),
        ]
        resultados_raw = await asyncio.gather(*tareas, return_exceptions=True)
        fuentes = []

        for r in resultados_raw:
            if not isinstance(r, Exception) and r:
                fuentes.append(r)

        # calcular consenso
        ubicacion = self._consenso_ubicacion(fuentes)

        if ubicacion:
            entidades.append({
                "tipo": "location",
                "valor": f"{ubicacion.get('ciudad', '')}, {ubicacion.get('pais', '')}",
                "datos": ubicacion,
                "confianza": ubicacion.get("confianza", 0.5),
            })
            relaciones.append({
                "tipo_relacion": "located_at",
                "origen_valor": ip,
                "origen_tipo": "ip",
                "destino_valor": f"{ubicacion.get('ciudad', '')}, {ubicacion.get('pais', '')}",
                "destino_tipo": "location",
                "confianza": ubicacion.get("confianza", 0.5),
            })

        self._entidades_encontradas = len(entidades)
        self._relaciones_creadas = len(relaciones)

        return ResultadoEnriquecimiento(
            fuente=self.nombre,
            tipo="location",
            datos={
                "ip": ip,
                "ubicacion": ubicacion,
                "fuentes_consultadas": len(fuentes),
            },
            confianza=ubicacion.get("confianza", 0.3) if ubicacion else 0.0,
            entidades_nuevas=entidades,
            relaciones_nuevas=relaciones,
        )

    async def _consultar_ipapi(self, ip: str) -> Optional[dict]:
        url = f"http://ip-api.com/json/{ip}?fields=status,country,regionName,city,lat,lon,isp,org,as"
        resp = await self.request_con_rate_limit(url, servicio="default")
        if resp and resp.status_code == 200:
            datos = resp.json()
            if datos.get("status") == "success":
                return {
                    "fuente": "ip-api",
                    "pais": datos.get("country"),
                    "region": datos.get("regionName"),
                    "ciudad": datos.get("city"),
                    "latitud": datos.get("lat"),
                    "longitud": datos.get("lon"),
                    "isp": datos.get("isp"),
                    "organizacion": datos.get("org"),
                    "asn": datos.get("as"),
                }
        return None

    async def _consultar_ipinfo(self, ip: str) -> Optional[dict]:
        url = f"https://ipinfo.io/{ip}/json"
        headers = {}
        if config.ipinfo_token:
            headers["Authorization"] = f"Bearer {config.ipinfo_token}"
        resp = await self.request_con_rate_limit(url, servicio="ipinfo", headers=headers)
        if resp and resp.status_code == 200:
            datos = resp.json()
            loc = datos.get("loc", ",").split(",")
            return {
                "fuente": "ipinfo",
                "pais": datos.get("country"),
                "region": datos.get("region"),
                "ciudad": datos.get("city"),
                "latitud": float(loc[0]) if len(loc) == 2 else None,
                "longitud": float(loc[1]) if len(loc) == 2 else None,
                "organizacion": datos.get("org"),
            }
        return None

    async def _consultar_ipwhois(self, ip: str) -> Optional[dict]:
        url = f"http://ipwho.is/{ip}"
        resp = await self.request_con_rate_limit(url, servicio="default")
        if resp and resp.status_code == 200:
            datos = resp.json()
            if datos.get("success"):
                return {
                    "fuente": "ipwhois",
                    "pais": datos.get("country"),
                    "region": datos.get("region"),
                    "ciudad": datos.get("city"),
                    "latitud": datos.get("latitude"),
                    "longitud": datos.get("longitude"),
                    "isp": datos.get("connection", {}).get("isp"),
                }
        return None

    def _consenso_ubicacion(self, fuentes: list[dict]) -> Optional[dict]:
        """calcula ubicacion por consenso de multiples fuentes"""
        if not fuentes:
            return None

        # contar votos por pais y ciudad
        paises = {}
        ciudades = {}
        lats = []
        lons = []

        for f in fuentes:
            p = f.get("pais")
            c = f.get("ciudad")
            if p:
                paises[p] = paises.get(p, 0) + 1
            if c:
                ciudades[c] = ciudades.get(c, 0) + 1
            if f.get("latitud") and f.get("longitud"):
                lats.append(f["latitud"])
                lons.append(f["longitud"])

        pais = max(paises, key=paises.get) if paises else None
        ciudad = max(ciudades, key=ciudades.get) if ciudades else None
        lat_promedio = sum(lats) / len(lats) if lats else None
        lon_promedio = sum(lons) / len(lons) if lons else None

        # confianza basada en acuerdo entre fuentes
        acuerdo = max(paises.values()) / len(fuentes) if paises else 0
        confianza = min(0.3 + (acuerdo * 0.5) + (len(fuentes) * 0.05), 1.0)

        return {
            "pais": pais,
            "ciudad": ciudad,
            "region": fuentes[0].get("region"),
            "latitud": lat_promedio,
            "longitud": lon_promedio,
            "confianza": round(confianza, 2),
            "fuentes_acuerdo": len(fuentes),
        }
