# sentinel - geolocalizacion de imagenes via exif gps
# c1q_ (M-Society team)

from typing import Optional

import structlog
from PIL import Image
from PIL.ExifTags import TAGS, GPSTAGS

from modules.base import ModuloBase
from schemas.modulos import ResultadoEnriquecimiento

log = structlog.get_logger()


class ImageGeolocation(ModuloBase):
    nombre = "image_geolocation"
    categoria = "geo"
    descripcion = "extrae coordenadas gps de imagenes y las geolocaliza"
    requiere_api_key = False

    async def ejecutar(self, objetivo: str, parametros: dict = None) -> ResultadoEnriquecimiento:
        ruta_imagen = objetivo.strip()
        entidades = []
        relaciones = []

        try:
            coords = self._extraer_gps(ruta_imagen)
            if coords:
                lat, lon = coords
                # reverse geocoding
                direccion = await self._reverse_geocode(lat, lon)

                ubicacion_str = f"{lat}, {lon}"
                if direccion:
                    ubicacion_str = direccion.get("display_name", ubicacion_str)

                entidades.append({
                    "tipo": "location",
                    "valor": ubicacion_str,
                    "datos": {
                        "latitud": lat,
                        "longitud": lon,
                        "direccion": direccion,
                        "fuente": "exif_gps",
                    },
                    "confianza": 0.9,
                })

                return ResultadoEnriquecimiento(
                    fuente=self.nombre,
                    tipo="location",
                    datos={
                        "imagen": ruta_imagen,
                        "latitud": lat,
                        "longitud": lon,
                        "direccion": direccion,
                    },
                    confianza=0.9,
                    entidades_nuevas=entidades,
                )

            return ResultadoEnriquecimiento(
                fuente=self.nombre, tipo="location",
                datos={"imagen": ruta_imagen, "gps_encontrado": False},
                confianza=0.0,
            )

        except Exception as e:
            return ResultadoEnriquecimiento(
                fuente=self.nombre, tipo="location",
                error=f"error procesando imagen: {str(e)}",
                confianza=0.0,
            )

    def _extraer_gps(self, ruta: str) -> Optional[tuple]:
        """extrae coordenadas gps del exif de una imagen"""
        imagen = Image.open(ruta)
        exif_data = imagen._getexif()
        if not exif_data:
            return None

        gps_info = {}
        for tag_id, valor in exif_data.items():
            tag = TAGS.get(tag_id)
            if tag == "GPSInfo":
                for gps_tag_id, gps_valor in valor.items():
                    gps_tag = GPSTAGS.get(gps_tag_id, gps_tag_id)
                    gps_info[gps_tag] = gps_valor

        if not gps_info:
            return None

        lat = self._convertir_gps(gps_info.get("GPSLatitude"), gps_info.get("GPSLatitudeRef"))
        lon = self._convertir_gps(gps_info.get("GPSLongitude"), gps_info.get("GPSLongitudeRef"))

        if lat is not None and lon is not None:
            return (lat, lon)
        return None

    def _convertir_gps(self, coords, ref) -> Optional[float]:
        """convierte coordenadas gps exif a decimal"""
        if not coords or not ref:
            return None
        grados = float(coords[0])
        minutos = float(coords[1])
        segundos = float(coords[2])
        resultado = grados + (minutos / 60.0) + (segundos / 3600.0)
        if ref in ("S", "W"):
            resultado = -resultado
        return resultado

    async def _reverse_geocode(self, lat: float, lon: float) -> Optional[dict]:
        """convierte coordenadas a direccion usando nominatim"""
        url = f"https://nominatim.openstreetmap.org/reverse?lat={lat}&lon={lon}&format=json"
        headers = {"User-Agent": "SENTINEL-OSINT/1.0"}
        resp = await self.request_con_rate_limit(url, servicio="default", headers=headers)
        if resp and resp.status_code == 200:
            return resp.json()
        return None
