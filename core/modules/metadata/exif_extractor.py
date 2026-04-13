# sentinel - extraccion de metadatos exif de imagenes
# m-society & c1q_

import asyncio
import io
from typing import Optional

from PIL import Image
from PIL.ExifTags import TAGS, GPSTAGS
import httpx
import structlog

from modules.base import ModuloBase
from schemas.modulos import ResultadoEnriquecimiento

log = structlog.get_logger()


class ExifExtractor(ModuloBase):
    nombre = "exif_extractor"
    categoria = "metadata"
    descripcion = "extraccion completa de exif de imagenes: gps, camara, software, fecha"

    async def ejecutar(self, objetivo: str, parametros: dict = None) -> ResultadoEnriquecimiento:
        """objetivo puede ser una url de imagen o una ruta local"""
        entidades = []
        relaciones = []
        resultados = {"objetivo": objetivo}

        # obtener imagen
        imagen_bytes = None
        if objetivo.startswith("http"):
            resp = await self.request_con_rate_limit(objetivo, servicio="default")
            if resp and resp.status_code == 200:
                imagen_bytes = resp.content
        else:
            try:
                with open(objetivo, "rb") as f:
                    imagen_bytes = f.read()
            except FileNotFoundError:
                return ResultadoEnriquecimiento(
                    fuente=self.nombre, tipo="document",
                    error="archivo no encontrado", confianza=0.0,
                )

        if not imagen_bytes:
            return ResultadoEnriquecimiento(
                fuente=self.nombre, tipo="document",
                error="no se pudo obtener la imagen", confianza=0.0,
            )

        # extraer exif
        loop = asyncio.get_event_loop()
        exif_data = await loop.run_in_executor(None, self._extraer_exif, imagen_bytes)

        if exif_data:
            resultados["exif"] = exif_data

            # gps
            if exif_data.get("gps"):
                gps = exif_data["gps"]
                lat = gps.get("latitud")
                lon = gps.get("longitud")
                if lat and lon:
                    # geolocalizacion inversa
                    direccion = await self._geo_inversa(lat, lon)
                    resultados["geolocalizacion"] = {
                        "latitud": lat,
                        "longitud": lon,
                        "direccion": direccion,
                    }

                    ubicacion = direccion or f"{lat}, {lon}"
                    entidades.append({
                        "tipo": "location", "valor": ubicacion,
                        "datos": {"latitud": lat, "longitud": lon, "fuente": "exif_gps"},
                        "confianza": 0.9,
                    })
                    relaciones.append({
                        "tipo_relacion": "located_at",
                        "origen_valor": objetivo, "origen_tipo": "document",
                        "destino_valor": ubicacion, "destino_tipo": "location",
                        "confianza": 0.9,
                    })

            # autor/artista
            if exif_data.get("artista") or exif_data.get("autor"):
                autor = exif_data.get("artista") or exif_data.get("autor")
                entidades.append({
                    "tipo": "person", "valor": autor,
                    "datos": {"fuente": "exif_autor"},
                    "confianza": 0.6,
                })
                relaciones.append({
                    "tipo_relacion": "owns",
                    "origen_valor": autor, "origen_tipo": "person",
                    "destino_valor": objetivo, "destino_tipo": "document",
                    "confianza": 0.6,
                })

            # software de edicion
            if exif_data.get("software"):
                sw = exif_data["software"]
                editado = any(e in sw.lower() for e in ["photoshop", "gimp", "lightroom", "snapseed", "canva"])
                resultados["edicion_detectada"] = editado
                resultados["software_edicion"] = sw

        # thumbnail embebido
        thumbnail = await loop.run_in_executor(None, self._extraer_thumbnail, imagen_bytes)
        if thumbnail:
            resultados["tiene_thumbnail"] = True
            resultados["thumbnail_tamano"] = len(thumbnail)

        self._entidades_encontradas = len(entidades)
        self._relaciones_creadas = len(relaciones)

        return ResultadoEnriquecimiento(
            fuente=self.nombre, tipo="document",
            datos=resultados, confianza=0.8,
            entidades_nuevas=entidades,
            relaciones_nuevas=relaciones,
        )

    def _extraer_exif(self, imagen_bytes: bytes) -> Optional[dict]:
        """extrae todos los datos exif de una imagen"""
        try:
            img = Image.open(io.BytesIO(imagen_bytes))
            exif_raw = img._getexif()
            if not exif_raw:
                return {"sin_exif": True}

            exif = {}
            gps_info = {}

            for tag_id, valor in exif_raw.items():
                tag = TAGS.get(tag_id, tag_id)

                if tag == "GPSInfo":
                    for gps_tag_id, gps_valor in valor.items():
                        gps_tag = GPSTAGS.get(gps_tag_id, gps_tag_id)
                        gps_info[gps_tag] = gps_valor
                else:
                    # convertir a string si es bytes
                    if isinstance(valor, bytes):
                        try:
                            valor = valor.decode("utf-8", errors="ignore")
                        except Exception:
                            valor = str(valor)
                    exif[str(tag)] = str(valor)

            resultado = {
                "marca_camara": exif.get("Make"),
                "modelo_camara": exif.get("Model"),
                "software": exif.get("Software"),
                "fecha_original": exif.get("DateTimeOriginal"),
                "fecha_digitalizacion": exif.get("DateTimeDigitized"),
                "fecha_modificacion": exif.get("DateTime"),
                "exposicion": exif.get("ExposureTime"),
                "apertura": exif.get("FNumber"),
                "iso": exif.get("ISOSpeedRatings"),
                "distancia_focal": exif.get("FocalLength"),
                "flash": exif.get("Flash"),
                "orientacion": exif.get("Orientation"),
                "ancho": exif.get("ExifImageWidth") or exif.get("ImageWidth"),
                "alto": exif.get("ExifImageHeight") or exif.get("ImageLength"),
                "artista": exif.get("Artist"),
                "copyright": exif.get("Copyright"),
                "descripcion": exif.get("ImageDescription"),
                "autor": exif.get("XPAuthor"),
                "comentarios": exif.get("XPComment"),
                "formato": img.format,
                "modo_color": img.mode,
                "tamano_px": list(img.size),
            }

            # procesar gps
            if gps_info:
                lat = self._gps_a_decimal(
                    gps_info.get("GPSLatitude"),
                    gps_info.get("GPSLatitudeRef", "N"),
                )
                lon = self._gps_a_decimal(
                    gps_info.get("GPSLongitude"),
                    gps_info.get("GPSLongitudeRef", "W"),
                )
                resultado["gps"] = {
                    "latitud": lat,
                    "longitud": lon,
                    "altitud": str(gps_info.get("GPSAltitude", "")),
                    "timestamp": str(gps_info.get("GPSTimeStamp", "")),
                    "fecha_gps": str(gps_info.get("GPSDateStamp", "")),
                }

            # limpiar nones
            resultado = {k: v for k, v in resultado.items() if v is not None}

            return resultado

        except Exception as e:
            log.warning("error extrayendo exif", error=str(e))
            return {"error": str(e)}

    def _gps_a_decimal(self, coordenadas, referencia: str) -> Optional[float]:
        """convierte coordenadas gps exif a decimal"""
        if not coordenadas:
            return None
        try:
            grados = float(coordenadas[0])
            minutos = float(coordenadas[1])
            segundos = float(coordenadas[2])

            decimal = grados + (minutos / 60.0) + (segundos / 3600.0)

            if referencia in ("S", "W"):
                decimal = -decimal

            return round(decimal, 6)
        except (TypeError, IndexError, ValueError):
            return None

    def _extraer_thumbnail(self, imagen_bytes: bytes) -> Optional[bytes]:
        """extrae el thumbnail embebido en la imagen"""
        try:
            img = Image.open(io.BytesIO(imagen_bytes))
            exif_raw = img._getexif()
            if exif_raw and 0x0201 in exif_raw:  # JPEGInterchangeFormat
                offset = exif_raw[0x0201]
                length = exif_raw.get(0x0202, 0)  # JPEGInterchangeFormatLength
                if offset and length:
                    return imagen_bytes[offset:offset + length]
        except Exception:
            pass
        return None

    async def _geo_inversa(self, lat: float, lon: float) -> Optional[str]:
        """geolocalizacion inversa de coordenadas a direccion"""
        url = f"https://nominatim.openstreetmap.org/reverse?format=json&lat={lat}&lon={lon}&zoom=18"
        headers = {"User-Agent": "SENTINEL-OSINT/1.0"}

        resp = await self.request_con_rate_limit(url, servicio="default", headers=headers)
        if resp and resp.status_code == 200:
            datos = resp.json()
            return datos.get("display_name")
        return None
