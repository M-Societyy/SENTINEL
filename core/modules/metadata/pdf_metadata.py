# sentinel - extraccion de metadatos de pdfs
# m-society & c1q_

import asyncio
import io
from typing import Optional

from PyPDF2 import PdfReader
import structlog

from modules.base import ModuloBase
from schemas.modulos import ResultadoEnriquecimiento

log = structlog.get_logger()


class PdfMetadata(ModuloBase):
    nombre = "pdf_metadata"
    categoria = "metadata"
    descripcion = "extraccion de metadatos de pdfs: autor, software, texto, macros"

    async def ejecutar(self, objetivo: str, parametros: dict = None) -> ResultadoEnriquecimiento:
        """objetivo puede ser una url o ruta local al pdf"""
        entidades = []
        relaciones = []
        resultados = {"objetivo": objetivo}

        pdf_bytes = None
        if objetivo.startswith("http"):
            resp = await self.request_con_rate_limit(objetivo, servicio="default")
            if resp and resp.status_code == 200:
                pdf_bytes = resp.content
        else:
            try:
                with open(objetivo, "rb") as f:
                    pdf_bytes = f.read()
            except FileNotFoundError:
                return ResultadoEnriquecimiento(
                    fuente=self.nombre, tipo="document",
                    error="archivo no encontrado", confianza=0.0,
                )

        if not pdf_bytes:
            return ResultadoEnriquecimiento(
                fuente=self.nombre, tipo="document",
                error="no se pudo obtener el pdf", confianza=0.0,
            )

        loop = asyncio.get_event_loop()
        metadata = await loop.run_in_executor(None, self._extraer_metadata, pdf_bytes)

        if metadata:
            resultados["metadata"] = metadata

            if metadata.get("autor"):
                entidades.append({
                    "tipo": "person", "valor": metadata["autor"],
                    "datos": {"fuente": "pdf_metadata"},
                    "confianza": 0.6,
                })
                relaciones.append({
                    "tipo_relacion": "owns",
                    "origen_valor": metadata["autor"], "origen_tipo": "person",
                    "destino_valor": objetivo, "destino_tipo": "document",
                    "confianza": 0.6,
                })

            if metadata.get("organizacion"):
                entidades.append({
                    "tipo": "organization", "valor": metadata["organizacion"],
                    "datos": {"fuente": "pdf_metadata"},
                    "confianza": 0.5,
                })

            # extraer emails del texto
            if metadata.get("texto_muestra"):
                import re
                emails = re.findall(
                    r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}',
                    metadata["texto_muestra"]
                )
                for email in set(emails):
                    email = email.lower()
                    entidades.append({
                        "tipo": "email", "valor": email,
                        "datos": {"fuente": "pdf_texto"},
                        "confianza": 0.6,
                    })

                # extraer urls del texto
                urls = re.findall(
                    r'https?://[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}[/\w.-]*',
                    metadata["texto_muestra"]
                )
                for url_encontrada in set(urls)[:10]:
                    dominio = url_encontrada.replace("https://", "").replace("http://", "").split("/")[0]
                    entidades.append({
                        "tipo": "domain", "valor": dominio,
                        "datos": {"fuente": "pdf_texto", "url_completa": url_encontrada},
                        "confianza": 0.5,
                    })

        self._entidades_encontradas = len(entidades)
        self._relaciones_creadas = len(relaciones)

        return ResultadoEnriquecimiento(
            fuente=self.nombre, tipo="document",
            datos=resultados, confianza=0.7,
            entidades_nuevas=entidades,
            relaciones_nuevas=relaciones,
        )

    def _extraer_metadata(self, pdf_bytes: bytes) -> Optional[dict]:
        """extrae metadatos y texto del pdf"""
        try:
            reader = PdfReader(io.BytesIO(pdf_bytes))
            info = reader.metadata

            metadata = {
                "titulo": info.title if info else None,
                "autor": info.author if info else None,
                "asunto": info.subject if info else None,
                "creador": info.creator if info else None,
                "productor": info.producer if info else None,
                "fecha_creacion": str(info.creation_date) if info and info.creation_date else None,
                "fecha_modificacion": str(info.modification_date) if info and info.modification_date else None,
                "total_paginas": len(reader.pages),
                "encriptado": reader.is_encrypted,
            }

            # detectar software
            software = metadata.get("creador") or metadata.get("productor") or ""
            metadata["software_creacion"] = software

            # detectar organizacion del productor/creador
            if software:
                orgs = ["Microsoft", "Adobe", "LibreOffice", "Google", "Apple"]
                for org in orgs:
                    if org.lower() in software.lower():
                        metadata["organizacion_software"] = org

            # info de autor como organizacion
            if info and hasattr(info, "custom_properties"):
                try:
                    props = info.custom_properties
                    if props:
                        metadata["propiedades_custom"] = {str(k): str(v) for k, v in props.items()}
                except Exception:
                    pass

            # extraer texto de las primeras paginas
            texto_total = ""
            for i, pagina in enumerate(reader.pages[:5]):
                try:
                    texto = pagina.extract_text()
                    if texto:
                        texto_total += texto + "\n"
                except Exception:
                    pass

            metadata["texto_muestra"] = texto_total[:5000]
            metadata["tiene_texto_extraible"] = len(texto_total.strip()) > 0

            # detectar posibles macros/scripts (indicadores)
            texto_raw = str(pdf_bytes[:10000])
            indicadores_maliciosos = []
            patrones_peligrosos = [
                "/JavaScript", "/JS ", "/Launch", "/OpenAction",
                "/AA ", "/RichMedia", "/XFA", "/AcroForm",
            ]
            for patron in patrones_peligrosos:
                if patron in texto_raw:
                    indicadores_maliciosos.append(patron.strip("/"))

            metadata["indicadores_scripts"] = indicadores_maliciosos
            metadata["posible_malicioso"] = len(indicadores_maliciosos) > 0

            # limpiar nones
            metadata = {k: v for k, v in metadata.items() if v is not None}

            return metadata

        except Exception as e:
            log.warning("error extrayendo metadata pdf", error=str(e))
            return {"error": str(e)}
