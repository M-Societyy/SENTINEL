# sentinel - generador de reportes pdf con weasyprint
# m-society & c1q_

import os
from datetime import datetime
from typing import Optional
from uuid import UUID

import structlog
from jinja2 import Environment, FileSystemLoader

log = structlog.get_logger()

# directorio de templates
TEMPLATES_DIR = os.path.join(os.path.dirname(__file__), "templates")


class GeneradorReportes:
    """genera reportes de investigacion en multiples formatos"""

    def __init__(self):
        self.env = Environment(
            loader=FileSystemLoader(TEMPLATES_DIR),
            autoescape=True,
        )

    def generar_pdf(self, datos_investigacion: dict, ruta_salida: str) -> str:
        """genera reporte pdf profesional"""
        try:
            from weasyprint import HTML

            html_contenido = self._renderizar_html(datos_investigacion)
            HTML(string=html_contenido).write_pdf(ruta_salida)
            log.info("reporte pdf generado", ruta=ruta_salida)
            return ruta_salida
        except ImportError:
            log.warning("weasyprint no instalado, generando solo html")
            ruta_html = ruta_salida.replace(".pdf", ".html")
            return self.generar_html(datos_investigacion, ruta_html)

    def generar_html(self, datos_investigacion: dict, ruta_salida: str) -> str:
        """genera reporte html interactivo"""
        html_contenido = self._renderizar_html(datos_investigacion)
        with open(ruta_salida, "w", encoding="utf-8") as f:
            f.write(html_contenido)
        log.info("reporte html generado", ruta=ruta_salida)
        return ruta_salida

    def generar_json(self, datos_investigacion: dict, ruta_salida: str) -> str:
        """genera reporte json estructurado"""
        import orjson
        with open(ruta_salida, "wb") as f:
            f.write(orjson.dumps(datos_investigacion, option=orjson.OPT_INDENT_2))
        log.info("reporte json generado", ruta=ruta_salida)
        return ruta_salida

    def generar_csv(self, entidades: list[dict], ruta_salida: str) -> str:
        """genera csv de entidades"""
        import csv
        if not entidades:
            return ruta_salida

        campos = ["tipo", "valor", "confianza", "fuentes", "primera_vez"]
        with open(ruta_salida, "w", newline="", encoding="utf-8") as f:
            writer = csv.DictWriter(f, fieldnames=campos, extrasaction="ignore")
            writer.writeheader()
            for ent in entidades:
                writer.writerow(ent)
        log.info("reporte csv generado", ruta=ruta_salida)
        return ruta_salida

    def generar_stix(self, datos_investigacion: dict, ruta_salida: str) -> str:
        """genera bundle stix 2.1 para intercambio de threat intelligence"""
        try:
            from stix2 import Bundle, Indicator, Identity, Report as StixReport
            from stix2 import DomainName, IPv4Address, EmailAddress

            identidad = Identity(
                name="SENTINEL by M-Society",
                identity_class="tool",
                description="plataforma osint enterprise - m-society & c1q_",
            )

            objetos = [identidad]
            entidades = datos_investigacion.get("entidades", [])

            for ent in entidades:
                tipo = ent.get("tipo", "")
                valor = ent.get("valor", "")

                if tipo == "ip":
                    try:
                        obj = IPv4Address(value=valor)
                        objetos.append(obj)
                    except Exception:
                        pass
                elif tipo == "domain":
                    try:
                        obj = DomainName(value=valor)
                        objetos.append(obj)
                    except Exception:
                        pass
                elif tipo == "email":
                    try:
                        obj = EmailAddress(value=valor)
                        objetos.append(obj)
                    except Exception:
                        pass

            bundle = Bundle(objects=objetos)
            with open(ruta_salida, "w", encoding="utf-8") as f:
                f.write(bundle.serialize(pretty=True))

            log.info("reporte stix generado", ruta=ruta_salida)
            return ruta_salida

        except ImportError:
            log.warning("stix2 no instalado")
            return ""

    def _renderizar_html(self, datos: dict) -> str:
        """renderiza el template html con los datos de la investigacion"""
        try:
            template = self.env.get_template("reporte_completo.html")
            return template.render(
                investigacion=datos.get("investigacion", {}),
                entidades=datos.get("entidades", []),
                relaciones=datos.get("relaciones", []),
                modulos=datos.get("modulos_ejecutados", []),
                estadisticas=datos.get("estadisticas", {}),
                fecha_generacion=datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S UTC"),
                version="1.0.0",
                autor="M-Society & c1q_",
            )
        except Exception as e:
            log.error("error renderizando template", error=str(e))
            # fallback: generar html basico
            return self._html_fallback(datos)

    def _html_fallback(self, datos: dict) -> str:
        """genera html basico si el template no esta disponible"""
        inv = datos.get("investigacion", {})
        entidades = datos.get("entidades", [])

        entidades_html = ""
        for ent in entidades:
            entidades_html += f"""
            <tr>
                <td>{ent.get('tipo', '')}</td>
                <td>{ent.get('valor', '')}</td>
                <td>{ent.get('confianza', 0):.0%}</td>
                <td>{', '.join(ent.get('fuentes', []))}</td>
            </tr>"""

        return f"""<!DOCTYPE html>
<html lang="es">
<head>
    <meta charset="UTF-8">
    <title>SENTINEL - Reporte de Investigacion</title>
    <style>
        * {{ margin: 0; padding: 0; box-sizing: border-box; }}
        body {{
            font-family: 'Inter', 'Segoe UI', system-ui, -apple-system, sans-serif;
            background: #0a0a0f;
            color: #e0e0e0;
            line-height: 1.6;
        }}
        .portada {{
            background: linear-gradient(135deg, #0f0f1a 0%, #1a0a2e 50%, #0a1628 100%);
            padding: 80px 40px;
            text-align: center;
            border-bottom: 2px solid #6c5ce7;
            min-height: 60vh;
            display: flex;
            flex-direction: column;
            justify-content: center;
        }}
        .portada h1 {{
            font-size: 4em;
            background: linear-gradient(135deg, #6c5ce7, #a29bfe, #fd79a8);
            -webkit-background-clip: text;
            -webkit-text-fill-color: transparent;
            margin-bottom: 20px;
            letter-spacing: 8px;
        }}
        .portada .subtitulo {{
            font-size: 1.4em;
            color: #a29bfe;
            margin-bottom: 40px;
        }}
        .portada .meta {{
            color: #888;
            font-size: 0.95em;
        }}
        .contenido {{ max-width: 1200px; margin: 0 auto; padding: 40px; }}
        h2 {{
            color: #a29bfe;
            border-bottom: 1px solid #333;
            padding-bottom: 10px;
            margin: 40px 0 20px;
            font-size: 1.6em;
        }}
        .disclaimer {{
            background: rgba(253, 121, 168, 0.1);
            border-left: 4px solid #fd79a8;
            padding: 15px 20px;
            margin: 20px 0;
            border-radius: 0 8px 8px 0;
        }}
        table {{ width: 100%; border-collapse: collapse; margin: 20px 0; }}
        th {{ background: #1a1a2e; color: #a29bfe; padding: 12px; text-align: left; }}
        td {{ padding: 10px 12px; border-bottom: 1px solid #1a1a2e; }}
        tr:hover {{ background: rgba(108, 92, 231, 0.05); }}
        .stats {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 20px;
            margin: 30px 0;
        }}
        .stat-card {{
            background: linear-gradient(135deg, #1a1a2e, #16213e);
            padding: 25px;
            border-radius: 12px;
            border: 1px solid #333;
            text-align: center;
        }}
        .stat-card .numero {{
            font-size: 2.5em;
            color: #6c5ce7;
            font-weight: 700;
        }}
        .stat-card .label {{ color: #888; margin-top: 5px; }}
        .footer {{
            text-align: center;
            padding: 40px;
            color: #555;
            border-top: 1px solid #1a1a2e;
            margin-top: 60px;
        }}
    </style>
</head>
<body>
    <div class="portada">
        <h1>SENTINEL</h1>
        <p class="subtitulo">reporte de investigacion osint</p>
        <p class="meta">
            investigacion: {inv.get('nombre', 'sin nombre')}<br>
            fecha: {datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S UTC')}<br>
            operador: {inv.get('operador', 'anonimo')}<br>
            generado por: m-society & c1q_
        </p>
    </div>

    <div class="contenido">
        <div class="disclaimer">
            <strong>DISCLAIMER:</strong> este reporte fue generado por SENTINEL, una herramienta
            disenada exclusivamente para investigaciones de seguridad autorizadas.
            el uso indebido es responsabilidad del operador.
        </div>

        <h2>resumen ejecutivo</h2>
        <div class="stats">
            <div class="stat-card">
                <div class="numero">{len(entidades)}</div>
                <div class="label">entidades descubiertas</div>
            </div>
            <div class="stat-card">
                <div class="numero">{len(datos.get('relaciones', []))}</div>
                <div class="label">relaciones encontradas</div>
            </div>
            <div class="stat-card">
                <div class="numero">{len(datos.get('modulos_ejecutados', []))}</div>
                <div class="label">modulos ejecutados</div>
            </div>
        </div>

        <h2>entidades descubiertas</h2>
        <table>
            <thead>
                <tr>
                    <th>tipo</th>
                    <th>valor</th>
                    <th>confianza</th>
                    <th>fuentes</th>
                </tr>
            </thead>
            <tbody>
                {entidades_html}
            </tbody>
        </table>
    </div>

    <div class="footer">
        <p>SENTINEL v1.0.0 - m-society & c1q_</p>
        <p>plataforma osint enterprise</p>
    </div>
</body>
</html>"""


# instancia global
generador = GeneradorReportes()
