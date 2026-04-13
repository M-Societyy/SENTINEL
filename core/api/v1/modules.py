# sentinel - endpoints de modulos osint
# m-society & c1q_

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.ext.asyncio import AsyncSession

from auth.seguridad import obtener_usuario_actual
from config import config
from db.session import obtener_sesion
from models.usuarios import Usuario
from schemas.modulos import EjecutarModulo, ResultadoModulo, EstadoModulo, ListaModulos

router = APIRouter(prefix="/modules", tags=["modulos"])

# registro de modulos disponibles
MODULOS_DISPONIBLES = [
    EstadoModulo(
        nombre="email_intel",
        categoria="identity",
        descripcion="inteligencia de email: validacion, breaches, correlacion",
        requiere_api_key=True,
        api_key_configurada=bool(config.hibp_api_key),
    ),
    EstadoModulo(
        nombre="username_enum",
        categoria="identity",
        descripcion="enumeracion de username en 400+ plataformas",
    ),
    EstadoModulo(
        nombre="phone_intel",
        categoria="identity",
        descripcion="inteligencia de numeros telefonicos",
    ),
    EstadoModulo(
        nombre="person_search",
        categoria="identity",
        descripcion="busqueda de personas con correlacion cruzada",
    ),
    EstadoModulo(
        nombre="domain_intel",
        categoria="network",
        descripcion="inteligencia completa de dominios: whois, dns, tecnologias",
    ),
    EstadoModulo(
        nombre="subdomain_enum",
        categoria="network",
        descripcion="enumeracion de subdominios pasiva y activa",
        requiere_api_key=True,
        api_key_configurada=bool(config.securitytrails_api_key),
    ),
    EstadoModulo(
        nombre="ip_intel",
        categoria="network",
        descripcion="inteligencia de ip: geolocalizacion, asn, reputacion, servicios",
        requiere_api_key=True,
        api_key_configurada=bool(config.shodan_api_key),
    ),
    EstadoModulo(
        nombre="ssl_intel",
        categoria="network",
        descripcion="analisis de certificados tls/ssl y fingerprinting",
    ),
    EstadoModulo(
        nombre="github_intel",
        categoria="social",
        descripcion="inteligencia de github: perfil, repos, secretos, emails",
    ),
    EstadoModulo(
        nombre="linkedin_intel",
        categoria="social",
        descripcion="inteligencia de linkedin: perfil, empresa, empleados",
    ),
    EstadoModulo(
        nombre="twitter_intel",
        categoria="social",
        descripcion="inteligencia de twitter/x",
    ),
    EstadoModulo(
        nombre="reddit_intel",
        categoria="social",
        descripcion="inteligencia de reddit: perfil, posts, comentarios",
    ),
    EstadoModulo(
        nombre="hibp_client",
        categoria="breach",
        descripcion="busqueda en haveibeenpwned",
        requiere_api_key=True,
        api_key_configurada=bool(config.hibp_api_key),
    ),
    EstadoModulo(
        nombre="paste_monitor",
        categoria="breach",
        descripcion="monitoreo de paste sites",
    ),
    EstadoModulo(
        nombre="ioc_enricher",
        categoria="threat",
        descripcion="enriquecimiento de iocs contra multiples fuentes",
        requiere_api_key=True,
        api_key_configurada=bool(config.virustotal_api_key),
    ),
    EstadoModulo(
        nombre="mitre_mapper",
        categoria="threat",
        descripcion="mapeo a mitre att&ck",
    ),
    EstadoModulo(
        nombre="virustotal_client",
        categoria="threat",
        descripcion="analisis en virustotal",
        requiere_api_key=True,
        api_key_configurada=bool(config.virustotal_api_key),
    ),
    EstadoModulo(
        nombre="exif_extractor",
        categoria="metadata",
        descripcion="extraccion de metadatos exif de imagenes",
    ),
    EstadoModulo(
        nombre="pdf_metadata",
        categoria="metadata",
        descripcion="extraccion de metadatos de pdfs",
    ),
    EstadoModulo(
        nombre="tor_crawler",
        categoria="darkweb",
        descripcion="crawling de sitios .onion (requiere activacion explicita)",
        habilitado=False,
    ),
    EstadoModulo(
        nombre="employee_enum",
        categoria="company",
        descripcion="enumeracion de empleados de organizaciones",
        requiere_api_key=True,
        api_key_configurada=bool(config.hunter_api_key),
    ),
    EstadoModulo(
        nombre="job_intel",
        categoria="company",
        descripcion="inteligencia de ofertas laborales y stack tecnologico",
    ),
]


@router.get("", response_model=ListaModulos)
async def listar_modulos(
    usuario: Usuario = Depends(obtener_usuario_actual),
):
    """lista todos los modulos osint disponibles y su estado"""
    return ListaModulos(
        modulos=MODULOS_DISPONIBLES,
        total=len(MODULOS_DISPONIBLES),
    )


@router.post("/execute", response_model=ResultadoModulo)
async def ejecutar_modulo(
    datos: EjecutarModulo,
    sesion: AsyncSession = Depends(obtener_sesion),
    usuario: Usuario = Depends(obtener_usuario_actual),
):
    """ejecuta un modulo osint contra un objetivo (envia a celery)"""
    # verificar que el modulo existe
    modulo_info = next(
        (m for m in MODULOS_DISPONIBLES if m.nombre == datos.modulo), None
    )
    if not modulo_info:
        raise HTTPException(status_code=404, detail=f"modulo '{datos.modulo}' no encontrado")

    if not modulo_info.habilitado:
        raise HTTPException(status_code=403, detail=f"modulo '{datos.modulo}' esta deshabilitado")

    # aqui se despacha la tarea a celery
    # por ahora retornamos el estado como pendiente
    from tasks.celery_app import ejecutar_modulo_task
    tarea = ejecutar_modulo_task.delay(
        str(datos.investigacion_id),
        datos.modulo,
        datos.objetivo,
        datos.parametros,
        str(usuario.id),
    )

    return ResultadoModulo(
        modulo=datos.modulo,
        estado="running",
        datos={"task_id": tarea.id},
    )
