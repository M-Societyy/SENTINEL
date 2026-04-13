# sentinel - mapeo a mitre att&ck
# c1q_ (M-Society team)

import asyncio
from typing import Optional

import structlog

from modules.base import ModuloBase
from schemas.modulos import ResultadoEnriquecimiento

log = structlog.get_logger()

# base de datos local simplificada de mitre att&ck (tacticas principales)
MITRE_TACTICAS = {
    "TA0001": {"nombre": "Initial Access", "descripcion": "tecnicas para obtener acceso inicial a una red"},
    "TA0002": {"nombre": "Execution", "descripcion": "tecnicas para ejecutar codigo malicioso"},
    "TA0003": {"nombre": "Persistence", "descripcion": "tecnicas para mantener acceso persistente"},
    "TA0004": {"nombre": "Privilege Escalation", "descripcion": "tecnicas para obtener permisos elevados"},
    "TA0005": {"nombre": "Defense Evasion", "descripcion": "tecnicas para evadir deteccion"},
    "TA0006": {"nombre": "Credential Access", "descripcion": "tecnicas para robar credenciales"},
    "TA0007": {"nombre": "Discovery", "descripcion": "tecnicas de reconocimiento en la red"},
    "TA0008": {"nombre": "Lateral Movement", "descripcion": "tecnicas para moverse lateralmente"},
    "TA0009": {"nombre": "Collection", "descripcion": "tecnicas para recolectar datos"},
    "TA0010": {"nombre": "Exfiltration", "descripcion": "tecnicas para exfiltrar datos"},
    "TA0011": {"nombre": "Command and Control", "descripcion": "tecnicas de comunicacion c2"},
    "TA0040": {"nombre": "Impact", "descripcion": "tecnicas para destruir o manipular sistemas"},
    "TA0043": {"nombre": "Reconnaissance", "descripcion": "tecnicas de reconocimiento previo al ataque"},
}

# tecnicas comunes mapeadas a keywords
TECNICAS_KEYWORDS = {
    "T1566": {"nombre": "Phishing", "tactica": "TA0001", "keywords": ["phishing", "spearphishing", "email malicioso"]},
    "T1059": {"nombre": "Command and Scripting Interpreter", "tactica": "TA0002", "keywords": ["powershell", "bash", "script", "cmd"]},
    "T1053": {"nombre": "Scheduled Task/Job", "tactica": "TA0003", "keywords": ["cron", "scheduled task", "at job"]},
    "T1548": {"nombre": "Abuse Elevation Control", "tactica": "TA0004", "keywords": ["uac bypass", "sudo", "privilege escalation"]},
    "T1027": {"nombre": "Obfuscated Files", "tactica": "TA0005", "keywords": ["obfuscation", "packed", "encoded", "base64"]},
    "T1003": {"nombre": "OS Credential Dumping", "tactica": "TA0006", "keywords": ["mimikatz", "credential dump", "lsass", "sam"]},
    "T1046": {"nombre": "Network Service Scanning", "tactica": "TA0007", "keywords": ["port scan", "nmap", "service scan"]},
    "T1021": {"nombre": "Remote Services", "tactica": "TA0008", "keywords": ["rdp", "ssh", "smb", "winrm"]},
    "T1005": {"nombre": "Data from Local System", "tactica": "TA0009", "keywords": ["data collection", "file steal"]},
    "T1041": {"nombre": "Exfiltration Over C2", "tactica": "TA0010", "keywords": ["exfiltration", "data theft"]},
    "T1071": {"nombre": "Application Layer Protocol", "tactica": "TA0011", "keywords": ["http c2", "dns c2", "beacon"]},
    "T1486": {"nombre": "Data Encrypted for Impact", "tactica": "TA0040", "keywords": ["ransomware", "encrypt", "ransom"]},
    "T1595": {"nombre": "Active Scanning", "tactica": "TA0043", "keywords": ["scanning", "reconnaissance", "enumeration"]},
    "T1590": {"nombre": "Gather Victim Network Info", "tactica": "TA0043", "keywords": ["whois", "dns enum", "subdomain"]},
    "T1589": {"nombre": "Gather Victim Identity Info", "tactica": "TA0043", "keywords": ["osint", "email harvest", "employee enum"]},
    "T1078": {"nombre": "Valid Accounts", "tactica": "TA0001", "keywords": ["stolen credentials", "valid account", "credential reuse"]},
    "T1110": {"nombre": "Brute Force", "tactica": "TA0006", "keywords": ["brute force", "password spray", "credential stuffing"]},
    "T1133": {"nombre": "External Remote Services", "tactica": "TA0001", "keywords": ["vpn", "citrix", "rdp external"]},
    "T1190": {"nombre": "Exploit Public-Facing Application", "tactica": "TA0001", "keywords": ["exploit", "cve", "vulnerability", "rce"]},
    "T1204": {"nombre": "User Execution", "tactica": "TA0002", "keywords": ["malicious file", "trojan", "user click"]},
}


class MitreMapper(ModuloBase):
    nombre = "mitre_mapper"
    categoria = "threat"
    descripcion = "mapeo de hallazgos a mitre att&ck tactics, techniques, procedures"

    async def ejecutar(self, objetivo: str, parametros: dict = None) -> ResultadoEnriquecimiento:
        """objetivo puede ser un texto descriptivo o una lista de tags/iocs"""
        texto = objetivo.strip().lower()
        parametros = parametros or {}
        tags = parametros.get("tags", [])

        # combinar objetivo y tags para busqueda
        texto_busqueda = f"{texto} {' '.join(tags)}".lower()

        tecnicas_encontradas = []
        tacticas_encontradas = set()

        for tecnica_id, info in TECNICAS_KEYWORDS.items():
            for keyword in info["keywords"]:
                if keyword.lower() in texto_busqueda:
                    tecnicas_encontradas.append({
                        "tecnica_id": tecnica_id,
                        "nombre": info["nombre"],
                        "tactica_id": info["tactica"],
                        "tactica_nombre": MITRE_TACTICAS.get(info["tactica"], {}).get("nombre", ""),
                        "keyword_match": keyword,
                    })
                    tacticas_encontradas.add(info["tactica"])
                    break

        # generar navigator layer
        navigator_layer = self._generar_navigator_layer(tecnicas_encontradas)

        # sugerir controles defensivos
        controles = self._sugerir_controles(tecnicas_encontradas)

        return ResultadoEnriquecimiento(
            fuente=self.nombre, tipo="threat",
            datos={
                "texto_analizado": texto[:200],
                "tecnicas_encontradas": tecnicas_encontradas,
                "tacticas_cubiertas": [{"id": t, "nombre": MITRE_TACTICAS.get(t, {}).get("nombre", "")} for t in tacticas_encontradas],
                "total_tecnicas": len(tecnicas_encontradas),
                "total_tacticas": len(tacticas_encontradas),
                "navigator_layer": navigator_layer,
                "controles_defensivos": controles,
            },
            confianza=min(0.3 + (len(tecnicas_encontradas) * 0.1), 0.95),
        )

    def _generar_navigator_layer(self, tecnicas: list[dict]) -> dict:
        """genera un att&ck navigator layer json"""
        return {
            "name": "SENTINEL - Hallazgos",
            "versions": {"attack": "14", "navigator": "4.9.1", "layer": "4.5"},
            "domain": "enterprise-attack",
            "description": "tecnicas detectadas por sentinel",
            "techniques": [{
                "techniqueID": t["tecnica_id"],
                "tactic": t["tactica_nombre"].lower().replace(" ", "-"),
                "color": "#ff6666",
                "comment": f"detectado por keyword: {t['keyword_match']}",
                "enabled": True,
                "score": 100,
            } for t in tecnicas],
        }

    def _sugerir_controles(self, tecnicas: list[dict]) -> list[dict]:
        """sugiere controles defensivos basados en las tecnicas encontradas"""
        controles_map = {
            "T1566": [{"control": "email filtering", "descripcion": "implementar filtrado avanzado de email con sandbox"}],
            "T1059": [{"control": "application whitelisting", "descripcion": "restringir ejecucion de scripts no autorizados"}],
            "T1003": [{"control": "credential guard", "descripcion": "habilitar windows credential guard, monitorear lsass"}],
            "T1110": [{"control": "account lockout", "descripcion": "implementar bloqueo de cuentas y mfa"}],
            "T1190": [{"control": "patch management", "descripcion": "mantener aplicaciones actualizadas, waf"}],
            "T1486": [{"control": "backup strategy", "descripcion": "backups offline regulares, segmentacion de red"}],
        }

        controles = []
        for t in tecnicas:
            tid = t["tecnica_id"]
            if tid in controles_map:
                for c in controles_map[tid]:
                    c["tecnica"] = tid
                    controles.append(c)

        return controles
