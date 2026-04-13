# SENTINEL - Guia de Modulos OSINT

Documentacion detallada de cada modulo de inteligencia disponible en SENTINEL.

---

## Tipos de Entidades

cada modulo descubre y genera entidades de estos tipos:

| tipo | descripcion | ejemplo |
|------|-------------|---------|
| `person` | persona identificada | "juan garcia" |
| `email` | direccion de email | "juan@empresa.com" |
| `username` | nombre de usuario en plataforma | "juangarcia123" |
| `phone` | numero de telefono | "+34612345678" |
| `domain` | dominio web | "empresa.com" |
| `ip` | direccion ip (v4 o v6) | "192.168.1.1" |
| `organization` | empresa u organizacion | "Empresa S.A." |
| `social_profile` | perfil en red social | "github:juangarcia" |
| `credential` | credencial expuesta | "breach:linkedin:juan@..." |
| `hash` | hash de archivo o password | "sha256:abc123..." |
| `document` | documento o archivo | "informe.pdf" |
| `location` | ubicacion geografica | "Madrid, Espana" |

## Tipos de Relaciones

| relacion | significado | ejemplo |
|----------|-------------|---------|
| `OWNS` | propietario de | person OWNS email |
| `USES` | usa o utiliza | person USES username |
| `ASSOCIATED_WITH` | asociado con | email ASSOCIATED_WITH domain |
| `LOCATED_AT` | ubicado en | ip LOCATED_AT location |
| `MEMBER_OF` | miembro de | person MEMBER_OF organization |
| `LEAKED_IN` | filtrado en | email LEAKED_IN credential |
| `RESOLVES_TO` | resuelve a | domain RESOLVES_TO ip |
| `HOSTED_ON` | alojado en | domain HOSTED_ON ip |
| `REGISTERED_BY` | registrado por | domain REGISTERED_BY person |

---

## Module 1: Identity Intelligence

### email_intel
**input:** direccion de email
**output:** validacion completa + correlaciones

funcionalidades:
1. validacion sintactica con regex
2. verificacion de registros mx del dominio
3. verificacion smtp (rcpt to handshake sin enviar email)
4. busqueda en haveibeenpwned (breaches)
5. busqueda en dehashed (credential leaks)
6. busqueda en hunter.io (organizacion, cargo)
7. busqueda de commits en github con ese email
8. gravatar hash check (foto de perfil)
9. score de confianza calculado por acuerdo entre fuentes

### username_enum
**input:** nombre de usuario
**output:** mapa de presencia digital en +400 plataformas

funcionalidades:
1. verificacion en +400 plataformas usando status code + body heuristics
2. rate limiting configurable por plataforma
3. proxy rotation automatica
4. extraccion de bio, foto, actividad de cada perfil
5. correlacion de usernames similares (levenshtein distance)

### phone_intel
**input:** numero de telefono
**output:** informacion del carrier, tipo, ubicacion

### person_search
**input:** nombre completo + ubicacion (opcional)
**output:** perfil digital estimado con timeline

---

## Module 2: Network Intelligence

### domain_intel
**input:** nombre de dominio
**output:** whois, dns, tecnologias, screenshot

dns records verificados: A, AAAA, MX, NS, TXT, SOA, CNAME, PTR, SRV, DMARC, DKIM, SPF

### subdomain_enum
**input:** dominio base
**output:** lista de subdominios activos

metodos:
- passive: certificate transparency (crt.sh), securitytrails, virustotal
- active: dns bruteforce con wordlist, permutaciones automaticas
- zone transfer attempt (axfr)

### ip_intel
**input:** direccion ip
**output:** asn, geolocalizacion, reputacion, puertos, cloud detection

### ssl_intel
**input:** dominio
**output:** certificado completo, cipher suites, vulnerabilidades tls

---

## Module 3: Threat Intelligence

### ioc_enricher
**input:** ip, dominio, hash o url
**output:** reputacion y contexto de amenaza multi-fuente

fuentes: virustotal, otx alienvault, malwarebazaar, urlhaus, feodo tracker

### mitre_mapper
mapea hallazgos a mitre att&ck tactics, techniques y procedures.
genera navigator layers para visualizacion.

---

## Uso Etico

todos los modulos incluyen:
- rate limiting automatico para no abusar de servicios
- proxy rotation para distribuir carga
- respeto de robots.txt y retry-after headers
- logging de auditoria de todas las acciones
- darkweb modules desactivados por defecto

---
*SENTINEL v1.0.0 - M-Society & c1q_*
