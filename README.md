<p align="center">
  <img src="docs/assets/sentinel-banner.svg" alt="SENTINEL" width="800"/>
</p>

<h1 align="center">
  🛡️ SENTINEL v1.0.0
</h1>

<p align="center">
  <strong>plataforma osint enterprise de fuentes abiertas</strong>
  <br/>
  <em>enriquecimiento automatizado · correlacion de entidades · grafos de relaciones · reportes de inteligencia</em>
</p>

<p align="center">
  <a href="#-instalacion"><img src="https://img.shields.io/badge/version-1.0.0-6c5ce7?style=for-the-badge&logo=semver" alt="Version"/></a>
  <a href="LICENSE"><img src="https://img.shields.io/badge/license-MIT-a29bfe?style=for-the-badge" alt="License"/></a>
  <a href="#-stack-tecnologico"><img src="https://img.shields.io/badge/python-3.12-3776AB?style=for-the-badge&logo=python&logoColor=white" alt="Python"/></a>
  <a href="#-stack-tecnologico"><img src="https://img.shields.io/badge/rust-1.76-000000?style=for-the-badge&logo=rust" alt="Rust"/></a>
  <a href="#-stack-tecnologico"><img src="https://img.shields.io/badge/go-1.22-00ADD8?style=for-the-badge&logo=go&logoColor=white" alt="Go"/></a>
  <a href="#-stack-tecnologico"><img src="https://img.shields.io/badge/react-18-61DAFB?style=for-the-badge&logo=react&logoColor=black" alt="React"/></a>
  <a href="#-stack-tecnologico"><img src="https://img.shields.io/badge/docker-compose-2496ED?style=for-the-badge&logo=docker&logoColor=white" alt="Docker"/></a>
</p>

<p align="center">
  <strong>desarrollado por <a href="https://github.com/c1q_">M-Society</a> & <a href="https://github.com/c1q_">c1q_</a></strong>
</p>

---

## 📋 tabla de contenidos

- [que es sentinel](#-que-es-sentinel)
- [disclaimer legal](#%EF%B8%8F-disclaimer-legal)
- [stack tecnologico](#-stack-tecnologico)
- [arquitectura del sistema](#-arquitectura-del-sistema)
- [modulos osint](#-modulos-osint)
- [instalacion](#-instalacion)
  - [requisitos previos](#requisitos-previos)
  - [instalacion con docker (recomendado)](#opcion-1-docker-compose-recomendado)
  - [instalacion manual en linux](#opcion-2-instalacion-manual-linux)
  - [solucion de problemas en linux](#-solucion-de-problemas-en-linux)
- [configuracion](#-configuracion)
- [uso basico](#-uso-basico)
- [api reference](#-api-reference)
- [ejemplos de uso](#-ejemplos-de-uso)
- [generacion de reportes](#-generacion-de-reportes)
- [seguridad](#-seguridad)
- [contribuir](#-contribuir)
- [creditos](#-creditos)

---

## 🔍 que es sentinel

**SENTINEL** es una plataforma unificada de inteligencia de fuentes abiertas (OSINT) disenada para profesionales de ciberseguridad, investigadores y equipos de threat intelligence. combina multiples fuentes de datos, un motor de correlacion inteligente, visualizacion de grafos de relaciones y generacion automatica de reportes en una sola herramienta.

### capacidades principales

| capacidad | descripcion |
|-----------|-------------|
| 🔎 **identity intelligence** | email verification, username enumeration (+400 plataformas), phone intel, person search |
| 🌐 **network intelligence** | domain intel, subdomain enumeration, ip intel, ssl/tls analysis, asn/bgp |
| 📱 **social media intelligence** | github, linkedin, twitter/x, reddit, instagram intel |
| 💀 **breach & leak intelligence** | haveibeenpwned, dehashed, paste monitoring |
| 🕸️ **dark web intelligence** | tor crawling, onion indexing (desactivado por defecto) |
| ⚔️ **threat intelligence** | virustotal, mitre att&ck mapping, ioc enrichment |
| 🏢 **company intelligence** | employee enumeration, job postings analysis, subsidiaries |
| 📄 **metadata intelligence** | exif extraction, pdf/doc metadata, image geolocation |
| 🧠 **correlacion automatica** | cross-module entity correlation, graph analysis, deduplication |
| 📊 **visualizacion de grafos** | sigma.js interactive graphs, neo4j, community detection |
| 📝 **reportes** | pdf, html interactivo, json, csv, stix 2.1 |

### como funciona

```
                    ┌─────────────┐
                    │   SEEDS     │  (email, dominio, username, ip, telefono)
                    └──────┬──────┘
                           │
                    ┌──────▼──────┐
                    │  PIPELINE   │  orquestacion paralela de modulos
                    └──────┬──────┘
                           │
              ┌────────────┼────────────┐
              │            │            │
        ┌─────▼────┐ ┌────▼─────┐ ┌───▼──────┐
        │ identity │ │ network  │ │  social  │  ... modulos osint
        └─────┬────┘ └────┬─────┘ └───┬──────┘
              │            │            │
              └────────────┼────────────┘
                           │
                    ┌──────▼──────┐
                    │ CORRELACION │  deduplicacion + fusion + scoring
                    └──────┬──────┘
                           │
              ┌────────────┼────────────┐
              │            │            │
        ┌─────▼────┐ ┌────▼─────┐ ┌───▼──────┐
        │PostgreSQL│ │  Neo4j   │ │  Elastic │  almacenamiento
        └──────────┘ └──────────┘ └──────────┘
                           │
                    ┌──────▼──────┐
                    │  REPORTES   │  pdf, html, stix, json, csv
                    └─────────────┘
```

---

## ⚖️ disclaimer legal

> **⚠️ IMPORTANTE: lee esto antes de usar sentinel**

esta herramienta esta disenada **exclusivamente** para:

- ✅ investigaciones de seguridad autorizadas (bug bounty, pentesting con contrato)
- ✅ investigacion academica y periodismo de investigacion
- ✅ equipos de threat intelligence corporativa sobre sus propios activos
- ✅ ejercicios de red team/blue team autorizados

**NO** uses esta herramienta para:

- ❌ espionaje, acoso o stalking
- ❌ acceso no autorizado a sistemas
- ❌ cualquier actividad ilegal
- ❌ recoleccion de datos sin consentimiento donde lo requiera la ley

**leyes aplicables que debes conocer:**
- 🇺🇸 CFAA (Computer Fraud and Abuse Act)
- 🇪🇺 GDPR (General Data Protection Regulation)
- 🇪🇸 LOPD (Ley Organica de Proteccion de Datos)
- leyes locales de tu jurisdiccion

*los autores (M-Society & c1q_) no se hacen responsables del mal uso de esta herramienta.*

---

## 🛠️ stack tecnologico

sentinel esta construido con un stack polyglot optimizado para cada tarea:

### backend principal — python 3.12

<p>
  <img src="https://img.shields.io/badge/FastAPI-009688?style=flat-square&logo=fastapi&logoColor=white" alt="FastAPI"/>
  <img src="https://img.shields.io/badge/SQLAlchemy_2.0-D71F00?style=flat-square&logo=sqlalchemy&logoColor=white" alt="SQLAlchemy"/>
  <img src="https://img.shields.io/badge/Pydantic_v2-E92063?style=flat-square&logo=pydantic&logoColor=white" alt="Pydantic"/>
  <img src="https://img.shields.io/badge/Celery-37814A?style=flat-square&logo=celery&logoColor=white" alt="Celery"/>
  <img src="https://img.shields.io/badge/httpx-async-blue?style=flat-square" alt="httpx"/>
</p>

| componente | tecnologia | proposito |
|-----------|-----------|----------|
| framework web | FastAPI + uvicorn | api rest async de alto rendimiento |
| http client | httpx (async) | todas las peticiones de red |
| scraping | beautifulsoup4, playwright | web scraping y headless browsing |
| network | scapy, python-nmap, dnspython | scanning y dns resolution |
| procesamiento | pandas, numpy, orjson | data processing y serialization |
| nlp | spacy, sentence-transformers | correlacion semantica |
| colas | celery + redis | ejecucion asincrona de tareas |
| orm | sqlalchemy 2.0 async + alembic | database + migrations |
| validacion | pydantic v2 | schemas y validacion de datos |
| auth | jose (jwt) + passlib (bcrypt) | autenticacion y autorizacion |
| reportes | weasyprint + jinja2 | generacion de pdf profesional |

### modulos de red — rust

<p>
  <img src="https://img.shields.io/badge/Tokio-async-orange?style=flat-square&logo=rust" alt="Tokio"/>
  <img src="https://img.shields.io/badge/Reqwest-HTTP-red?style=flat-square" alt="Reqwest"/>
  <img src="https://img.shields.io/badge/Rayon-parallel-green?style=flat-square" alt="Rayon"/>
</p>

| componente | proposito |
|-----------|----------|
| port_scanner.rs | tcp connect scan masivo con tokio (500+ conexiones concurrentes) |
| banner_grabber.rs | service banner grabbing con protocol probes |
| tls_fingerprint.rs | tls/ssl fingerprinting y handshake analysis |
| mass_resolver.rs | dns resolution masiva para subdomain enumeration |

los binarios rust se compilan independientemente y python los invoca via subprocess.

### microservicio de crawling — go 1.22

<p>
  <img src="https://img.shields.io/badge/Colly-crawler-00ADD8?style=flat-square&logo=go&logoColor=white" alt="Colly"/>
  <img src="https://img.shields.io/badge/Chi-router-purple?style=flat-square" alt="Chi"/>
  <img src="https://img.shields.io/badge/gRPC-protobuf-4285F4?style=flat-square&logo=google&logoColor=white" alt="gRPC"/>
</p>

| componente | proposito |
|-----------|----------|
| colly crawler | crawling de alta velocidad para webs, foros, paste sites |
| chi router | api http para control del crawler |
| grpc + protobuf | comunicacion con el core python |

### frontend — typescript + react 18

<p>
  <img src="https://img.shields.io/badge/React_18-61DAFB?style=flat-square&logo=react&logoColor=black" alt="React"/>
  <img src="https://img.shields.io/badge/Vite_5-646CFF?style=flat-square&logo=vite&logoColor=white" alt="Vite"/>
  <img src="https://img.shields.io/badge/Tailwind_CSS-06B6D4?style=flat-square&logo=tailwindcss&logoColor=white" alt="Tailwind"/>
  <img src="https://img.shields.io/badge/Sigma.js-graphs-ff6b6b?style=flat-square" alt="Sigma.js"/>
  <img src="https://img.shields.io/badge/Zustand-state-brown?style=flat-square" alt="Zustand"/>
</p>

| componente | proposito |
|-----------|----------|
| react 18 + vite 5 | ui framework + bundler |
| shadcn/ui + tailwind | componentes ui + styling |
| sigma.js + graphology | visualizacion interactiva de grafos |
| leaflet.js | mapas de geolocalizacion |
| tanstack table v8 | tablas de datos con filtros |
| recharts | graficas y charts |
| zustand | estado global |
| tanstack query v5 | data fetching y caching |

### bases de datos

<p>
  <img src="https://img.shields.io/badge/PostgreSQL_16-4169E1?style=flat-square&logo=postgresql&logoColor=white" alt="PostgreSQL"/>
  <img src="https://img.shields.io/badge/Redis_7-DC382D?style=flat-square&logo=redis&logoColor=white" alt="Redis"/>
  <img src="https://img.shields.io/badge/Elasticsearch_8-005571?style=flat-square&logo=elasticsearch&logoColor=white" alt="Elasticsearch"/>
  <img src="https://img.shields.io/badge/Neo4j_5-008CC1?style=flat-square&logo=neo4j&logoColor=white" alt="Neo4j"/>
</p>

| base de datos | proposito |
|--------------|----------|
| **postgresql 16** | almacenamiento principal: entidades, investigaciones, usuarios, auditoria |
| **redis 7** | cache, rate limiting, colas celery, sesiones jwt |
| **elasticsearch 8** | indexacion full-text de todo el contenido recolectado |
| **neo4j 5** | grafo de relaciones entre entidades (personas, dominios, ips, cuentas) |

### infraestructura

<p>
  <img src="https://img.shields.io/badge/Docker-2496ED?style=flat-square&logo=docker&logoColor=white" alt="Docker"/>
  <img src="https://img.shields.io/badge/Kubernetes-326CE5?style=flat-square&logo=kubernetes&logoColor=white" alt="Kubernetes"/>
  <img src="https://img.shields.io/badge/Nginx-009639?style=flat-square&logo=nginx&logoColor=white" alt="Nginx"/>
  <img src="https://img.shields.io/badge/Prometheus-E6522C?style=flat-square&logo=prometheus&logoColor=white" alt="Prometheus"/>
  <img src="https://img.shields.io/badge/Grafana-F46800?style=flat-square&logo=grafana&logoColor=white" alt="Grafana"/>
</p>

---

## 🏗️ arquitectura del sistema

```
sentinel/
├── core/                          # python — motor principal
│   ├── api/v1/                    # fastapi routers (auth, investigations, entities, modules, reports, feeds)
│   ├── modules/                   # modulos osint individuales
│   │   ├── identity/              # email, username, phone, person
│   │   ├── network/               # domain, ip, subdomain, ssl, asn
│   │   ├── social/                # github, linkedin, twitter, reddit, instagram
│   │   ├── breach/                # hibp, dehashed, paste monitoring
│   │   ├── darkweb/               # tor crawler, onion indexer
│   │   ├── threat/                # virustotal, mitre, ioc enrichment
│   │   ├── company/               # employees, jobs, subsidiaries, financial
│   │   ├── geo/                   # ip geolocation, image geolocation
│   │   └── metadata/              # exif, pdf, doc metadata
│   ├── engine/                    # motor de procesamiento
│   │   ├── pipeline.py            # orquestacion paralela de modulos
│   │   ├── correlation.py         # correlacion cross-module
│   │   ├── entity_resolver.py     # deduplicacion y fusion de entidades
│   │   ├── graph_builder.py       # construccion del grafo neo4j
│   │   └── scheduler.py           # scheduling de tareas
│   ├── models/                    # sqlalchemy models (8 tablas)
│   ├── schemas/                   # pydantic schemas
│   ├── auth/                      # jwt + rbac
│   ├── db/                        # database connections + migrations
│   ├── tasks/                     # celery tasks
│   └── utils/                     # rate limiter, proxy rotator, user agent rotator, tor controller
│
├── scanner/                       # rust — modulos de red de alta performance
│   └── src/                       # port_scanner, banner_grabber, tls_fingerprint, mass_resolver
│
├── crawler/                       # go — microservicio de crawling
│   ├── cmd/                       # main.go
│   └── proto/                     # protobuf definitions
│
├── reports/                       # generacion de reportes
│   ├── generator.py               # pdf, html, json, csv, stix 2.1
│   └── templates/                 # jinja2 templates
│
├── docker/                        # infraestructura
│   ├── docker-compose.yml         # desarrollo local (12 servicios)
│   ├── nginx/                     # reverse proxy config
│   ├── prometheus/                # metricas config
│   └── k8s/                       # kubernetes manifests
│
└── docs/                          # documentacion
```

### diagrama de arquitectura

```
┌──────────────────────────────────────────────────────────────────┐
│                        SENTINEL PLATFORM                         │
├──────────────────────────────────────────────────────────────────┤
│                                                                  │
│  ┌─────────┐    ┌──────────────────────────────────────────┐    │
│  │ FRONTEND│◄──►│           NGINX REVERSE PROXY            │    │
│  │ React   │    └─────────────────┬────────────────────────┘    │
│  │ Sigma.js│                      │                              │
│  │ Leaflet │    ┌─────────────────▼────────────────────────┐    │
│  └─────────┘    │          FASTAPI CORE (Python)           │    │
│                 │  ┌─────────────────────────────────┐     │    │
│                 │  │      API v1 ROUTERS              │     │    │
│                 │  │  auth | investigations | entities │     │    │
│                 │  │  modules | reports | feeds        │     │    │
│                 │  └──────────────┬──────────────────┘     │    │
│                 │                 │                          │    │
│                 │  ┌──────────────▼──────────────────┐     │    │
│                 │  │     PIPELINE ENGINE              │     │    │
│                 │  │  correlation | entity_resolver   │     │    │
│                 │  │  graph_builder | scheduler       │     │    │
│                 │  └──────────────┬──────────────────┘     │    │
│                 │                 │                          │    │
│                 │  ┌──────────────▼──────────────────┐     │    │
│                 │  │      OSINT MODULES (20+)        │     │    │
│                 │  │  identity | network | social    │     │    │
│                 │  │  breach | threat | company      │     │    │
│                 │  │  darkweb | geo | metadata       │     │    │
│                 │  └─────────────────────────────────┘     │    │
│                 └──────────────────────────────────────────┘    │
│                         │              │            │            │
│              ┌──────────▼──┐  ┌───────▼────┐  ┌───▼──────┐    │
│              │ GO CRAWLER  │  │RUST SCANNER │  │  CELERY  │    │
│              │ colly + grpc│  │tokio + rayon│  │ workers  │    │
│              └──────────┬──┘  └───────┬────┘  └───┬──────┘    │
│                         │             │            │            │
│  ┌──────────────────────▼─────────────▼────────────▼──────┐    │
│  │                   DATA LAYER                           │    │
│  │  ┌──────────┐ ┌───────┐ ┌──────────────┐ ┌────────┐  │    │
│  │  │PostgreSQL│ │ Redis │ │Elasticsearch │ │ Neo4j  │  │    │
│  │  │ entities │ │ cache │ │ full-text     │ │ graphs │  │    │
│  │  │ users    │ │ queue │ │ search        │ │ rels   │  │    │
│  │  │ audit    │ │ rate  │ │ indexing      │ │ algos  │  │    │
│  │  └──────────┘ └───────┘ └──────────────┘ └────────┘  │    │
│  └────────────────────────────────────────────────────────┘    │
│                                                                  │
│  ┌──────────────────────────────────────────────────────────┐  │
│  │                    MONITORING                             │  │
│  │        Prometheus  ──►  Grafana  (metricas + dashboards) │  │
│  └──────────────────────────────────────────────────────────┘  │
└──────────────────────────────────────────────────────────────────┘
```

---

## 🔮 modulos osint

### identity intelligence

| modulo | funcionalidades | apis usadas |
|--------|----------------|-------------|
| **email_intel** | validacion mx, smtp verification, gravatar lookup, github commits correlation | hibp, dehashed, hunter.io |
| **username_enum** | verificacion en +400 plataformas, bio extraction, activity tracking | status code + body heuristics |
| **phone_intel** | carrier identification, line type, country/region, whatsapp check | phonenumbers, truecaller-compatible |
| **person_search** | google dorks, linkedin scraping, timeline construction | nlp profile estimation |

### network intelligence

| modulo | funcionalidades | apis usadas |
|--------|----------------|-------------|
| **domain_intel** | whois completo, dns enumeration (12 record types), tech detection, screenshot | securitytrails, wappalyzer |
| **subdomain_enum** | passive ct + active bruteforce, permutations, zone transfer | crt.sh, censys, virustotal |
| **ip_intel** | ptr, asn, bgp, geolocation consensus, reputation, cloud detection | shodan, censys, abuseipdb |
| **ssl_intel** | certificate analysis, ja3 fingerprint, ct search, tls assessment | crt.sh, censys |
| **asn_bgp** | asn details, bgp prefixes, peer analysis | bgpview api |

### social media intelligence

| modulo | funcionalidades |
|--------|----------------|
| **github_intel** | profile, repos, secret scanning, commit emails, orgs, gists, starred repos |
| **linkedin_intel** | profile, work history, skills, employee search |
| **twitter_intel** | profile info, recent tweets, metadata |
| **reddit_intel** | profile, karma, subreddits, recent activity |
| **instagram_intel** | profile info, public posts metadata |

### breach, threat & dark web

| modulo | funcionalidades |
|--------|----------------|
| **hibp_client** | breach check, pwned passwords (k-anonymity), paste exposures |
| **dehashed_client** | credential leak search |
| **paste_monitor** | continuous monitoring de pastebin, gists, hastebin |
| **ioc_enricher** | multi-source ioc enrichment (vt, otx, malwarebazaar, urlhaus) |
| **mitre_mapper** | att&ck mapping, navigator layer generation, d3fend controls |
| **tor_crawler** | ⚠️ desactivado por defecto - onion search via ahmia, tor circuit rotation |

### company & metadata

| modulo | funcionalidades |
|--------|----------------|
| **employee_enum** | employee discovery via hunter.io + github orgs, email pattern inference |
| **job_intel** | job posting analysis, tech stack inference |
| **exif_extractor** | gps coords, camera info, edit detection, thumbnail extraction |
| **pdf_metadata** | author, org, software, creation dates, macro detection |

---

## 📦 instalacion

### requisitos previos

| requisito | version minima | notas |
|-----------|---------------|-------|
| **docker** | 24.0+ | `docker --version` |
| **docker compose** | 2.20+ | `docker compose version` |
| **git** | 2.30+ | `git --version` |
| **python** | 3.12+ | solo para instalacion manual |
| **rust** | 1.76+ | solo si compilas el scanner |
| **go** | 1.22+ | solo si compilas el crawler |
| **node.js** | 20+ | solo si ejecutas frontend manual |

### opcion 1: docker compose (recomendado)

este es el metodo mas simple y funciona en cualquier sistema con docker.

```bash
# 1. clonar el repositorio
git clone https://github.com/m-society/sentinel.git
cd sentinel

# 2. copiar y configurar variables de entorno
cp docker/.env.example docker/.env

# 3. editar .env con tus api keys (opcional pero recomendado)
nano docker/.env

# 4. levantar todos los servicios
cd docker
docker compose up -d

# 5. verificar que todo funcione
docker compose ps
curl http://localhost:8000/api/v1/health
```

**servicios que se levantan:**

| servicio | puerto | url |
|----------|--------|-----|
| sentinel core (api) | 8000 | http://localhost:8000/api/docs |
| frontend | 3000 | http://localhost:3000 |
| postgres | 5432 | localhost:5432 |
| redis | 6379 | localhost:6379 |
| elasticsearch | 9200 | http://localhost:9200 |
| neo4j browser | 7474 | http://localhost:7474 |
| neo4j bolt | 7687 | bolt://localhost:7687 |
| nginx (proxy) | 80 | http://localhost |
| prometheus | 9090 | http://localhost:9090 |
| grafana | 3001 | http://localhost:3001 |
| celery worker | - | (background workers) |
| celery beat | - | (scheduled tasks) |

### opcion 2: instalacion manual (linux)

para desarrollo local sin docker:

```bash
# 1. clonar
git clone https://github.com/m-society/sentinel.git
cd sentinel

# 2. crear entorno virtual python
python3.12 -m venv venv
source venv/bin/activate

# 3. instalar dependencias python
cd core
pip install --upgrade pip setuptools wheel
pip install -r requirements.txt

# 4. descargar modelos spacy
python -m spacy download es_core_news_sm
python -m spacy download en_core_web_sm

# 5. instalar playwright browsers
playwright install chromium

# 6. configurar env
cp ../docker/.env.example .env
# editar .env con tus valores

# 7. bases de datos (necesitas postgresql, redis, elasticsearch, neo4j corriendo)
# ver seccion "instalar dependencias del sistema" abajo

# 8. ejecutar migraciones
alembic upgrade head

# 9. iniciar el servidor
uvicorn main:app --host 0.0.0.0 --port 8000 --reload
```

#### instalar dependencias del sistema (linux)

```bash
# ubuntu / debian
sudo apt update
sudo apt install -y \
    python3.12 python3.12-venv python3.12-dev \
    build-essential libpq-dev libxml2-dev libxslt1-dev \
    libffi-dev libssl-dev nmap curl wget git \
    libcairo2 libpango-1.0-0 libpangocairo-1.0-0 \
    libgdk-pixbuf2.0-0 libffi-dev shared-mime-info

# fedora / rhel / centos
sudo dnf install -y \
    python3.12 python3-devel gcc gcc-c++ \
    libpq-devel libxml2-devel libxslt-devel \
    libffi-devel openssl-devel nmap curl wget git \
    cairo-devel pango-devel gdk-pixbuf2-devel

# arch linux
sudo pacman -S python python-pip gcc \
    libpqxx libxml2 libxslt nmap curl wget git \
    cairo pango gdk-pixbuf2
```

#### compilar el scanner (rust) - opcional

```bash
cd scanner
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
source $HOME/.cargo/env
cargo build --release

# los binarios quedan en scanner/target/release/
# port-scanner, banner-grabber, tls-fingerprint, mass-resolver
```

#### compilar el crawler (go) - opcional

```bash
cd crawler
# instalar go si no lo tienes
wget https://go.dev/dl/go1.22.0.linux-amd64.tar.gz
sudo tar -C /usr/local -xzf go1.22.0.linux-amd64.tar.gz
export PATH=$PATH:/usr/local/go/bin

go build -o sentinel-crawler ./cmd/main.go
./sentinel-crawler
```

---

## 🐧 solucion de problemas en linux

### pip install falla con "externally managed environment"

este error es comun en ubuntu 23.04+, debian 12+ y fedora 38+ por PEP 668:

```bash
# error: externally-managed-environment
# solucion 1: usar entorno virtual (RECOMENDADO)
python3.12 -m venv venv
source venv/bin/activate
pip install -r requirements.txt

# solucion 2: usar pipx para herramientas cli
pipx install sentinel

# solucion 3: forzar instalacion global (NO RECOMENDADO)
pip install --break-system-packages -r requirements.txt

# solucion 4: eliminar archivo EXTERNALLY-MANAGED (PELIGROSO)
# sudo rm /usr/lib/python3.12/EXTERNALLY-MANAGED
```

### error al instalar psycopg2-binary

```bash
# ubuntu / debian
sudo apt install -y libpq-dev python3-dev

# fedora
sudo dnf install -y libpq-devel python3-devel

# si sigue fallando, usa psycopg2-binary en lugar de psycopg2
pip install psycopg2-binary
```

### error con weasyprint en linux

weasyprint necesita librerias del sistema para generar pdf:

```bash
# ubuntu / debian
sudo apt install -y libcairo2 libpango-1.0-0 libpangocairo-1.0-0 \
    libgdk-pixbuf2.0-0 shared-mime-info

# fedora
sudo dnf install -y cairo pango gdk-pixbuf2

# arch
sudo pacman -S cairo pango gdk-pixbuf2
```

### error con lxml en linux

```bash
# ubuntu / debian
sudo apt install -y libxml2-dev libxslt1-dev

# fedora
sudo dnf install -y libxml2-devel libxslt-devel
```

### error "playwright not found"

```bash
# instalar playwright y sus browsers
pip install playwright
playwright install
# si falla por dependencias:
playwright install-deps
playwright install chromium
```

### error con permisos de nmap

```bash
# nmap necesita permisos root para ciertos scans
sudo setcap cap_net_raw,cap_net_admin=eip $(which nmap)
# o ejecutar sentinel con sudo (no recomendado)
```

### docker compose: elasticsearch falla con "max virtual memory areas vm.max_map_count"

```bash
# temporal (se pierde al reiniciar)
sudo sysctl -w vm.max_map_count=262144

# permanente
echo "vm.max_map_count=262144" | sudo tee -a /etc/sysctl.conf
sudo sysctl -p
```

### docker compose: neo4j no inicia

```bash
# verificar que los plugins esten disponibles
docker compose logs neo4j

# si falla por permisos de volumen
sudo chown -R 7474:7474 neo4j_data/
```

### python 3.12 no disponible en mi distro

```bash
# ubuntu
sudo add-apt-repository ppa:deadsnakes/ppa
sudo apt update
sudo apt install python3.12 python3.12-venv python3.12-dev

# fedora
sudo dnf install python3.12

# cualquier distro (compilar desde fuente)
wget https://www.python.org/ftp/python/3.12.2/Python-3.12.2.tgz
tar xzf Python-3.12.2.tgz
cd Python-3.12.2
./configure --enable-optimizations
make -j$(nproc)
sudo make altinstall
```

---

## ⚙️ configuracion

### variables de entorno

copia `docker/.env.example` como `.env` y configura:

```env
# --- passwords de servicios (cambiar en produccion!) ---
POSTGRES_PASSWORD=tu_password_seguro
REDIS_PASSWORD=tu_password_seguro
NEO4J_PASSWORD=tu_password_seguro
SECRET_KEY=una_clave_secreta_larga_y_aleatoria
GRAFANA_PASSWORD=tu_password_seguro

# --- api keys externas (configurar segun necesidad) ---
SHODAN_API_KEY=tu_key_de_shodan
VIRUSTOTAL_API_KEY=tu_key_de_virustotal
SECURITYTRAILS_API_KEY=tu_key
HUNTER_API_KEY=tu_key_de_hunter
HIBP_API_KEY=tu_key_de_haveibeenpwned
CLEARBIT_API_KEY=tu_key
IPINFO_TOKEN=tu_token
ABUSEIPDB_API_KEY=tu_key
URLSCAN_API_KEY=tu_key
FULLHUNT_API_KEY=tu_key
INTELX_API_KEY=tu_key
DEHASHED_API_KEY=tu_key
CENSYS_API_ID=tu_id
CENSYS_API_SECRET=tu_secret
```

### donde obtener api keys

| servicio | url | tier gratuito |
|----------|-----|--------------|
| shodan | https://shodan.io | ✅ limitado |
| virustotal | https://virustotal.com | ✅ 4 req/min |
| securitytrails | https://securitytrails.com | ✅ 50 req/mes |
| hunter.io | https://hunter.io | ✅ 25 req/mes |
| haveibeenpwned | https://haveibeenpwned.com/API | ❌ $3.50/mes |
| clearbit | https://clearbit.com | ✅ limitado |
| ipinfo.io | https://ipinfo.io | ✅ 50k req/mes |
| abuseipdb | https://abuseipdb.com | ✅ 1000 req/dia |
| urlscan.io | https://urlscan.io | ✅ 5000 req/dia |
| censys | https://search.censys.io | ✅ 250 req/mes |

> **nota:** sentinel funciona sin api keys pero con funcionalidad reducida. los modulos que requieren api key desactivada se saltan automaticamente.

---

## 🚀 uso basico

### 1. crear un usuario

```bash
# via api
curl -X POST http://localhost:8000/api/v1/auth/register \
  -H "Content-Type: application/json" \
  -d '{
    "nombre_usuario": "analista1",
    "email": "analista@sentinel.local",
    "password": "password_seguro_123",
    "nombre_completo": "analista de seguridad"
  }'
```

### 2. obtener token jwt

```bash
curl -X POST http://localhost:8000/api/v1/auth/login \
  -H "Content-Type: application/json" \
  -d '{
    "nombre_usuario": "analista1",
    "password": "password_seguro_123"
  }'

# respuesta:
# {
#   "access_token": "eyJ...",
#   "refresh_token": "eyJ...",
#   "token_type": "bearer"
# }
```

### 3. crear una investigacion

```bash
export TOKEN="tu_access_token"

curl -X POST http://localhost:8000/api/v1/investigations \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer $TOKEN" \
  -d '{
    "nombre": "investigacion-empresa-xyz",
    "descripcion": "assessment de seguridad autorizado para empresa xyz",
    "proposito": "bug bounty autorizado",
    "semillas": [
      {"tipo": "domain", "valor": "ejemplo.com"},
      {"tipo": "email", "valor": "admin@ejemplo.com"}
    ],
    "profundidad_maxima": 2,
    "presupuesto_api": 500
  }'
```

### 4. ejecutar modulos

```bash
# ejecutar un modulo especifico
curl -X POST http://localhost:8000/api/v1/modules/execute \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer $TOKEN" \
  -d '{
    "investigacion_id": "uuid-de-la-investigacion",
    "modulo": "email_intel",
    "objetivo": "admin@ejemplo.com"
  }'

# ejecutar pipeline completa
curl -X POST http://localhost:8000/api/v1/investigations/{id}/run \
  -H "Authorization: Bearer $TOKEN"
```

### 5. ver resultados

```bash
# listar entidades descubiertas
curl http://localhost:8000/api/v1/entities?investigacion_id=UUID \
  -H "Authorization: Bearer $TOKEN"

# descargar grafo
curl http://localhost:8000/api/v1/investigations/{id}/graph \
  -H "Authorization: Bearer $TOKEN"

# generar reporte
curl -X POST http://localhost:8000/api/v1/reports/generate \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer $TOKEN" \
  -d '{"investigacion_id": "UUID", "formato": "pdf"}'
```

---

## 📡 api reference

la documentacion interactiva de la api esta disponible en:

- **swagger ui:** http://localhost:8000/api/docs
- **redoc:** http://localhost:8000/api/redoc
- **openapi json:** http://localhost:8000/api/openapi.json

### endpoints principales

| metodo | endpoint | descripcion |
|--------|----------|-------------|
| `POST` | `/api/v1/auth/register` | registrar nuevo usuario |
| `POST` | `/api/v1/auth/login` | login y obtener jwt |
| `POST` | `/api/v1/auth/refresh` | refrescar token |
| `GET` | `/api/v1/health` | health check |
| `GET` | `/api/v1/info` | informacion del sistema |
| | | |
| `POST` | `/api/v1/investigations` | crear investigacion |
| `GET` | `/api/v1/investigations` | listar investigaciones |
| `GET` | `/api/v1/investigations/{id}` | detalle de investigacion |
| `POST` | `/api/v1/investigations/{id}/run` | ejecutar pipeline |
| `PUT` | `/api/v1/investigations/{id}/pause` | pausar investigacion |
| | | |
| `GET` | `/api/v1/entities` | listar entidades |
| `GET` | `/api/v1/entities/{id}` | detalle de entidad |
| `GET` | `/api/v1/entities/search` | buscar entidades |
| | | |
| `GET` | `/api/v1/modules` | listar modulos disponibles |
| `POST` | `/api/v1/modules/execute` | ejecutar modulo individual |
| | | |
| `POST` | `/api/v1/reports/generate` | generar reporte |
| `GET` | `/api/v1/reports` | listar reportes |
| `GET` | `/api/v1/reports/{id}/download` | descargar reporte |
| | | |
| `GET` | `/api/v1/feeds` | threat feeds configurados |
| `POST` | `/api/v1/feeds` | agregar feed |

---

## 💡 ejemplos de uso

### ejemplo 1: investigacion de email

```python
import httpx
import asyncio

async def investigar_email():
    async with httpx.AsyncClient(base_url="http://localhost:8000") as client:
        # login
        login = await client.post("/api/v1/auth/login", json={
            "nombre_usuario": "analista1",
            "password": "mi_password"
        })
        token = login.json()["access_token"]
        headers = {"Authorization": f"Bearer {token}"}

        # crear investigacion
        inv = await client.post("/api/v1/investigations", headers=headers, json={
            "nombre": "analisis-email-target",
            "descripcion": "investigacion autorizada de email",
            "proposito": "security assessment",
            "semillas": [{"tipo": "email", "valor": "target@empresa.com"}],
        })
        inv_id = inv.json()["id"]

        # ejecutar modulo de email
        resultado = await client.post("/api/v1/modules/execute", headers=headers, json={
            "investigacion_id": inv_id,
            "modulo": "email_intel",
            "objetivo": "target@empresa.com",
        })

        print(resultado.json())

asyncio.run(investigar_email())
```

### ejemplo 2: enumeracion de dominio completo

```bash
# 1. crear investigacion con dominio como semilla
curl -X POST http://localhost:8000/api/v1/investigations \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "nombre": "recon-empresa-xyz",
    "semillas": [{"tipo": "domain", "valor": "empresa-xyz.com"}],
    "profundidad_maxima": 3
  }'

# 2. ejecutar modulos de red en paralelo
for modulo in domain_intel subdomain_enum ssl_intel; do
  curl -X POST http://localhost:8000/api/v1/modules/execute \
    -H "Authorization: Bearer $TOKEN" \
    -H "Content-Type: application/json" \
    -d "{
      \"investigacion_id\": \"$INV_ID\",
      \"modulo\": \"$modulo\",
      \"objetivo\": \"empresa-xyz.com\"
    }" &
done
wait

# 3. generar reporte final
curl -X POST http://localhost:8000/api/v1/reports/generate \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d "{\"investigacion_id\": \"$INV_ID\", \"formato\": \"pdf\"}"
```

### ejemplo 3: uso del scanner rust

```bash
# port scan masivo
./scanner/target/release/port-scanner --target 192.168.1.1 --ports 1-65535 --concurrency 1000

# banner grabbing de puertos abiertos
./scanner/target/release/banner-grabber --target 192.168.1.1 --ports 22,80,443,3306,8080

# resolver subdominios masivamente
cat subdominios.txt | ./scanner/target/release/mass-resolver --concurrency 500
```

### ejemplo 4: uso del crawler go

```bash
# crawl de un sitio web
curl -X POST http://localhost:8081/api/v1/crawl \
  -H "Content-Type: application/json" \
  -d '{
    "urls": ["https://blog.empresa.com"],
    "profundidad": 3,
    "max_paginas": 100,
    "buscar_emails": true,
    "delay_ms": 500
  }'
```

---

## 📊 generacion de reportes

sentinel genera reportes en 5 formatos:

| formato | uso | extension |
|---------|-----|-----------|
| **pdf** | reporte ejecutivo con portada profesional, grafos, tablas, timeline | `.pdf` |
| **html** | reporte interactivo con grafo navegable embebido | `.html` |
| **json** | integracion con herramientas (MISP, TheHive, Maltego) | `.json` |
| **csv** | exportar entidades por tipo para analisis en excel | `.csv` |
| **stix 2.1** | intercambio estandar de threat intelligence | `.json` (stix bundle) |

### contenido del reporte

- portada profesional (dark theme)
- disclaimer legal
- resumen ejecutivo con estadisticas
- entidades descubiertas con score de confianza
- grafo de relaciones (exportado como imagen en pdf, interactivo en html)
- tabla de iocs con nivel de confianza
- modulos ejecutados con duracion
- metadata de la investigacion

---

## 🔒 seguridad

### autenticacion y autorizacion

| feature | implementacion |
|---------|---------------|
| passwords | bcrypt hashing |
| tokens | jwt con access token (60 min) + refresh token (7 dias) |
| roles | rbac: admin, analyst, viewer |
| audit log | cada accion registrada con usuario, timestamp, ip |
| encryption | aes-256 para datos sensibles en postgres |
| api keys | via variables de entorno, nunca en codigo |

### roles y permisos

| rol | permisos |
|-----|----------|
| **admin** | todo: crear usuarios, configurar apis, eliminar datos |
| **analyst** | crear/ejecutar investigaciones, generar reportes |
| **viewer** | solo lectura: ver investigaciones y reportes existentes |

---

## 🤝 contribuir

ver [CONTRIBUTING.md](CONTRIBUTING.md) para guias detalladas.

```bash
# fork + clone
git clone https://github.com/TU-USUARIO/sentinel.git
cd sentinel
git checkout -b feature/mi-feature

# hacer cambios...

# tests
cd core
pytest --cov=. --cov-report=term-missing

# commit + push + pr
git add .
git commit -m "feat: agregar mi feature"
git push origin feature/mi-feature
# crear pull request en github
```

---

## 📝 creditos

<table>
  <tr>
    <td align="center">
      <strong>M-Society</strong>
      <br/>
      <em>organizacion</em>
      <br/>
      <a href="https://discord.gg/9QRngbrMKS">github</a>
    </td>
    <td align="center">
      <strong>c1q_</strong>
      <br/>
      <em>lead developer</em>
      <br/>
      <a href="">github</a>
    </td>
  </tr>
</table>

### tecnologias y agradecimientos

este proyecto utiliza y agradece a los creadores de:

- [FastAPI](https://fastapi.tiangolo.com/) - framework web moderno para python
- [SQLAlchemy](https://www.sqlalchemy.org/) - orm para python
- [Celery](https://docs.celeryq.dev/) - colas de tareas distribuidas
- [Tokio](https://tokio.rs/) - runtime async para rust
- [Colly](http://go-colly.org/) - framework de crawling para go
- [React](https://react.dev/) - ui library
- [Sigma.js](https://www.sigmajs.org/) - visualizacion de grafos
- [Neo4j](https://neo4j.com/) - base de datos de grafos
- [PostgreSQL](https://www.postgresql.org/) - base de datos relacional
- [Elasticsearch](https://www.elastic.co/) - busqueda full-text
- [Redis](https://redis.io/) - cache y message broker
- [Docker](https://www.docker.com/) - containerization
- [Prometheus](https://prometheus.io/) + [Grafana](https://grafana.com/) - monitoring

### inspiracion

sentinel se inspira en herramientas como:
- [Maltego](https://www.maltego.com/)
- [SpiderFoot](https://www.spiderfoot.net/)
- [theHarvester](https://github.com/laramies/theHarvester)
- [Recon-ng](https://github.com/lanmaster53/recon-ng)
- [Sherlock](https://github.com/sherlock-project/sherlock)

la diferencia: sentinel unifica todas estas capacidades en una sola plataforma con correlacion automatica, grafos de relaciones y reportes profesionales.

---

<p align="center">
  <strong>⚠️ usa esta herramienta de forma responsable y legal ⚠️</strong>
</p>

<p align="center">
  <em>SENTINEL v1.0.0 — M-Society & c1q_</em>
  <br/>
  <em>plataforma osint enterprise de fuentes abiertas</em>
</p>

<p align="center">
  <img src="https://img.shields.io/badge/made_with-❤️-ff69b4?style=flat-square" alt="Made with love"/>
  <img src="https://img.shields.io/badge/by-M--Society_&_c1q__-6c5ce7?style=flat-square" alt="By"/>
</p>
