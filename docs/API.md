# SENTINEL - API Reference Completa

## Base URL
```
http://localhost:8000/api/v1
```

## Autenticacion

todos los endpoints (excepto auth y health) requieren header:
```
Authorization: Bearer <access_token>
```

---

## Auth

### POST /auth/register
registra un nuevo usuario.

**body:**
```json
{
  "nombre_usuario": "string (min 3 chars)",
  "email": "string (email valido)",
  "password": "string (min 8 chars)",
  "nombre_completo": "string"
}
```

**response 201:**
```json
{
  "id": "uuid",
  "nombre_usuario": "analista1",
  "email": "analista@sentinel.local",
  "rol": "analyst",
  "activo": true
}
```

### POST /auth/login
obtiene access y refresh token.

**body:**
```json
{
  "nombre_usuario": "string",
  "password": "string"
}
```

**response 200:**
```json
{
  "access_token": "eyJ...",
  "refresh_token": "eyJ...",
  "token_type": "bearer",
  "expira_en": 3600
}
```

### POST /auth/refresh
renueva un access token usando el refresh token.

**body:**
```json
{
  "refresh_token": "eyJ..."
}
```

---

## Investigations

### POST /investigations
crea una nueva investigacion.

**body:**
```json
{
  "nombre": "string",
  "descripcion": "string",
  "proposito": "string (requerido para auditoria)",
  "semillas": [
    {"tipo": "email|domain|ip|username|phone|person", "valor": "string"}
  ],
  "profundidad_maxima": 2,
  "presupuesto_api": 500,
  "configuracion_modulos": {
    "email_intel": true,
    "domain_intel": true,
    "tor_crawler": false
  }
}
```

### GET /investigations
lista todas las investigaciones del usuario.

**query params:**
- `estado`: active|paused|completed|archived
- `pagina`: int (default 1)
- `por_pagina`: int (default 20)

### GET /investigations/{id}
detalle de una investigacion con estadisticas.

### POST /investigations/{id}/run
ejecuta la pipeline completa de la investigacion.

### PUT /investigations/{id}/pause
pausa la ejecucion de la investigacion.

### DELETE /investigations/{id}
archiva una investigacion (soft delete).

---

## Entities

### GET /entities
lista entidades descubiertas.

**query params:**
- `investigacion_id`: uuid (requerido)
- `tipo`: person|email|username|phone|domain|ip|organization|social_profile|credential|hash|document|location
- `confianza_min`: float (0.0-1.0)
- `buscar`: string (full text search)
- `pagina`: int
- `por_pagina`: int

### GET /entities/{id}
detalle de una entidad con todas sus relaciones.

### GET /entities/search
busqueda avanzada de entidades.

---

## Modules

### GET /modules
lista todos los modulos osint disponibles con su estado.

**response:**
```json
{
  "modulos": [
    {
      "nombre": "email_intel",
      "categoria": "identity",
      "descripcion": "inteligencia de email",
      "requiere_api_key": true,
      "api_key_configurada": true,
      "habilitado": true
    }
  ],
  "total": 20
}
```

### POST /modules/execute
ejecuta un modulo individual.

**body:**
```json
{
  "investigacion_id": "uuid",
  "modulo": "email_intel",
  "objetivo": "target@example.com",
  "parametros": {}
}
```

---

## Reports

### POST /reports/generate
genera un reporte de investigacion.

**body:**
```json
{
  "investigacion_id": "uuid",
  "formato": "pdf|html|json|csv|stix"
}
```

### GET /reports
lista reportes generados.

### GET /reports/{id}/download
descarga un reporte generado.

---

## Feeds

### GET /feeds
lista threat feeds configurados.

### POST /feeds
agrega un nuevo threat feed.

**body:**
```json
{
  "nombre": "string",
  "url": "string",
  "tipo": "stix|csv|json",
  "intervalo_minutos": 60
}
```

---

## Health & Info

### GET /health
```json
{
  "estado": "operativo",
  "version": "1.0.0",
  "nombre": "SENTINEL",
  "autor": "c1q_ (M-Society team)"
}
```

### GET /info
informacion general del sistema.

### GET /metrics
metricas prometheus.

---

## Codigos de Error

| codigo | significado |
|--------|-------------|
| 400 | request invalido |
| 401 | no autenticado o token expirado |
| 403 | no autorizado (rol insuficiente) |
| 404 | recurso no encontrado |
| 429 | rate limit excedido |
| 500 | error interno del servidor |

---

*SENTINEL v1.0.0 - Developed by c1q_ for M-Society team*
