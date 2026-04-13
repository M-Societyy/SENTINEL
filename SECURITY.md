# Security Policy - SENTINEL

## versiones soportadas

| version | soporte |
|---------|---------|
| 1.0.x | soportada |
| < 1.0 | no soportada |

## reportar vulnerabilidades

si encuentras una vulnerabilidad de seguridad en sentinel:

1. **NO** abras un issue publico
2. envia un mensaje de discord al servidor https://discord.gg/9QRngbrMKS
3. incluye: descripcion, pasos para reproducir, impacto, sugerencia de fix

respondemos dentro de 48 horas.

## buenas practicas

### para operadores
- nunca uses sentinel sin autorizacion
- cambia todas las passwords por defecto
- configura api keys via variables de entorno
- usa tls en produccion
- revisa audit logs regularmente
- usa rbac (roles: admin, analyst, viewer)

### para desarrolladores
- nunca commits con credenciales
- bcrypt para hashing de passwords
- valida todo input con pydantic
- rate limiting en endpoints
- jwt con expiracion corta
- aes-256 para datos sensibles

---
m-society & c1q_
