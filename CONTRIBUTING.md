# Contributing to SENTINEL

gracias por tu interes en contribuir a sentinel!

## codigo de conducta
- se respetuoso con otros contribuidores
- usa esta herramienta solo para fines legales y autorizados
- no incluyas credenciales ni api keys en commits

## como contribuir

### reportar bugs
1. verifica que el bug no haya sido reportado en issues
2. crea un issue con pasos para reproducir, comportamiento esperado vs actual, logs

### pull requests
1. fork el repositorio
2. crea branch descriptiva: `feature/nuevo-modulo` o `fix/error-en-scan`
3. sigue los estandares de codigo:
   - type hints completos en python
   - docstrings en funciones publicas
   - tests unitarios para cada modulo nuevo
   - comentarios en minusculas, sin acentos
4. ejecuta tests: `pytest --cov=. --cov-report=term-missing`
5. envia el pr contra la branch `develop`

### estandares
- **python:** pep 8, max 120 chars, type hints, structlog, pydantic
- **rust:** `cargo fmt` y `cargo clippy`
- **go:** `go fmt` y `go vet`
- **typescript:** eslint + prettier

### commits
```
feat: agregar modulo de whois historico
fix: corregir rate limiting en github intel
docs: actualizar seccion de instalacion
test: agregar tests para email_intel
```

---
m-society & c1q_ - sentinel v1.0.0
