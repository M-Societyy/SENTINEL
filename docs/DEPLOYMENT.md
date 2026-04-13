# SENTINEL - Guia de Despliegue en Produccion

## Pre-requisitos

- servidor linux (ubuntu 22.04+ recomendado)
- docker 24+ con docker compose 2.20+
- minimo 8gb ram, 4 vcpu, 100gb ssd
- dominio con certificado ssl/tls
- firewall configurado

## 1. Preparar el Servidor

```bash
# actualizar sistema
sudo apt update && sudo apt upgrade -y

# instalar docker
curl -fsSL https://get.docker.com | sh
sudo usermod -aG docker $USER

# configurar sysctl para elasticsearch
echo "vm.max_map_count=262144" | sudo tee -a /etc/sysctl.conf
sudo sysctl -p

# configurar firewall
sudo ufw allow 80/tcp
sudo ufw allow 443/tcp
sudo ufw enable
```

## 2. Configurar Produccion

```bash
# clonar repositorio
git clone https://github.com/M-Societyy/SENTINEL.git
cd SENTINEL/docker

# crear .env de produccion
cp .env.example .env.production

# IMPORTANTE: cambiar TODAS las passwords
# usar passwords fuertes y unicos
nano .env.production
```

### variables criticas para produccion:

```env
POSTGRES_PASSWORD=<password_fuerte_aleatorio>
REDIS_PASSWORD=<password_fuerte_aleatorio>
NEO4J_PASSWORD=<password_fuerte_aleatorio>
SECRET_KEY=<clave_de_64_caracteres_aleatoria>
GRAFANA_PASSWORD=<password_fuerte>
ENVIRONMENT=production
```

## 3. Desplegar con Docker Compose

```bash
docker compose -f docker-compose.yml --env-file .env.production up -d
```

## 4. Configurar TLS con Certbot

```bash
sudo apt install certbot
sudo certbot certonly --standalone -d sentinel.tudominio.com

# agregar certificados al nginx config
```

## 5. Backups Automaticos

```bash
# backup diario de postgres
0 2 * * * docker exec sentinel-postgres pg_dump -U sentinel sentinel | gzip > /backups/sentinel_$(date +\%Y\%m\%d).sql.gz

# backup de neo4j
0 3 * * * docker exec sentinel-neo4j neo4j-admin database dump neo4j --to-path=/backups/
```

## 6. Monitoreo

- prometheus: http://tu-servidor:9090
- grafana: http://tu-servidor:3001 (password configurado en .env)
- health check: http://tu-servidor:8000/api/v1/health

## 7. Kubernetes (Opcional)

si prefieres kubernetes para alta disponibilidad:

```bash
kubectl create namespace sentinel
kubectl apply -f docker/k8s/deployment.yaml
```

---

## Checklist de Seguridad para Produccion

- [ ] passwords fuertes y unicos en todas las db
- [ ] secret_key aleatorio (no el default)
- [ ] tls/ssl habilitado (certificados validos)
- [ ] firewall configurado (solo puertos 80, 443)
- [ ] api keys en variables de entorno (nunca en codigo)
- [ ] backups automaticos configurados
- [ ] monitoreo activo con prometheus/grafana
- [ ] logs de auditoria habilitados
- [ ] rate limiting configurado

---
*SENTINEL v1.0.0 - Developed by c1q_ for M-Society team*
