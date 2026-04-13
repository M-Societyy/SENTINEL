# sentinel - configuracion central
# c1q_ (M-Society team)

from pydantic_settings import BaseSettings
from typing import Optional


class Configuracion(BaseSettings):
    # general
    nombre_app: str = "SENTINEL"
    version: str = "1.0.0"
    ambiente: str = "development"
    debug: bool = True

    # base de datos
    database_url: str = "postgresql+asyncpg://sentinel:sentinel_dev_2024@localhost:5432/sentinel"
    database_echo: bool = False

    # redis
    redis_url: str = "redis://:sentinel_redis_2024@localhost:6379/0"

    # elasticsearch
    elasticsearch_url: str = "http://localhost:9200"

    # neo4j
    neo4j_uri: str = "bolt://localhost:7687"
    neo4j_user: str = "neo4j"
    neo4j_password: str = "sentinel_neo4j_2024"

    # auth jwt
    secret_key: str = "sentinel_secret_key_cambiar_en_produccion"
    algoritmo_jwt: str = "HS256"
    expiracion_token_minutos: int = 60
    expiracion_refresh_dias: int = 7

    # rate limiting
    rate_limit_global: int = 100
    rate_limit_ventana_segundos: int = 60

    # proxy
    proxy_lista: list[str] = []
    tor_socks_proxy: str = "socks5://127.0.0.1:9050"
    tor_control_port: int = 9051
    tor_control_password: str = ""

    # api keys externas
    shodan_api_key: Optional[str] = None
    virustotal_api_key: Optional[str] = None
    securitytrails_api_key: Optional[str] = None
    hunter_api_key: Optional[str] = None
    hibp_api_key: Optional[str] = None
    clearbit_api_key: Optional[str] = None
    ipinfo_token: Optional[str] = None
    abuseipdb_api_key: Optional[str] = None
    urlscan_api_key: Optional[str] = None
    fullhunt_api_key: Optional[str] = None
    intelx_api_key: Optional[str] = None
    dehashed_api_key: Optional[str] = None
    censys_api_id: Optional[str] = None
    censys_api_secret: Optional[str] = None

    # crawler go
    crawler_grpc_host: str = "localhost"
    crawler_grpc_port: int = 50051

    # encriptacion
    clave_encriptacion: str = "sentinel_encryption_key_32bytes!"

    model_config = {
        "env_file": ".env",
        "env_file_encoding": "utf-8",
        "case_sensitive": False,
    }


config = Configuracion()
