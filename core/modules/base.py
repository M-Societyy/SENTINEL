# sentinel - clase base para todos los modulos osint
# c1q_ (M-Society team)

import time
import asyncio
from abc import ABC, abstractmethod
from typing import Optional
from uuid import UUID

import httpx
import structlog

from config import config
from utils.rate_limiter import obtener_limitador
from utils.proxy_rotator import rotador_proxies
from utils.user_agent_rotator import obtener_headers_completos, obtener_headers_api
from schemas.modulos import ResultadoEnriquecimiento

log = structlog.get_logger()


class ModuloBase(ABC):
    """clase base que todos los modulos osint deben heredar"""

    nombre: str = "base"
    categoria: str = "general"
    descripcion: str = ""
    requiere_api_key: bool = False

    def __init__(self):
        self._cliente_http: Optional[httpx.AsyncClient] = None
        self._inicio = 0.0
        self._entidades_encontradas = 0
        self._relaciones_creadas = 0
        self._errores: list[str] = []

    async def obtener_cliente(self) -> httpx.AsyncClient:
        """retorna un cliente http reutilizable con proxy y headers"""
        if self._cliente_http is None or self._cliente_http.is_closed:
            proxies = rotador_proxies.obtener_httpx_proxies()
            self._cliente_http = httpx.AsyncClient(
                timeout=httpx.Timeout(30.0, connect=10.0),
                follow_redirects=True,
                proxies=proxies,
                headers=obtener_headers_completos(),
            )
        return self._cliente_http

    async def request_con_rate_limit(
        self,
        url: str,
        servicio: str = "default",
        metodo: str = "GET",
        headers: dict = None,
        params: dict = None,
        json_data: dict = None,
        timeout: float = 30.0,
    ) -> Optional[httpx.Response]:
        """hace una peticion http respetando rate limits"""
        limitador = obtener_limitador(servicio)
        await limitador.esperar_turno()

        cliente = await self.obtener_cliente()
        try:
            if metodo.upper() == "GET":
                resp = await cliente.get(url, headers=headers, params=params, timeout=timeout)
            elif metodo.upper() == "POST":
                resp = await cliente.post(url, headers=headers, params=params, json=json_data, timeout=timeout)
            else:
                resp = await cliente.request(metodo, url, headers=headers, params=params, timeout=timeout)

            # si nos bloquean, marcar proxy y reintentar
            if resp.status_code in (403, 429):
                proxy_actual = rotador_proxies.siguiente()
                if proxy_actual:
                    rotador_proxies.marcar_bloqueado(proxy_actual)
                log.warning("rate limited o bloqueado", url=url, status=resp.status_code, modulo=self.nombre)

                # respetar retry-after
                retry_after = resp.headers.get("Retry-After")
                if retry_after:
                    await asyncio.sleep(min(int(retry_after), 120))

                return None

            return resp

        except httpx.TimeoutException:
            log.warning("timeout en request", url=url, modulo=self.nombre)
            self._errores.append(f"timeout: {url}")
            return None
        except httpx.ConnectError as e:
            log.warning("error de conexion", url=url, error=str(e), modulo=self.nombre)
            self._errores.append(f"conexion fallida: {url}")
            return None
        except Exception as e:
            log.error("error inesperado en request", url=url, error=str(e), modulo=self.nombre)
            self._errores.append(f"error: {url} - {str(e)}")
            return None

    @abstractmethod
    async def ejecutar(self, objetivo: str, parametros: dict = None) -> ResultadoEnriquecimiento:
        """metodo principal que cada modulo debe implementar"""
        pass

    async def run(self, objetivo: str, parametros: dict = None) -> ResultadoEnriquecimiento:
        """wrapper que mide tiempo y maneja errores globales"""
        self._inicio = time.time()
        self._entidades_encontradas = 0
        self._relaciones_creadas = 0
        self._errores = []

        log.info("modulo iniciado", modulo=self.nombre, objetivo=objetivo)

        try:
            resultado = await self.ejecutar(objetivo, parametros or {})
            duracion = time.time() - self._inicio
            log.info(
                "modulo completado",
                modulo=self.nombre,
                objetivo=objetivo,
                duracion=f"{duracion:.2f}s",
                entidades=self._entidades_encontradas,
            )
            return resultado
        except Exception as e:
            duracion = time.time() - self._inicio
            log.error("modulo fallo", modulo=self.nombre, objetivo=objetivo, error=str(e), duracion=f"{duracion:.2f}s")
            return ResultadoEnriquecimiento(
                fuente=self.nombre,
                tipo="error",
                error=str(e),
                confianza=0.0,
            )
        finally:
            if self._cliente_http and not self._cliente_http.is_closed:
                await self._cliente_http.aclose()

    async def cerrar(self):
        """cierra recursos del modulo"""
        if self._cliente_http and not self._cliente_http.is_closed:
            await self._cliente_http.aclose()
