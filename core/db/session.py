# sentinel - sesion de base de datos async
# m-society & c1q_

from sqlalchemy.ext.asyncio import create_async_engine, AsyncSession, async_sessionmaker
from sqlalchemy.orm import DeclarativeBase

from config import config


# motor async de sqlalchemy
motor = create_async_engine(
    config.database_url,
    echo=config.database_echo,
    pool_size=20,
    max_overflow=10,
    pool_pre_ping=True,
)

# fabrica de sesiones
fabrica_sesion = async_sessionmaker(
    motor,
    class_=AsyncSession,
    expire_on_commit=False,
)


class Base(DeclarativeBase):
    pass


async def obtener_sesion():
    """generador de sesiones para inyeccion de dependencias en fastapi"""
    async with fabrica_sesion() as sesion:
        try:
            yield sesion
            await sesion.commit()
        except Exception:
            await sesion.rollback()
            raise
        finally:
            await sesion.close()


async def inicializar_db():
    """crea todas las tablas si no existen"""
    async with motor.begin() as conexion:
        await conexion.run_sync(Base.metadata.create_all)


async def cerrar_db():
    """cierra el pool de conexiones"""
    await motor.dispose()
