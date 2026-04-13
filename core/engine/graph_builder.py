# sentinel - constructor del grafo neo4j
# c1q_ (M-Society team)

import uuid
from typing import Optional

from neo4j import AsyncGraphDatabase
import structlog

from config import config

log = structlog.get_logger()


class ConstructorGrafo:
    """gestiona el grafo de relaciones en neo4j"""

    def __init__(self):
        self._driver = None

    async def conectar(self):
        """establece conexion con neo4j"""
        try:
            self._driver = AsyncGraphDatabase.driver(
                config.neo4j_uri,
                auth=(config.neo4j_user, config.neo4j_password),
            )
            log.info("neo4j conectado", uri=config.neo4j_uri)
        except Exception as e:
            log.error("error conectando neo4j", error=str(e))
            self._driver = None

    async def cerrar(self):
        """cierra la conexion"""
        if self._driver:
            await self._driver.close()

    async def inicializar_indices(self):
        """crea indices y constraints en neo4j"""
        if not self._driver:
            await self.conectar()
        if not self._driver:
            return

        queries = [
            "CREATE INDEX IF NOT EXISTS FOR (e:Entidad) ON (e.valor)",
            "CREATE INDEX IF NOT EXISTS FOR (e:Entidad) ON (e.tipo)",
            "CREATE INDEX IF NOT EXISTS FOR (e:Entidad) ON (e.investigacion_id)",
            "CREATE CONSTRAINT IF NOT EXISTS FOR (e:Entidad) REQUIRE (e.uid) IS UNIQUE",
        ]

        async with self._driver.session() as sesion:
            for q in queries:
                try:
                    await sesion.run(q)
                except Exception as e:
                    log.debug("error creando indice neo4j", error=str(e))

    async def agregar_entidad(
        self,
        entidad_id: str,
        investigacion_id: str,
        tipo: str,
        valor: str,
        nombre_display: str = None,
        confianza: float = 0.5,
        datos: dict = None,
    ):
        """agrega o actualiza un nodo en el grafo"""
        if not self._driver:
            await self.conectar()
        if not self._driver:
            return

        query = """
        MERGE (e:Entidad {uid: $uid})
        SET e.investigacion_id = $inv_id,
            e.tipo = $tipo,
            e.valor = $valor,
            e.nombre_display = $display,
            e.confianza = $confianza,
            e.actualizado = datetime()
        """

        # agregar label segun tipo
        label_map = {
            "person": "Persona",
            "email": "Email",
            "username": "Username",
            "phone": "Telefono",
            "domain": "Dominio",
            "ip": "DireccionIP",
            "organization": "Organizacion",
            "social_profile": "PerfilSocial",
            "credential": "Credencial",
            "hash": "Hash",
            "document": "Documento",
            "location": "Ubicacion",
        }

        label = label_map.get(tipo, "Entidad")
        query += f"\nSET e:{label}"

        if datos:
            for k, v in datos.items():
                if isinstance(v, (str, int, float, bool)):
                    query += f"\nSET e.{k} = ${k}"

        async with self._driver.session() as sesion:
            try:
                params = {
                    "uid": entidad_id,
                    "inv_id": investigacion_id,
                    "tipo": tipo,
                    "valor": valor,
                    "display": nombre_display or valor,
                    "confianza": confianza,
                }
                if datos:
                    for k, v in datos.items():
                        if isinstance(v, (str, int, float, bool)):
                            params[k] = v

                await sesion.run(query, params)
            except Exception as e:
                log.error("error agregando nodo neo4j", error=str(e))

    async def agregar_relacion(
        self,
        origen_id: str,
        destino_id: str,
        tipo_relacion: str,
        confianza: float = 0.5,
        datos: dict = None,
    ):
        """agrega una relacion entre dos nodos"""
        if not self._driver:
            await self.conectar()
        if not self._driver:
            return

        # neo4j no permite parametrizar tipos de relacion, se sanitiza
        tipo_safe = tipo_relacion.upper().replace(" ", "_")
        tipos_validos = [
            "OWNS", "USES", "ASSOCIATED_WITH", "LOCATED_AT",
            "MEMBER_OF", "LEAKED_IN", "RESOLVES_TO", "HOSTED_ON", "REGISTERED_BY",
        ]
        if tipo_safe not in tipos_validos:
            tipo_safe = "ASSOCIATED_WITH"

        query = f"""
        MATCH (a:Entidad {{uid: $origen_id}})
        MATCH (b:Entidad {{uid: $destino_id}})
        MERGE (a)-[r:{tipo_safe}]->(b)
        SET r.confianza = $confianza,
            r.actualizado = datetime()
        """

        async with self._driver.session() as sesion:
            try:
                await sesion.run(query, {
                    "origen_id": origen_id,
                    "destino_id": destino_id,
                    "confianza": confianza,
                })
            except Exception as e:
                log.error("error agregando relacion neo4j", error=str(e))

    async def obtener_grafo_investigacion(self, investigacion_id: str, limite: int = 500) -> dict:
        """obtiene el grafo completo de una investigacion"""
        if not self._driver:
            await self.conectar()
        if not self._driver:
            return {"nodos": [], "aristas": []}

        query = """
        MATCH (e:Entidad {investigacion_id: $inv_id})
        OPTIONAL MATCH (e)-[r]->(e2:Entidad {investigacion_id: $inv_id})
        RETURN e, r, e2
        LIMIT $limite
        """

        nodos = {}
        aristas = []

        async with self._driver.session() as sesion:
            try:
                resultado = await sesion.run(query, {"inv_id": investigacion_id, "limite": limite})
                async for registro in resultado:
                    nodo_e = registro["e"]
                    if nodo_e:
                        uid = nodo_e.get("uid")
                        if uid not in nodos:
                            nodos[uid] = {
                                "id": uid,
                                "tipo": nodo_e.get("tipo"),
                                "valor": nodo_e.get("valor"),
                                "display": nodo_e.get("nombre_display"),
                                "confianza": nodo_e.get("confianza"),
                            }

                    rel = registro["r"]
                    nodo_e2 = registro["e2"]
                    if rel and nodo_e2:
                        uid2 = nodo_e2.get("uid")
                        if uid2 not in nodos:
                            nodos[uid2] = {
                                "id": uid2,
                                "tipo": nodo_e2.get("tipo"),
                                "valor": nodo_e2.get("valor"),
                                "display": nodo_e2.get("nombre_display"),
                                "confianza": nodo_e2.get("confianza"),
                            }
                        aristas.append({
                            "origen": nodo_e.get("uid"),
                            "destino": uid2,
                            "tipo": rel.type,
                            "confianza": rel.get("confianza", 0.5),
                        })
            except Exception as e:
                log.error("error obteniendo grafo neo4j", error=str(e))

        return {"nodos": list(nodos.values()), "aristas": aristas}

    async def pagerank(self, investigacion_id: str, top_n: int = 20) -> list[dict]:
        """ejecuta pagerank para encontrar entidades mas conectadas"""
        if not self._driver:
            await self.conectar()
        if not self._driver:
            return []

        query = """
        MATCH (e:Entidad {investigacion_id: $inv_id})
        WITH e, size((e)--()) as conexiones
        RETURN e.uid as id, e.tipo as tipo, e.valor as valor,
               e.nombre_display as display, conexiones
        ORDER BY conexiones DESC
        LIMIT $top
        """

        resultados = []
        async with self._driver.session() as sesion:
            try:
                resultado = await sesion.run(query, {"inv_id": investigacion_id, "top": top_n})
                async for registro in resultado:
                    resultados.append({
                        "id": registro["id"],
                        "tipo": registro["tipo"],
                        "valor": registro["valor"],
                        "display": registro["display"],
                        "conexiones": registro["conexiones"],
                    })
            except Exception as e:
                log.error("error en pagerank neo4j", error=str(e))

        return resultados

    async def camino_mas_corto(self, origen_id: str, destino_id: str) -> Optional[list]:
        """encuentra el camino mas corto entre dos entidades"""
        if not self._driver:
            await self.conectar()
        if not self._driver:
            return None

        query = """
        MATCH path = shortestPath(
            (a:Entidad {uid: $origen})-[*..10]-(b:Entidad {uid: $destino})
        )
        RETURN [n in nodes(path) | {id: n.uid, tipo: n.tipo, valor: n.valor}] as nodos,
               [r in relationships(path) | {tipo: type(r)}] as relaciones
        """

        async with self._driver.session() as sesion:
            try:
                resultado = await sesion.run(query, {"origen": origen_id, "destino": destino_id})
                registro = await resultado.single()
                if registro:
                    return {
                        "nodos": registro["nodos"],
                        "relaciones": registro["relaciones"],
                        "longitud": len(registro["nodos"]) - 1,
                    }
            except Exception as e:
                log.error("error en camino corto neo4j", error=str(e))

        return None

    async def exportar_graphml(self, investigacion_id: str) -> str:
        """exporta el grafo en formato graphml"""
        grafo = await self.obtener_grafo_investigacion(investigacion_id, limite=5000)

        xml = '<?xml version="1.0" encoding="UTF-8"?>\n'
        xml += '<graphml xmlns="http://graphml.graphstruct.org/graphml">\n'
        xml += '  <key id="tipo" for="node" attr.name="tipo" attr.type="string"/>\n'
        xml += '  <key id="valor" for="node" attr.name="valor" attr.type="string"/>\n'
        xml += '  <key id="confianza" for="node" attr.name="confianza" attr.type="double"/>\n'
        xml += '  <key id="rel_tipo" for="edge" attr.name="tipo" attr.type="string"/>\n'
        xml += '  <graph id="sentinel" edgedefault="directed">\n'

        for nodo in grafo["nodos"]:
            xml += f'    <node id="{nodo["id"]}">\n'
            xml += f'      <data key="tipo">{nodo.get("tipo", "")}</data>\n'
            xml += f'      <data key="valor">{nodo.get("valor", "")}</data>\n'
            xml += f'      <data key="confianza">{nodo.get("confianza", 0.5)}</data>\n'
            xml += f'    </node>\n'

        for i, arista in enumerate(grafo["aristas"]):
            xml += f'    <edge id="e{i}" source="{arista["origen"]}" target="{arista["destino"]}">\n'
            xml += f'      <data key="rel_tipo">{arista.get("tipo", "")}</data>\n'
            xml += f'    </edge>\n'

        xml += '  </graph>\n</graphml>'
        return xml

    async def exportar_json_sigma(self, investigacion_id: str) -> dict:
        """exporta el grafo en formato json para sigma.js"""
        grafo = await self.obtener_grafo_investigacion(investigacion_id)

        colores_tipo = {
            "person": "#e74c3c",
            "email": "#3498db",
            "username": "#2ecc71",
            "phone": "#f39c12",
            "domain": "#9b59b6",
            "ip": "#1abc9c",
            "organization": "#e67e22",
            "social_profile": "#00bcd4",
            "credential": "#f44336",
            "hash": "#607d8b",
            "document": "#795548",
            "location": "#4caf50",
        }

        nodos_sigma = []
        for nodo in grafo["nodos"]:
            nodos_sigma.append({
                "id": nodo["id"],
                "label": nodo.get("display") or nodo.get("valor", ""),
                "x": hash(nodo["id"]) % 1000,
                "y": hash(nodo["id"] + "y") % 1000,
                "size": max(5, min(20, int((nodo.get("confianza", 0.5)) * 20))),
                "color": colores_tipo.get(nodo.get("tipo"), "#999999"),
                "tipo": nodo.get("tipo"),
                "valor": nodo.get("valor"),
            })

        aristas_sigma = []
        for i, arista in enumerate(grafo["aristas"]):
            aristas_sigma.append({
                "id": f"e{i}",
                "source": arista["origen"],
                "target": arista["destino"],
                "label": arista.get("tipo", ""),
                "size": max(1, int(arista.get("confianza", 0.5) * 5)),
                "color": "#cccccc",
            })

        return {"nodes": nodos_sigma, "edges": aristas_sigma}


# instancia global
constructor_grafo = ConstructorGrafo()
