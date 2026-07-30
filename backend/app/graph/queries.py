from typing import Any

from app.graph.graph_builder import GraphBuilder


def get_graph_data(builder: GraphBuilder) -> dict[str, list[dict[str, Any]]]:
    with builder.driver.session() as session:
        node_result = session.run(
            """
            MATCH (n)
            WHERE n:Principal OR n:Finding
            RETURN
                n.id AS id,
                labels(n)[0] AS type,
                coalesce(n.name, n.title, n.id) AS label,
                n.kind AS kind,
                n.severity AS severity,
                n.score AS score
            ORDER BY type, label
            """
        )

        nodes = [record.data() for record in node_result]

        edge_result = session.run(
            """
            MATCH (source)-[relationship]->(target)
            WHERE
                (source:Principal OR source:Finding)
                AND
                (target:Principal OR target:Finding)
            RETURN
                source.id AS source,
                target.id AS target,
                type(relationship) AS type
            """
        )

        edges = [record.data() for record in edge_result]

    return {
        "nodes": nodes,
        "edges": edges,
    }


def get_findings(builder: GraphBuilder) -> list[dict[str, Any]]:
    with builder.driver.session() as session:
        result = session.run(
            """
            MATCH (source:Principal)-[:HAS_ATTACK_PATH]->(finding:Finding)
            MATCH (finding)-[:TARGETS]->(target:Principal)
            RETURN
                finding.id AS id,
                finding.primitive AS primitive,
                finding.title AS title,
                source.id AS source,
                target.id AS target,
                finding.severity AS severity,
                finding.score AS score,
                finding.evidence AS evidence,
                finding.remediation AS remediation
            ORDER BY finding.score DESC, finding.title
            """
        )

        return [record.data() for record in result]