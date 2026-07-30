import os

from dotenv import load_dotenv
from neo4j import GraphDatabase

from app.models.domain import Dataset, Finding


load_dotenv()


class GraphBuilder:
    def __init__(self) -> None:
        uri = os.getenv("NEO4J_URI", "bolt://localhost:7687")
        user = os.getenv("NEO4J_USER", "neo4j")
        password = os.getenv("NEO4J_PASSWORD", "cloudpathpass")

        self.driver = GraphDatabase.driver(
            uri,
            auth=(user, password),
        )

    def close(self) -> None:
        self.driver.close()

    def verify_connection(self) -> None:
        self.driver.verify_connectivity()

    def clear_graph(self) -> None:
        with self.driver.session() as session:
            session.run("MATCH (n) DETACH DELETE n").consume()

    def write_dataset(
        self,
        dataset: Dataset,
        findings: list[Finding],
    ) -> None:
        with self.driver.session() as session:
            session.execute_write(
                self._write_account,
                dataset.account_id,
            )

            for principal in dataset.principals:
                session.execute_write(
                    self._write_principal,
                    dataset.account_id,
                    principal.model_dump(),
                )

            for finding in findings:
                session.execute_write(
                    self._write_finding,
                    finding.model_dump(),
                )

    @staticmethod
    def _write_account(tx, account_id: str) -> None:
        tx.run(
            """
            MERGE (a:Account {id: $account_id})
            SET a.name = $account_id
            """,
            account_id=account_id,
        ).consume()

    @staticmethod
    def _write_principal(
        tx,
        account_id: str,
        principal: dict,
    ) -> None:
        tx.run(
            """
            MATCH (a:Account {id: $account_id})
            MERGE (p:Principal {id: $id})
            SET
                p.name = $name,
                p.kind = $kind
            MERGE (a)-[:CONTAINS]->(p)
            """,
            account_id=account_id,
            id=principal["id"],
            name=principal["name"],
            kind=principal["kind"],
        ).consume()

        for trusted_principal in principal["trust"]:
            tx.run(
                """
                MERGE (source:Principal {id: $source_id})
                MERGE (target:Principal {id: $target_id})
                MERGE (source)-[:TRUSTED_BY]->(target)
                """,
                source_id=principal["id"],
                target_id=trusted_principal,
            ).consume()

        for statement_index, statement in enumerate(principal["policies"]):
            statement_id = (
                f"{principal['id']}:statement:{statement_index}"
            )

            tx.run(
                """
                MATCH (p:Principal {id: $principal_id})
                MERGE (s:PolicyStatement {id: $statement_id})
                SET
                    s.effect = $effect,
                    s.actions = $actions,
                    s.resources = $resources
                MERGE (p)-[:HAS_STATEMENT]->(s)
                """,
                principal_id=principal["id"],
                statement_id=statement_id,
                effect=statement["effect"],
                actions=statement["actions"],
                resources=statement["resources"],
            ).consume()

    @staticmethod
    def _write_finding(tx, finding: dict) -> None:
        tx.run(
            """
            MERGE (f:Finding {id: $id})
            SET
                f.primitive = $primitive,
                f.title = $title,
                f.severity = $severity,
                f.score = $score,
                f.evidence = $evidence,
                f.remediation = $remediation

            MERGE (source:Principal {id: $source})
            MERGE (target:Principal {id: $target})

            MERGE (source)-[:HAS_ATTACK_PATH]->(f)
            MERGE (f)-[:TARGETS]->(target)
            """,
            **finding,
        ).consume()