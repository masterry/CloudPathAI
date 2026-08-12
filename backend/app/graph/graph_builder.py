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
        self.driver = GraphDatabase.driver(uri, auth=(user, password))

    def close(self) -> None:
        self.driver.close()

    def verify_connection(self) -> None:
        self.driver.verify_connectivity()

    def clear_graph(self) -> None:
        with self.driver.session() as session:
            session.run("MATCH (n) DETACH DELETE n").consume()

    def write_dataset(self, dataset: Dataset, findings: list[Finding]) -> None:
        principals = [principal.model_dump() for principal in dataset.principals]
        finding_rows = [finding.model_dump() for finding in findings]

        statement_rows: list[dict] = []
        trust_rows: list[dict[str, str]] = []
        for principal in principals:
            for statement_index, statement in enumerate(principal["policies"]):
                statement_rows.append(
                    {
                        "principal_id": principal["id"],
                        "statement_id": f"{principal['id']}:statement:{statement_index}",
                        "effect": statement["effect"],
                        "actions": statement["actions"],
                        "resources": statement["resources"],
                        "conditional": statement["condition"] is not None,
                        "unsupported_elements": statement["unsupported_elements"],
                        "source_policy_arn": statement["source_policy_arn"],
                    }
                )
            for trusted_principal in principal["trust"]:
                trust_rows.append(
                    {
                        "trusted_principal": trusted_principal,
                        "role_id": principal["id"],
                    }
                )

        with self.driver.session() as session:
            session.execute_write(
                self._write_all,
                dataset.account_id,
                principals,
                statement_rows,
                trust_rows,
                finding_rows,
            )

    @staticmethod
    def _write_all(
        tx,
        account_id: str,
        principals: list[dict],
        statements: list[dict],
        trusts: list[dict],
        findings: list[dict],
    ) -> None:
        tx.run(
            """
            MERGE (a:Account {id: $account_id})
            SET a.name = $account_id
            """,
            account_id=account_id,
        ).consume()

        tx.run(
            """
            MATCH (a:Account {id: $account_id})
            UNWIND $principals AS principal
            MERGE (p:Principal {id: principal.id})
            SET p.name = principal.name,
                p.kind = principal.kind,
                p.arn = principal.arn
            MERGE (a)-[:CONTAINS]->(p)
            """,
            account_id=account_id,
            principals=principals,
        ).consume()

        tx.run(
            """
            UNWIND $trusts AS trust
            MERGE (source:Principal {id: trust.trusted_principal})
            MERGE (role:Principal {id: trust.role_id})
            MERGE (source)-[:TRUSTED_TO_ASSUME]->(role)
            """,
            trusts=trusts,
        ).consume()

        tx.run(
            """
            UNWIND $statements AS statement
            MATCH (p:Principal {id: statement.principal_id})
            MERGE (s:PolicyStatement {id: statement.statement_id})
            SET s.effect = statement.effect,
                s.actions = statement.actions,
                s.resources = statement.resources,
                s.conditional = statement.conditional,
                s.unsupported_elements = statement.unsupported_elements,
                s.source_policy_arn = statement.source_policy_arn
            MERGE (p)-[:HAS_STATEMENT]->(s)
            """,
            statements=statements,
        ).consume()

        tx.run(
            """
            UNWIND $findings AS finding
            MERGE (f:Finding {id: finding.id})
            SET f.primitive = finding.primitive,
                f.title = finding.title,
                f.severity = finding.severity,
                f.score = finding.score,
                f.evidence = finding.evidence,
                f.remediation = finding.remediation
            MERGE (source:Principal {id: finding.source})
            MERGE (target:Principal {id: finding.target})
            MERGE (source)-[:HAS_ATTACK_PATH]->(f)
            MERGE (f)-[:TARGETS]->(target)
            """,
            findings=findings,
        ).consume()
