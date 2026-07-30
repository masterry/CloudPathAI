from contextlib import asynccontextmanager
from typing import Any

from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware

from app.ai.explainer import explain_finding
from app.collectors.sample_loader import load_sample
from app.detection.path_finder import build_attack_paths
from app.detection.primitives import detect_primitives
from app.graph.graph_builder import GraphBuilder
from app.graph.queries import get_findings, get_graph_data
from app.models.domain import Finding


graph_builder: GraphBuilder | None = None


@asynccontextmanager
async def lifespan(app: FastAPI):
    global graph_builder

    graph_builder = GraphBuilder()
    graph_builder.verify_connection()

    yield

    graph_builder.close()
    graph_builder = None


app = FastAPI(
    title="CloudPathAI API",
    description="AWS IAM attack path analyzer",
    version="0.1.0",
    lifespan=lifespan,
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        "http://localhost:5173",
        "http://127.0.0.1:5173",
    ],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


def get_builder() -> GraphBuilder:
    if graph_builder is None:
        raise HTTPException(
            status_code=503,
            detail="Neo4j connection is not available.",
        )

    return graph_builder


@app.get("/")
def root() -> dict[str, str]:
    return {
        "name": "CloudPathAI",
        "status": "running",
    }


@app.get("/health")
def health() -> dict[str, str]:
    builder = get_builder()
    builder.verify_connection()

    return {
        "api": "healthy",
        "neo4j": "connected",
    }


@app.post("/api/analyze/sample")
def analyze_sample() -> dict[str, Any]:
    dataset = load_sample()
    findings = detect_primitives(dataset)

    builder = get_builder()
    builder.clear_graph()
    builder.write_dataset(dataset, findings)

    return {
        "account_id": dataset.account_id,
        "principal_count": len(dataset.principals),
        "finding_count": len(findings),
        "findings": [
            finding.model_dump()
            for finding in findings
        ],
    }


@app.get("/api/findings")
def list_findings() -> dict[str, Any]:
    findings = get_findings(get_builder())

    return {
        "count": len(findings),
        "findings": findings,
    }


@app.get("/api/graph")
def graph() -> dict[str, Any]:
    return get_graph_data(get_builder())


@app.get("/api/paths")
def paths() -> dict[str, Any]:
    stored_findings = get_findings(get_builder())

    findings = [
        Finding.model_validate(finding)
        for finding in stored_findings
    ]

    attack_paths = build_attack_paths(findings)

    return {
        "count": len(attack_paths),
        "paths": attack_paths,
    }


@app.get("/api/findings/{finding_id}/explanation")
def finding_explanation(finding_id: str) -> dict[str, str]:
    stored_findings = get_findings(get_builder())

    matching_finding = next(
        (
            Finding.model_validate(finding)
            for finding in stored_findings
            if finding["id"] == finding_id
        ),
        None,
    )

    if matching_finding is None:
        raise HTTPException(
            status_code=404,
            detail="Finding not found.",
        )

    return {
        "finding_id": finding_id,
        "explanation": explain_finding(matching_finding),
    }