# CloudPathAI

AWS IAM Attack Path Analyzer

CloudPathAI discovers IAM privilege-escalation paths inside AWS accounts by analyzing users, roles, permissions, and trust relationships.

---

## Features

- FastAPI backend
- React frontend
- Neo4j graph database
- IAM privilege escalation detection
- Risk scoring
- Attack path visualization
- AI-powered security explanations

---

## Architecture

```
AWS IAM
     │
     ▼
Collector
     │
     ▼
Policy Parser
     │
     ▼
Detection Engine
     │
     ▼
Neo4j
     │
     ▼
FastAPI
     │
     ▼
React Dashboard
```

---

## Screenshots

### Dashboard

![Dashboard](screenshots/dashboard.png)

### Neo4j Graph

![Neo4j](screenshots/neo4j.png)

---

## Run

```bash
docker compose up -d

cd backend
uvicorn app.main:app --reload

cd frontend
npm install
npm run dev
```

---

## Tech Stack

* React
* FastAPI
* Neo4j
* Docker
* Python
* boto3
* OpenAI API

---

## Future Work

* Real AWS account scanning
* Multi-account support
* Continuous monitoring
* Interactive attack graph
* AI remediation suggestions

## Enhanced Research Features

This enhanced version adds:

- A read-only Boto3 IAM collector for users, roles, managed policies, inline policies, and role trust policies
- Three additional privilege-escalation techniques
- Transparent multi-factor risk scoring
- Automated unit tests
- A reproducible synthetic benchmark
- A report improvement and evaluation guide

### Run tests

```bash
cd backend
pytest -q
```

### Run the benchmark

```bash
cd backend
python scripts/benchmark.py --sizes 10 100 500 1000 --repetitions 5
```

### Analyze an AWS account

Use temporary credentials for a read-only audit role. The collector calls IAM List/Get APIs and STS `GetCallerIdentity`; it does not modify AWS resources.

```bash
cd backend
python scripts/analyze_aws.py --profile your-audit-profile --output aws_analysis.json
```

### Important analysis limitations

The current evaluator does not fully resolve IAM conditions, permission boundaries, service control policies, session policies, or all resource-based policies. Findings must therefore be presented as configuration-based attack opportunities, not proof that exploitation will always succeed.
