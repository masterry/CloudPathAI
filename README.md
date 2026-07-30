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
