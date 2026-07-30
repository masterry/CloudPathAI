import { StrictMode, useEffect, useMemo, useState } from "react";
import { createRoot } from "react-dom/client";

import AttackGraph from "./components/AttackGraph";
import "./styles.css";

const API_BASE_URL = "http://127.0.0.1:8000";

const severityRank = {
  critical: 4,
  high: 3,
  medium: 2,
  low: 1,
};

function App() {
  const [health, setHealth] = useState(null);
  const [findings, setFindings] = useState([]);
  const [graph, setGraph] = useState({
    nodes: [],
    edges: [],
  });
  const [paths, setPaths] = useState([]);
  const [selectedFinding, setSelectedFinding] = useState(null);
  const [explanation, setExplanation] = useState("");
  const [loading, setLoading] = useState(false);
  const [explanationLoading, setExplanationLoading] = useState(false);
  const [error, setError] = useState("");

  const sortedFindings = useMemo(() => {
    return [...findings].sort((a, b) => {
      const severityDifference =
        severityRank[b.severity] - severityRank[a.severity];

      if (severityDifference !== 0) {
        return severityDifference;
      }

      return b.score - a.score;
    });
  }, [findings]);

  const criticalCount = findings.filter(
    (finding) => finding.severity === "critical",
  ).length;

  const highCount = findings.filter(
    (finding) => finding.severity === "high",
  ).length;

  async function request(path, options = {}) {
    const response = await fetch(`${API_BASE_URL}${path}`, options);

    if (!response.ok) {
      let detail = `Request failed with status ${response.status}`;

      try {
        const body = await response.json();
        detail = body.detail || detail;
      } catch {
        // Keep the default error message.
      }

      throw new Error(detail);
    }

    return response.json();
  }

  async function loadDashboard() {
    const [healthData, findingsData, graphData, pathsData] =
      await Promise.all([
        request("/health"),
        request("/api/findings"),
        request("/api/graph"),
        request("/api/paths"),
      ]);

    setHealth(healthData);
    setFindings(findingsData.findings);
    setGraph(graphData);
    setPaths(pathsData.paths);
  }

  async function analyzeSample() {
    setLoading(true);
    setError("");
    setSelectedFinding(null);
    setExplanation("");

    try {
      await request("/api/analyze/sample", {
        method: "POST",
      });

      await loadDashboard();
    } catch (requestError) {
      setError(requestError.message);
    } finally {
      setLoading(false);
    }
  }

  async function showExplanation(finding) {
    setSelectedFinding(finding);
    setExplanation("");
    setExplanationLoading(true);
    setError("");

    try {
      const encodedId = encodeURIComponent(finding.id);

      const result = await request(
        `/api/findings/${encodedId}/explanation`,
      );

      setExplanation(result.explanation);
    } catch (requestError) {
      setError(requestError.message);
    } finally {
      setExplanationLoading(false);
    }
  }

  useEffect(() => {
    async function initialize() {
      setLoading(true);

      try {
        await loadDashboard();
      } catch (requestError) {
        setError(
          `${requestError.message}. Make sure the FastAPI server is running.`,
        );
      } finally {
        setLoading(false);
      }
    }

    initialize();
  }, []);

  return (
    <div className="app-shell">
      <header className="topbar">
        <div>
          <div className="brand">
            <span className="brand-mark">CP</span>
            <span>CloudPathAI</span>
          </div>

          <p className="subtitle">
            AWS IAM attack path analyzer
          </p>
        </div>

        <div className="header-actions">
          <div
            className={
              health
                ? "status-badge status-online"
                : "status-badge status-offline"
            }
          >
            <span className="status-dot" />
            {health ? "API and Neo4j connected" : "Disconnected"}
          </div>

          <button
            className="primary-button"
            type="button"
            onClick={analyzeSample}
            disabled={loading}
          >
            {loading ? "Analyzing…" : "Analyze sample account"}
          </button>
        </div>
      </header>

      <main className="dashboard">
        {error && (
          <div className="error-banner">
            <strong>Something went wrong:</strong> {error}
          </div>
        )}

        <section className="hero">
          <div>
            <span className="eyebrow">Security overview</span>

            <h1>
              Find IAM privilege-escalation paths
            </h1>

            <p>
              Analyze identities, roles, policies, and trust relationships
              to expose dangerous routes to administrator access.
            </p>
          </div>

          <div className="hero-score">
            <span>Highest risk</span>

            <strong>
              {findings.length
                ? Math.max(...findings.map((item) => item.score))
                : 0}
            </strong>

            <small>out of 100</small>
          </div>
        </section>

        <section className="metrics-grid">
          <MetricCard
            label="Total findings"
            value={findings.length}
            note="Detected escalation primitives"
          />

          <MetricCard
            label="Critical"
            value={criticalCount}
            note="Requires immediate review"
          />

          <MetricCard
            label="High"
            value={highCount}
            note="Significant IAM exposure"
          />

          <MetricCard
            label="Attack paths"
            value={paths.length}
            note="Reachable privilege routes"
          />

          <MetricCard
            label="Graph nodes"
            value={graph.nodes.length}
            note="Principals and findings"
          />
        </section>

        <section className="content-grid">
          <div className="panel findings-panel">
            <div className="panel-heading">
              <div>
                <span className="eyebrow">
                  Prioritized results
                </span>

                <h2>Security findings</h2>
              </div>

              <span className="count-badge">
                {findings.length}
              </span>
            </div>

            {loading && findings.length === 0 ? (
              <EmptyState
                title="Loading analysis"
                message="Retrieving findings from the API."
              />
            ) : sortedFindings.length === 0 ? (
              <EmptyState
                title="No analysis loaded"
                message="Run the sample analysis to discover IAM attack paths."
              />
            ) : (
              <div className="finding-list">
                {sortedFindings.map((finding) => (
                  <button
                    className={`finding-card ${
                      selectedFinding?.id === finding.id
                        ? "finding-card-selected"
                        : ""
                    }`}
                    key={finding.id}
                    type="button"
                    onClick={() => showExplanation(finding)}
                  >
                    <div className="finding-card-top">
                      <SeverityBadge
                        severity={finding.severity}
                      />

                      <span className="risk-score">
                        Risk {finding.score}
                      </span>
                    </div>

                    <h3>{finding.title}</h3>

                    <div className="attack-route">
                      <code>{finding.source}</code>

                      <span aria-hidden="true">
                        →
                      </span>

                      <code>{finding.target}</code>
                    </div>

                    <span className="primitive">
                      {formatPrimitive(finding.primitive)}
                    </span>
                  </button>
                ))}
              </div>
            )}
          </div>

          <aside className="panel details-panel">
            <div className="panel-heading">
              <div>
                <span className="eyebrow">
                  Finding details
                </span>

                <h2>Path explanation</h2>
              </div>
            </div>

            {!selectedFinding ? (
              <EmptyState
                title="Select a finding"
                message="Choose a security finding to inspect its evidence and remediation."
              />
            ) : (
              <div className="details-content">
                <SeverityBadge
                  severity={selectedFinding.severity}
                />

                <h3>{selectedFinding.title}</h3>

                <div className="detail-block">
                  <span className="detail-label">
                    Attack path
                  </span>

                  <div className="path-display">
                    <code>{selectedFinding.source}</code>
                    <span>→</span>
                    <code>{selectedFinding.target}</code>
                  </div>
                </div>

                <div className="detail-block">
                  <span className="detail-label">
                    Evidence
                  </span>

                  <ul>
                    {selectedFinding.evidence.map((item) => (
                      <li key={item}>
                        {item}
                      </li>
                    ))}
                  </ul>
                </div>

                <div className="detail-block">
                  <span className="detail-label">
                    Explanation
                  </span>

                  <p>
                    {explanationLoading
                      ? "Generating explanation…"
                      : explanation}
                  </p>
                </div>

                <div className="remediation-box">
                  <span className="detail-label">
                    Remediation
                  </span>

                  <p>{selectedFinding.remediation}</p>
                </div>
              </div>
            )}
          </aside>
        </section>

        <section className="panel graph-panel">
          <div className="panel-heading">
            <div>
              <span className="eyebrow">
                Neo4j representation
              </span>

              <h2>Interactive attack-path graph</h2>
            </div>

            <span className="count-badge">
              {graph.edges.length} edges
            </span>
          </div>

          {graph.nodes.length === 0 ? (
            <EmptyState
              title="Graph is empty"
              message="Run an analysis to populate Neo4j."
            />
          ) : (
            <AttackGraph graph={graph} />
          )}
        </section>
      </main>
    </div>
  );
}

function MetricCard({ label, value, note }) {
  return (
    <article className="metric-card">
      <span>{label}</span>
      <strong>{value}</strong>
      <small>{note}</small>
    </article>
  );
}

function SeverityBadge({ severity }) {
  return (
    <span className={`severity severity-${severity}`}>
      {severity}
    </span>
  );
}

function EmptyState({ title, message }) {
  return (
    <div className="empty-state">
      <div className="empty-icon">
        ◇
      </div>

      <h3>{title}</h3>
      <p>{message}</p>
    </div>
  );
}

function formatPrimitive(value) {
  return value
    .toLowerCase()
    .split("_")
    .map(
      (part) =>
        part.charAt(0).toUpperCase() + part.slice(1),
    )
    .join(" ");
}

createRoot(document.getElementById("root")).render(
  <StrictMode>
    <App />
  </StrictMode>,
);