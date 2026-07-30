import { useMemo } from "react";
import ReactFlow, {
  Background,
  Controls,
  MarkerType,
  MiniMap,
  Position,
} from "reactflow";
import dagre from "@dagrejs/dagre";

import "reactflow/dist/style.css";

const NODE_WIDTH = 240;
const NODE_HEIGHT = 82;

function getNodeStyle(node) {
  if (node.type === "Finding") {
    return {
      background: node.severity === "critical" ? "#dc2626" : "#ea580c",
      color: "#ffffff",
      border: "1px solid rgba(255, 255, 255, 0.22)",
      borderRadius: 12,
      padding: 14,
      width: NODE_WIDTH,
      fontSize: 13,
      fontWeight: 700,
      textAlign: "center",
    };
  }

  if (node.kind === "Role") {
    return {
      background: "#7c3aed",
      color: "#ffffff",
      border: "1px solid rgba(255, 255, 255, 0.22)",
      borderRadius: 12,
      padding: 14,
      width: NODE_WIDTH,
      fontSize: 13,
      fontWeight: 700,
      textAlign: "center",
    };
  }

  if (node.kind === "User") {
    return {
      background: "#2563eb",
      color: "#ffffff",
      border: "1px solid rgba(255, 255, 255, 0.22)",
      borderRadius: 12,
      padding: 14,
      width: NODE_WIDTH,
      fontSize: 13,
      fontWeight: 700,
      textAlign: "center",
    };
  }

  return {
    background: "#475569",
    color: "#ffffff",
    border: "1px solid rgba(255, 255, 255, 0.22)",
    borderRadius: 12,
    padding: 14,
    width: NODE_WIDTH,
    fontSize: 13,
    fontWeight: 700,
    textAlign: "center",
  };
}

function getNodeLabel(node) {
  if (node.type === "Finding") {
    return `${node.severity?.toUpperCase() || "FINDING"}\n${node.label}`;
  }

  return `${node.kind || "External"}\n${node.label}`;
}

function getEdgeStyle(type) {
  if (type === "HAS_ATTACK_PATH") {
    return {
      stroke: "#ef4444",
      strokeWidth: 3,
    };
  }

  if (type === "TARGETS") {
    return {
      stroke: "#f59e0b",
      strokeWidth: 2.5,
    };
  }

  if (type === "TRUSTED_BY") {
    return {
      stroke: "#22c55e",
      strokeWidth: 2,
    };
  }

  return {
    stroke: "#94a3b8",
    strokeWidth: 2,
  };
}

function createLayout(graph) {
  const dagreGraph = new dagre.graphlib.Graph();

  dagreGraph.setDefaultEdgeLabel(() => ({}));

  dagreGraph.setGraph({
    rankdir: "LR",
    ranksep: 150,
    nodesep: 55,
    edgesep: 30,
    marginx: 40,
    marginy: 40,
  });

  const nodes = graph.nodes.map((node) => ({
    id: node.id,
    data: {
      label: getNodeLabel(node),
      originalNode: node,
    },
    position: {
      x: 0,
      y: 0,
    },
    sourcePosition: Position.Right,
    targetPosition: Position.Left,
    style: getNodeStyle(node),
  }));

  const edges = graph.edges.map((edge, index) => ({
    id: `${edge.source}-${edge.target}-${edge.type}-${index}`,
    source: edge.source,
    target: edge.target,
    label: edge.type.replaceAll("_", " "),
    animated: edge.type === "HAS_ATTACK_PATH",
    style: getEdgeStyle(edge.type),
    markerEnd: {
      type: MarkerType.ArrowClosed,
      width: 18,
      height: 18,
      color: getEdgeStyle(edge.type).stroke,
    },
    labelStyle: {
      fill: "#cbd5e1",
      fontSize: 10,
      fontWeight: 700,
    },
    labelBgStyle: {
      fill: "#0f172a",
      fillOpacity: 0.92,
    },
    labelBgPadding: [6, 4],
    labelBgBorderRadius: 4,
  }));

  nodes.forEach((node) => {
    dagreGraph.setNode(node.id, {
      width: NODE_WIDTH,
      height: NODE_HEIGHT,
    });
  });

  edges.forEach((edge) => {
    dagreGraph.setEdge(edge.source, edge.target);
  });

  dagre.layout(dagreGraph);

  const positionedNodes = nodes.map((node) => {
    const position = dagreGraph.node(node.id);

    return {
      ...node,
      position: {
        x: position.x - NODE_WIDTH / 2,
        y: position.y - NODE_HEIGHT / 2,
      },
    };
  });

  return {
    nodes: positionedNodes,
    edges,
  };
}

export default function AttackGraph({ graph }) {
  const layout = useMemo(() => createLayout(graph), [graph]);

  return (
    <div className="attack-graph">
      <div className="graph-legend">
        <span>
          <i className="legend-dot legend-user" />
          User
        </span>

        <span>
          <i className="legend-dot legend-role" />
          Role
        </span>

        <span>
          <i className="legend-dot legend-finding" />
          Finding
        </span>

        <span>
          <i className="legend-line legend-attack" />
          Attack path
        </span>

        <span>
          <i className="legend-line legend-target" />
          Target
        </span>

        <span>
          <i className="legend-line legend-trust" />
          Trust
        </span>
      </div>

      <ReactFlow
        nodes={layout.nodes}
        edges={layout.edges}
        fitView
        fitViewOptions={{
          padding: 0.2,
        }}
        minZoom={0.25}
        maxZoom={1.8}
        nodesDraggable
        nodesConnectable={false}
        elementsSelectable
      >
        <MiniMap
          pannable
          zoomable
          nodeColor={(node) => {
            const originalNode = node.data?.originalNode;

            if (originalNode?.type === "Finding") {
              return "#dc2626";
            }

            if (originalNode?.kind === "Role") {
              return "#7c3aed";
            }

            if (originalNode?.kind === "User") {
              return "#2563eb";
            }

            return "#475569";
          }}
        />

        <Controls />

        <Background
          gap={20}
          size={1}
          color="#263247"
        />
      </ReactFlow>
    </div>
  );
}