"use client";

import React, { useMemo } from "react";
import {
  ReactFlow,
  MiniMap,
  Controls,
  Background,
  useNodesState,
  useEdgesState,
  Node,
  Edge,
  MarkerType,
  Position,
  Handle,
} from "@xyflow/react";
import {
  ShieldAlert,
  User,
  Server,
  Network,
  Bug,
  Info,
  ExternalLink,
} from "lucide-react";
import { VisualizationData, GraphNodeData } from "../types";

// ── Custom Node Components ────────────────────────────────────────────────

const AlertNodeComponent = ({ data }: { data: any }) => (
  <div className="px-3 py-2.5 rounded-xl bg-slate-900 border-2 border-rose-500 shadow-lg shadow-rose-950/40 min-w-[170px] text-left">
    <Handle type="source" position={Position.Right} className="!bg-rose-400" />
    <div className="flex items-center gap-2 mb-1">
      <div className="p-1 rounded bg-rose-500/20 text-rose-400">
        <ShieldAlert className="w-3.5 h-3.5" />
      </div>
      <div>
        <span className="text-[10px] font-mono font-bold text-rose-400 block leading-tight">ALERT</span>
        <span className="text-xs font-bold text-white block">{data.id}</span>
      </div>
    </div>
    <div className="text-[11px] text-slate-300 font-medium truncate">{data.type}</div>
    <div className="mt-1 flex items-center justify-between text-[10px] text-slate-400 font-mono">
      <span>{data.severity}</span>
      <span className="text-slate-500">{data.status}</span>
    </div>
  </div>
);

const AccountNodeComponent = ({ data }: { data: any }) => (
  <div className="px-3 py-2.5 rounded-xl bg-slate-900 border-2 border-cyan-500 shadow-lg shadow-cyan-950/40 min-w-[170px] text-left">
    <Handle type="target" position={Position.Left} className="!bg-cyan-400" />
    <Handle type="source" position={Position.Right} className="!bg-cyan-400" />
    <div className="flex items-center gap-2 mb-1">
      <div className="p-1 rounded bg-cyan-500/20 text-cyan-400">
        <User className="w-3.5 h-3.5" />
      </div>
      <div>
        <span className="text-[10px] font-mono font-bold text-cyan-400 block leading-tight">ACCOUNT</span>
        <span className="text-xs font-bold text-white truncate max-w-[110px] block">{data.username || data.id}</span>
      </div>
    </div>
    <div className="text-[11px] text-slate-300 font-medium truncate">{data.department || "No Dept"}</div>
    <div className="mt-1 text-[10px] text-slate-500 font-mono">{data.id}</div>
  </div>
);

const DeviceNodeComponent = ({ data }: { data: any }) => {
  const isCompromised = data.status === "COMPROMISED" || data.status === "ISOLATED";
  const borderCol = isCompromised ? "border-amber-500 shadow-amber-950/40" : "border-emerald-500 shadow-emerald-950/40";
  const badgeCol = isCompromised ? "bg-amber-500/20 text-amber-400" : "bg-emerald-500/20 text-emerald-400";

  return (
    <div className={`px-3 py-2.5 rounded-xl bg-slate-900 border-2 shadow-lg min-w-[170px] text-left ${borderCol}`}>
      <Handle type="target" position={Position.Left} className="!bg-emerald-400" />
      <Handle type="source" position={Position.Right} className="!bg-emerald-400" />
      <div className="flex items-center gap-2 mb-1">
        <div className={`p-1 rounded ${badgeCol}`}>
          <Server className="w-3.5 h-3.5" />
        </div>
        <div>
          <span className="text-[10px] font-mono font-bold text-emerald-400 block leading-tight">DEVICE</span>
          <span className="text-xs font-bold text-white truncate max-w-[110px] block">{data.hostname || data.id}</span>
        </div>
      </div>
      <div className="text-[11px] text-slate-300 font-medium flex items-center justify-between">
        <span>{data.criticality} CRIT</span>
        <span className={`text-[10px] px-1 rounded font-semibold ${badgeCol}`}>{data.status}</span>
      </div>
    </div>
  );
};

const IPNodeComponent = ({ data }: { data: any }) => {
  const isMalicious = data.reputation === "MALICIOUS";
  const isSuspicious = data.reputation === "SUSPICIOUS";
  const repBadge = isMalicious
    ? "bg-rose-500/20 text-rose-400 border-rose-500/40"
    : isSuspicious
    ? "bg-amber-500/20 text-amber-400 border-amber-500/40"
    : "bg-blue-500/20 text-blue-400 border-blue-500/40";

  return (
    <div className="px-3 py-2.5 rounded-xl bg-slate-900 border-2 border-indigo-500 shadow-lg shadow-indigo-950/40 min-w-[170px] text-left">
      <Handle type="target" position={Position.Left} className="!bg-indigo-400" />
      <Handle type="source" position={Position.Right} className="!bg-indigo-400" />
      <div className="flex items-center gap-2 mb-1">
        <div className="p-1 rounded bg-indigo-500/20 text-indigo-400">
          <Network className="w-3.5 h-3.5" />
        </div>
        <div>
          <span className="text-[10px] font-mono font-bold text-indigo-400 block leading-tight">IP ADDRESS</span>
          <span className="text-xs font-bold text-white font-mono block">{data.address}</span>
        </div>
      </div>
      <div className="mt-1 flex items-center justify-between">
        <span className={`text-[10px] px-1.5 py-0.5 rounded border font-semibold ${repBadge}`}>
          {data.reputation || "UNKNOWN"}
        </span>
        <span className="text-[10px] text-slate-500 font-mono">{data.first_seen || ""}</span>
      </div>
    </div>
  );
};

const ThreatIndicatorNodeComponent = ({ data }: { data: any }) => {
  const conf = data.confidence !== undefined ? Math.round(data.confidence * 100) : null;
  return (
    <div className="px-3 py-2.5 rounded-xl bg-slate-900 border-2 border-red-500 shadow-lg shadow-red-950/40 min-w-[180px] text-left">
      <Handle type="target" position={Position.Left} className="!bg-red-400" />
      <div className="flex items-center gap-2 mb-1">
        <div className="p-1 rounded bg-red-500/20 text-red-400">
          <Bug className="w-3.5 h-3.5" />
        </div>
        <div>
          <span className="text-[10px] font-mono font-bold text-red-400 block leading-tight">THREAT INDICATOR</span>
          <span className="text-xs font-bold text-white block">{data.id}</span>
        </div>
      </div>
      <div className="text-[11px] text-slate-200 font-semibold truncate">{data.type}</div>
      <div className="mt-1 flex items-center justify-between text-[10px] font-mono">
        <span className="text-slate-400">{data.source}</span>
        {conf !== null && (
          <span className="text-red-400 font-bold bg-red-950/60 px-1 rounded border border-red-800">
            {conf}% Conf
          </span>
        )}
      </div>
    </div>
  );
};

const nodeTypes = {
  alert: AlertNodeComponent,
  account: AccountNodeComponent,
  device: DeviceNodeComponent,
  ip: IPNodeComponent,
  threatindicator: ThreatIndicatorNodeComponent,
};

// ── Graph Layout Calculator ───────────────────────────────────────────────

function calculateGraphLayout(data: VisualizationData): { nodes: Node[]; edges: Edge[] } {
  const nodesByType: Record<string, GraphNodeData[]> = {
    alert: [],
    account: [],
    device: [],
    ip: [],
    threatindicator: [],
  };

  data.nodes.forEach((n) => {
    const t = n.label.toLowerCase();
    if (nodesByType[t]) {
      nodesByType[t].push(n);
    } else {
      nodesByType.alert.push(n);
    }
  });

  const columnX: Record<string, number> = {
    alert: 50,
    account: 300,
    device: 560,
    ip: 560,
    threatindicator: 850,
  };

  const initialNodes: Node[] = [];

  // Alerts column
  nodesByType.alert.forEach((n, idx) => {
    initialNodes.push({
      id: n.id,
      type: "alert",
      position: { x: columnX.alert, y: 150 + idx * 130 },
      data: n.data,
    });
  });

  // Account column
  nodesByType.account.forEach((n, idx) => {
    initialNodes.push({
      id: n.id,
      type: "account",
      position: { x: columnX.account, y: 120 + idx * 140 },
      data: n.data,
    });
  });

  // Devices & IPs column (separate vertical offsets)
  nodesByType.device.forEach((n, idx) => {
    initialNodes.push({
      id: n.id,
      type: "device",
      position: { x: columnX.device, y: 40 + idx * 120 },
      data: n.data,
    });
  });

  nodesByType.ip.forEach((n, idx) => {
    initialNodes.push({
      id: n.id,
      type: "ip",
      position: { x: columnX.ip, y: 240 + idx * 120 },
      data: n.data,
    });
  });

  // ThreatIndicator column
  nodesByType.threatindicator.forEach((n, idx) => {
    initialNodes.push({
      id: n.id,
      type: "threatindicator",
      position: { x: columnX.threatindicator, y: 100 + idx * 130 },
      data: n.data,
    });
  });

  // Map edges
  const initialEdges: Edge[] = data.edges.map((e) => {
    let strokeColor = "#64748b";
    let animated = false;

    if (e.label === "HAS_INDICATOR") {
      strokeColor = "#ef4444";
      animated = true;
    } else if (e.label === "USED_FROM") {
      strokeColor = "#818cf8";
    } else if (e.label === "ON_ACCOUNT") {
      strokeColor = "#38bdf8";
    } else if (e.label === "ACCESSED") {
      strokeColor = "#34d399";
    } else if (e.label === "CONNECTED_TO") {
      strokeColor = "#fbbf24";
    }

    return {
      id: e.id,
      source: e.source,
      target: e.target,
      label: e.label,
      animated,
      style: { stroke: strokeColor, strokeWidth: 2 },
      markerEnd: {
        type: MarkerType.ArrowClosed,
        color: strokeColor,
      },
      labelStyle: { fill: "#94a3b8", fontSize: 10, fontWeight: 600, fontFamily: "monospace" },
      labelBgStyle: { fill: "#090d16", fillOpacity: 0.9, rx: 4, ry: 4 },
      labelBgPadding: [4, 2] as [number, number],
    };
  });

  return { nodes: initialNodes, edges: initialEdges };
}

// ── GraphViewer Component ─────────────────────────────────────────────────

interface GraphViewerProps {
  data: VisualizationData | null;
  onSelectNode: (node: GraphNodeData) => void;
  isLoading: boolean;
}

export const GraphViewer: React.FC<GraphViewerProps> = ({
  data,
  onSelectNode,
  isLoading,
}) => {
  const { nodes: computedNodes, edges: computedEdges } = useMemo(() => {
    if (!data || data.nodes.length === 0) {
      return { nodes: [], edges: [] };
    }
    return calculateGraphLayout(data);
  }, [data]);

  const [nodes, setNodes, onNodesChange] = useNodesState(computedNodes);
  const [edges, setEdges, onEdgesChange] = useEdgesState(computedEdges);

  // Sync state when props change
  React.useEffect(() => {
    setNodes(computedNodes);
    setEdges(computedEdges);
  }, [computedNodes, computedEdges, setNodes, setEdges]);

  if (isLoading) {
    return (
      <div className="h-full w-full flex items-center justify-center bg-slate-950 text-slate-500 font-mono text-xs">
        <div className="flex flex-col items-center gap-2">
          <div className="w-6 h-6 border-2 border-cyan-500 border-t-transparent rounded-full animate-spin" />
          <span>Extracting graph topology from FalkorDB...</span>
        </div>
      </div>
    );
  }

  if (!data || data.nodes.length === 0) {
    return (
      <div className="h-full w-full flex items-center justify-center bg-slate-950 text-slate-500 text-xs">
        <div className="text-center space-y-1">
          <Info className="w-6 h-6 text-slate-600 mx-auto mb-2" />
          <p className="font-semibold text-slate-400">No Graph Data Loaded</p>
          <p className="text-[11px] text-slate-600">
            Select an alert and trigger an investigation to explore multi-hop relationships.
          </p>
        </div>
      </div>
    );
  }

  return (
    <div className="h-full w-full relative bg-slate-950">
      {/* Top Legend Bar */}
      <div className="absolute top-3 left-3 z-10 bg-slate-900/90 backdrop-blur-md border border-slate-800 rounded-lg p-2.5 shadow-xl text-[11px] flex items-center gap-4">
        <span className="font-mono text-slate-400 font-semibold uppercase tracking-wider text-[10px]">
          FalkorDB Subgraph:
        </span>
        <div className="flex items-center gap-1.5">
          <span className="w-2.5 h-2.5 rounded-full bg-rose-500" />
          <span className="text-slate-300">Alert</span>
        </div>
        <div className="flex items-center gap-1.5">
          <span className="w-2.5 h-2.5 rounded-full bg-cyan-400" />
          <span className="text-slate-300">Account</span>
        </div>
        <div className="flex items-center gap-1.5">
          <span className="w-2.5 h-2.5 rounded-full bg-emerald-400" />
          <span className="text-slate-300">Device</span>
        </div>
        <div className="flex items-center gap-1.5">
          <span className="w-2.5 h-2.5 rounded-full bg-indigo-400" />
          <span className="text-slate-300">IP</span>
        </div>
        <div className="flex items-center gap-1.5">
          <span className="w-2.5 h-2.5 rounded-full bg-red-500" />
          <span className="text-slate-300">ThreatIndicator</span>
        </div>
      </div>

      <ReactFlow
        nodes={nodes}
        edges={edges}
        nodeTypes={nodeTypes}
        onNodesChange={onNodesChange}
        onEdgesChange={onEdgesChange}
        onNodeClick={(_, node) => {
          onSelectNode({
            id: node.id,
            label: (node.type || "node") as any,
            type: node.type || "",
            data: node.data,
          });
        }}
        fitView
        className="cyber-grid"
      >
        <Background color="#1e293b" gap={20} size={1} />
        <Controls className="!bg-slate-900 !border-slate-800 !text-slate-300 fill-slate-300" />
        <MiniMap
          nodeColor={(node) => {
            switch (node.type) {
              case "alert":
                return "#f43f5e";
              case "account":
                return "#06b6d4";
              case "device":
                return "#10b981";
              case "ip":
                return "#6366f1";
              case "threatindicator":
                return "#ef4444";
              default:
                return "#64748b";
            }
          }}
          className="!bg-slate-900/90 !border-slate-800"
          maskColor="rgba(15, 23, 42, 0.7)"
        />
      </ReactFlow>
    </div>
  );
};
