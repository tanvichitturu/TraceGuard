"use client";

import React, { useEffect, useState, useCallback } from "react";
import { Header } from "../components/Header";
import { AlertsSidebar } from "../components/AlertsSidebar";
import { InvestigationPanel } from "../components/InvestigationPanel";
import { GraphViewer } from "../components/GraphViewer";
import { NodeDetailModal } from "../components/NodeDetailModal";
import {
  Alert,
  InvestigationResult,
  VisualizationData,
  GraphStats,
  GraphNodeData,
} from "../types";
import {
  fetchAlerts,
  runInvestigation,
  fetchVisualization,
  fetchGraphStats,
  checkBackendHealth,
} from "../lib/api";
import { Share2, Split, ShieldAlert, AlertCircle } from "lucide-react";

export default function Home() {
  const [alerts, setAlerts] = useState<Alert[]>([]);
  const [selectedAlertId, setSelectedAlertId] = useState<string | null>(null);
  const [selectedAlert, setSelectedAlert] = useState<Alert | null>(null);
  const [investigation, setInvestigation] = useState<InvestigationResult | null>(null);
  const [visualizationData, setVisualizationData] = useState<VisualizationData | null>(null);
  const [selectedNode, setSelectedNode] = useState<GraphNodeData | null>(null);
  const [stats, setStats] = useState<GraphStats | null>(null);
  const [backendOnline, setBackendOnline] = useState(false);
  const [backendMessage, setBackendMessage] = useState<string>("");
  const [errorMessage, setErrorMessage] = useState<string | null>(null);
  const [loadingAlerts, setLoadingAlerts] = useState(true);
  const [investigating, setInvestigating] = useState(false);
  const [loadingViz, setLoadingViz] = useState(false);
  const [viewMode, setViewMode] = useState<"split" | "investigation" | "graph">("split");

  // Load initial data
  const loadInitialData = useCallback(async () => {
    setLoadingAlerts(true);
    setErrorMessage(null);
    try {
      const health = await checkBackendHealth();
      setBackendOnline(health.online);
      setBackendMessage(health.message || "");

      if (health.online) {
        const [alertsData, statsData] = await Promise.all([
          fetchAlerts(),
          fetchGraphStats().catch((err) => {
            console.warn("Could not fetch graph stats:", err);
            return null;
          }),
        ]);

        setAlerts(alertsData);
        if (statsData) setStats(statsData);

        // Auto-select first alert if none selected
        setSelectedAlertId((prev) => {
          if (!prev && alertsData.length > 0) {
            setSelectedAlert(alertsData[0]);
            return alertsData[0].id;
          }
          return prev;
        });
      } else {
        setErrorMessage(
          `FastAPI backend is offline (${health.message || "Cannot connect to http://127.0.0.1:8000"}). Please ensure the backend is running.`
        );
      }
    } catch (err: any) {
      console.error("Initialization error:", err);
      setBackendOnline(false);
      setErrorMessage(`Failed to connect to backend: ${err.message}`);
    } finally {
      setLoadingAlerts(false);
    }
  }, []);

  useEffect(() => {
    loadInitialData();
  }, [loadInitialData]);

  // When selected alert changes, fetch initial visualization
  useEffect(() => {
    if (!selectedAlertId) return;

    const alertObj = alerts.find((a) => a.id === selectedAlertId) || null;
    setSelectedAlert(alertObj);
    setInvestigation(null);

    // Fetch initial visualization for this alert
    const loadViz = async () => {
      try {
        setLoadingViz(true);
        const viz = await fetchVisualization(selectedAlertId);
        setVisualizationData(viz);
      } catch (err: any) {
        console.error("Failed to load visualization:", err);
      } finally {
        setLoadingViz(false);
      }
    };

    loadViz();
  }, [selectedAlertId, alerts]);

  // Run LangGraph Investigation
  const handleRunInvestigation = async (alertId: string) => {
    try {
      setInvestigating(true);
      const result = await runInvestigation(alertId);
      setInvestigation(result);
      if (result.visualization_data) {
        setVisualizationData(result.visualization_data);
      }
      // Refresh stats in header
      const updatedStats = await fetchGraphStats().catch(() => null);
      if (updatedStats) setStats(updatedStats);
    } catch (err: any) {
      alert("Investigation failed: " + err.message);
    } finally {
      setInvestigating(false);
    }
  };

  return (
    <div className="min-h-screen flex flex-col bg-slate-950 font-sans">
      <Header
        stats={stats}
        backendOnline={backendOnline}
        backendMessage={backendMessage}
        onRefresh={loadInitialData}
      />

      {/* Error alert banner if backend offline */}
      {errorMessage && (
        <div className="bg-rose-500/10 border-b border-rose-500/30 px-4 py-2 text-xs text-rose-300 flex items-center justify-between">
          <div className="flex items-center gap-2">
            <AlertCircle className="w-4 h-4 text-rose-400 shrink-0" />
            <span>{errorMessage}</span>
          </div>
          <button
            type="button"
            onClick={loadInitialData}
            className="px-2.5 py-1 rounded bg-rose-500/20 hover:bg-rose-500/30 text-rose-200 border border-rose-500/40 text-[11px] font-semibold transition-colors cursor-pointer"
          >
            Retry Connection
          </button>
        </div>
      )}

      {/* Main Workspace */}
      <div className="flex-1 flex flex-col lg:flex-row overflow-hidden">
        {/* Left: Alerts Sidebar */}
        <AlertsSidebar
          alerts={alerts}
          selectedAlertId={selectedAlertId}
          onSelectAlert={(id) => setSelectedAlertId(id)}
          isLoading={loadingAlerts}
        />

        {/* Center / Right Content Area */}
        <div className="flex-1 flex flex-col h-[calc(100vh-4rem)] overflow-hidden">
          {/* Top view controls bar */}
          <div className="px-4 py-2 border-b border-slate-800 bg-slate-900/40 flex items-center justify-between text-xs font-mono">
            <div className="flex items-center gap-2 text-slate-400">
              <span className="text-cyan-400 font-bold">ACTIVE TARGET:</span>
              <span className="text-white font-semibold">
                {selectedAlert ? `${selectedAlert.id} (${selectedAlert.type})` : "None"}
              </span>
            </div>

            {/* View Mode Toggle */}
            <div className="hidden sm:flex items-center gap-1 bg-slate-900 border border-slate-800 p-1 rounded-lg">
              <button
                type="button"
                onClick={() => setViewMode("split")}
                className={`px-2.5 py-1 rounded flex items-center gap-1.5 transition-colors cursor-pointer ${
                  viewMode === "split"
                    ? "bg-cyan-500/20 text-cyan-300 font-semibold"
                    : "text-slate-400 hover:text-slate-200"
                }`}
              >
                <Split className="w-3.5 h-3.5" />
                Split View
              </button>
              <button
                type="button"
                onClick={() => setViewMode("investigation")}
                className={`px-2.5 py-1 rounded flex items-center gap-1.5 transition-colors cursor-pointer ${
                  viewMode === "investigation"
                    ? "bg-cyan-500/20 text-cyan-300 font-semibold"
                    : "text-slate-400 hover:text-slate-200"
                }`}
              >
                <ShieldAlert className="w-3.5 h-3.5" />
                Investigation Findings
              </button>
              <button
                type="button"
                onClick={() => setViewMode("graph")}
                className={`px-2.5 py-1 rounded flex items-center gap-1.5 transition-colors cursor-pointer ${
                  viewMode === "graph"
                    ? "bg-cyan-500/20 text-cyan-300 font-semibold"
                    : "text-slate-400 hover:text-slate-200"
                }`}
              >
                <Share2 className="w-3.5 h-3.5" />
                Graph Subgraph
              </button>
            </div>
          </div>

          {/* Dynamic Content Views */}
          <div className="flex-1 min-h-0 flex flex-col xl:flex-row overflow-hidden">
            {/* Investigation Panel View */}
            {(viewMode === "split" || viewMode === "investigation") && (
              <div
                className={`h-full border-r border-slate-800 overflow-hidden ${
                  viewMode === "split" ? "w-full xl:w-1/2" : "w-full"
                }`}
              >
                <InvestigationPanel
                  alert={selectedAlert}
                  investigation={investigation}
                  onRunInvestigation={handleRunInvestigation}
                  isLoading={investigating}
                />
              </div>
            )}

            {/* React Flow Graph Visualizer */}
            {(viewMode === "split" || viewMode === "graph") && (
              <div
                className={`h-full min-h-0 overflow-hidden ${
                  viewMode === "split" ? "w-full xl:w-1/2" : "w-full"
                }`}
              >
                <GraphViewer
                  data={visualizationData}
                  onSelectNode={(node) => setSelectedNode(node)}
                  isLoading={loadingViz}
                />
              </div>
            )}
          </div>
        </div>
      </div>

      {/* Slide-over Node Inspector Modal */}
      <NodeDetailModal
        node={selectedNode}
        onClose={() => setSelectedNode(null)}
      />
    </div>
  );
}
