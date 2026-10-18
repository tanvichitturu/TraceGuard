"use client";

import React, { useState } from "react";
import { ShieldAlert, Database, RefreshCw, Cpu, Activity, AlertTriangle } from "lucide-react";
import { GraphStats } from "../types";
import { reseedGraph } from "../lib/api";

interface HeaderProps {
  stats: GraphStats | null;
  backendOnline: boolean;
  backendMessage?: string;
  onRefresh: () => void;
}

export const Header: React.FC<HeaderProps> = ({ stats, backendOnline, backendMessage, onRefresh }) => {
  const [reseeding, setReseeding] = useState(false);

  const handleReseed = async () => {
    if (confirm("Reset graph database to deterministic seed telemetry?")) {
      try {
        setReseeding(true);
        await reseedGraph();
        onRefresh();
      } catch (err: any) {
        alert("Reseed failed: " + err.message);
      } finally {
        setReseeding(false);
      }
    }
  };

  return (
    <header className="border-b border-slate-800 bg-slate-950/80 backdrop-blur-md sticky top-0 z-40">
      {/* Simulation Notice Banner */}
      <div className="bg-amber-500/10 border-b border-amber-500/20 px-4 py-1.5 text-xs text-amber-300 flex items-center justify-between">
        <div className="flex items-center gap-2">
          <AlertTriangle className="w-3.5 h-3.5 text-amber-400 shrink-0" />
          <span>
            <strong className="font-semibold uppercase tracking-wider">Simulated Security Telemetry:</strong> Synthetic dataset crafted for Graph Hacks 2026. Non-production environment.
          </span>
        </div>
        <div className="flex items-center gap-4 text-xs font-mono">
          <span className="flex items-center gap-1.5" title={backendMessage || (backendOnline ? "API Online" : "API Offline")}>
            <span className={`w-2 h-2 rounded-full ${backendOnline ? "bg-emerald-400 animate-pulse" : "bg-rose-500"}`} />
            {backendOnline ? "API Online" : "API Offline"}
          </span>
          <span className="text-slate-400">FalkorDB Named Graph: <span className="text-cyan-400 font-semibold">traceguard</span></span>
        </div>
      </div>

      {/* Main Header Bar */}
      <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 h-16 flex items-center justify-between">
        <div className="flex items-center gap-3">
          <div className="w-10 h-10 rounded-xl bg-gradient-to-tr from-cyan-600 via-blue-600 to-indigo-600 p-0.5 shadow-lg shadow-cyan-500/20">
            <div className="w-full h-full bg-slate-950 rounded-[10px] flex items-center justify-center">
              <ShieldAlert className="w-5 h-5 text-cyan-400" />
            </div>
          </div>
          <div>
            <div className="flex items-center gap-2">
              <span className="text-lg font-bold tracking-tight text-white flex items-center gap-1.5">
                Trace<span className="text-cyan-400">Guard</span>
              </span>
              <span className="px-2 py-0.5 text-[10px] font-semibold bg-cyan-950/70 border border-cyan-800/80 text-cyan-300 rounded-full uppercase tracking-wider">
                Graph Hacks 2026
              </span>
            </div>
            <p className="text-xs text-slate-400 hidden sm:block">
              Explainable Threat Investigation Agent &bull; Powered by FalkorDB &amp; LangGraph
            </p>
          </div>
        </div>

        {/* Right side stats & actions */}
        <div className="flex items-center gap-3">
          {stats && (
            <div className="hidden md:flex items-center gap-3 px-3 py-1.5 bg-slate-900/80 border border-slate-800 rounded-lg text-xs font-mono">
              <div className="flex items-center gap-1.5 text-slate-300">
                <Database className="w-3.5 h-3.5 text-cyan-400" />
                <span>{stats.total_nodes} nodes</span>
              </div>
              <span className="text-slate-600">|</span>
              <div className="flex items-center gap-1.5 text-slate-300">
                <Activity className="w-3.5 h-3.5 text-indigo-400" />
                <span>{stats.total_relationships} edges</span>
              </div>
            </div>
          )}

          <button
            type="button"
            onClick={onRefresh}
            title="Refresh Data"
            className="p-2 text-slate-400 hover:text-white bg-slate-900 hover:bg-slate-800 border border-slate-800 rounded-lg transition-colors cursor-pointer"
          >
            <RefreshCw className="w-4 h-4" />
          </button>

          <button
            type="button"
            onClick={handleReseed}
            disabled={reseeding}
            className="flex items-center gap-1.5 px-3 py-2 text-xs font-medium text-slate-200 bg-slate-900 hover:bg-slate-800 border border-slate-700/80 rounded-lg transition-colors disabled:opacity-50 cursor-pointer"
          >
            <Cpu className="w-3.5 h-3.5 text-cyan-400" />
            <span>{reseeding ? "Reseeding..." : "Reseed Graph"}</span>
          </button>
        </div>
      </div>
    </header>
  );
};
