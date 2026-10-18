"use client";

import React, { useState } from "react";
import {
  Alert,
  InvestigationResult,
  ScoreFactor,
  ThreatPath,
  RelatedAccount,
  DeviceInfo,
} from "../types";
import {
  Play,
  ShieldAlert,
  AlertTriangle,
  CheckCircle2,
  HelpCircle,
  Server,
  Network,
  Bug,
  User,
  ArrowRight,
  History,
  TrendingUp,
  FileText,
  Activity,
  Layers,
  Sparkles,
} from "lucide-react";

interface InvestigationPanelProps {
  alert: Alert | null;
  investigation: InvestigationResult | null;
  onRunInvestigation: (alertId: string) => void;
  isLoading: boolean;
}

export const InvestigationPanel: React.FC<InvestigationPanelProps> = ({
  alert,
  investigation,
  onRunInvestigation,
  isLoading,
}) => {
  const [activeTab, setActiveTab] = useState<"overview" | "paths" | "entities" | "history">("overview");

  if (!alert) {
    return (
      <div className="h-full flex flex-col items-center justify-center p-8 text-center text-slate-500">
        <ShieldAlert className="w-12 h-12 text-slate-700 mb-3" />
        <h3 className="text-base font-semibold text-slate-300">Select an Alert to Begin</h3>
        <p className="text-xs text-slate-500 max-w-sm mt-1">
          Choose a security alert from the sidebar to retrieve its context from FalkorDB and initiate multi-hop graph analysis.
        </p>
      </div>
    );
  }

  const getVerdictStyle = (verdict: string) => {
    switch (verdict.toUpperCase()) {
      case "CRITICAL":
        return {
          bg: "bg-rose-500/10 border-rose-500/40 text-rose-300",
          glow: "glow-critical",
          badge: "bg-rose-500 text-white",
          bar: "bg-rose-500",
        };
      case "HIGH":
        return {
          bg: "bg-orange-500/10 border-orange-500/40 text-orange-300",
          glow: "glow-high",
          badge: "bg-orange-500 text-white",
          bar: "bg-orange-500",
        };
      case "MEDIUM":
        return {
          bg: "bg-amber-500/10 border-amber-500/40 text-amber-300",
          glow: "glow-medium",
          badge: "bg-amber-500 text-white",
          bar: "bg-amber-500",
        };
      case "LOW":
        return {
          bg: "bg-blue-500/10 border-blue-500/40 text-blue-300",
          glow: "glow-low",
          badge: "bg-blue-500 text-white",
          bar: "bg-blue-500",
        };
      case "BENIGN":
        return {
          bg: "bg-emerald-500/10 border-emerald-500/40 text-emerald-300",
          glow: "glow-benign",
          badge: "bg-emerald-500 text-white",
          bar: "bg-emerald-500",
        };
      default:
        return {
          bg: "bg-slate-500/10 border-slate-500/40 text-slate-300",
          glow: "",
          badge: "bg-slate-500 text-white",
          bar: "bg-slate-500",
        };
    }
  };

  const vStyle = investigation ? getVerdictStyle(investigation.verdict) : getVerdictStyle(alert.severity);

  return (
    <div className="h-full flex flex-col bg-slate-950/70 overflow-hidden">
      {/* Alert Header & Action Banner */}
      <div className="p-4 border-b border-slate-800 bg-slate-900/60 backdrop-blur-sm flex flex-wrap items-center justify-between gap-4">
        <div>
          <div className="flex items-center gap-2">
            <span className="font-mono text-sm font-bold text-cyan-400">{alert.id}</span>
            <span className="text-xs px-2 py-0.5 rounded-full bg-slate-800 text-slate-300 font-medium">
              {alert.type}
            </span>
            <span className={`text-[10px] font-bold px-2 py-0.5 rounded-full border ${vStyle.bg}`}>
              {alert.severity}
            </span>
          </div>
          <p className="text-xs text-slate-300 mt-1 max-w-xl">{alert.description}</p>
        </div>

        {/* Investigate Button */}
        <button
          type="button"
          onClick={() => onRunInvestigation(alert.id)}
          disabled={isLoading}
          className="flex items-center gap-2 px-4 py-2.5 rounded-xl bg-gradient-to-r from-cyan-600 via-blue-600 to-indigo-600 hover:from-cyan-500 hover:to-indigo-500 text-white font-medium text-xs shadow-lg shadow-cyan-950/50 transition-all hover:scale-[1.02] active:scale-[0.98] disabled:opacity-50 disabled:pointer-events-none cursor-pointer"
        >
          {isLoading ? (
            <>
              <div className="w-4 h-4 border-2 border-white border-t-transparent rounded-full animate-spin" />
              <span>Traversing Graph with LangGraph...</span>
            </>
          ) : (
            <>
              <Play className="w-4 h-4 fill-white" />
              <span>{investigation ? "Re-Investigate Alert" : "Investigate Threat in Graph"}</span>
            </>
          )}
        </button>
      </div>

      {/* Tabs */}
      {investigation && (
        <div className="flex items-center px-4 border-b border-slate-800 bg-slate-950 text-xs font-medium text-slate-400 gap-1 overflow-x-auto">
          <button
            type="button"
            onClick={() => setActiveTab("overview")}
            className={`px-3 py-2.5 border-b-2 transition-colors flex items-center gap-1.5 shrink-0 cursor-pointer ${
              activeTab === "overview"
                ? "border-cyan-400 text-cyan-300"
                : "border-transparent hover:text-slate-200"
            }`}
          >
            <Activity className="w-3.5 h-3.5" />
            Verdict &amp; Score
          </button>
          <button
            type="button"
            onClick={() => setActiveTab("paths")}
            className={`px-3 py-2.5 border-b-2 transition-colors flex items-center gap-1.5 shrink-0 cursor-pointer ${
              activeTab === "paths"
                ? "border-cyan-400 text-cyan-300"
                : "border-transparent hover:text-slate-200"
            }`}
          >
            <Layers className="w-3.5 h-3.5" />
            Threat Paths ({investigation.threat_paths.length})
          </button>
          <button
            type="button"
            onClick={() => setActiveTab("entities")}
            className={`px-3 py-2.5 border-b-2 transition-colors flex items-center gap-1.5 shrink-0 cursor-pointer ${
              activeTab === "entities"
                ? "border-cyan-400 text-cyan-300"
                : "border-transparent hover:text-slate-200"
            }`}
          >
            <Server className="w-3.5 h-3.5" />
            Correlated Entities ({investigation.devices.length + investigation.related_accounts.length})
          </button>
          <button
            type="button"
            onClick={() => setActiveTab("history")}
            className={`px-3 py-2.5 border-b-2 transition-colors flex items-center gap-1.5 shrink-0 cursor-pointer ${
              activeTab === "history"
                ? "border-cyan-400 text-cyan-300"
                : "border-transparent hover:text-slate-200"
            }`}
          >
            <History className="w-3.5 h-3.5" />
            FalkorDB History ({investigation.previous_cases.length})
          </button>
        </div>
      )}

      {/* Scrollable Content Body */}
      <div className="flex-1 overflow-y-auto p-4 space-y-6">
        {!investigation ? (
          // Pre-investigation placeholder view
          <div className="space-y-4">
            <div className="p-4 rounded-xl border border-slate-800 bg-slate-900/40 space-y-3">
              <h4 className="text-xs font-mono uppercase tracking-wider text-slate-400 flex items-center gap-2">
                <User className="w-4 h-4 text-cyan-400" />
                Alert Direct Context (Step 1/2)
              </h4>
              <div className="grid grid-cols-2 sm:grid-cols-3 gap-3 text-xs font-mono">
                <div className="p-2.5 rounded-lg bg-slate-900 border border-slate-800">
                  <span className="text-slate-500 block text-[10px]">TARGET ACCOUNT</span>
                  <span className="text-slate-200 font-bold">{alert.account_username || "Unknown"}</span>
                </div>
                <div className="p-2.5 rounded-lg bg-slate-900 border border-slate-800">
                  <span className="text-slate-500 block text-[10px]">DEPARTMENT</span>
                  <span className="text-slate-200 font-bold">{alert.account_department || "Unassigned"}</span>
                </div>
                <div className="p-2.5 rounded-lg bg-slate-900 border border-slate-800">
                  <span className="text-slate-500 block text-[10px]">OBSERVED AT</span>
                  <span className="text-slate-200">{new Date(alert.timestamp).toLocaleString()}</span>
                </div>
              </div>
            </div>

            <div className="p-6 rounded-2xl border border-dashed border-slate-800 bg-slate-900/20 text-center space-y-3">
              <Sparkles className="w-8 h-8 text-cyan-400 mx-auto" />
              <div>
                <h4 className="text-sm font-semibold text-slate-200">Explainable Multi-Hop Graph Traversal</h4>
                <p className="text-xs text-slate-400 max-w-md mx-auto mt-1 leading-relaxed">
                  Click <strong>&quot;Investigate Threat in Graph&quot;</strong> to trace <em>Alert &rarr; Account &rarr; IP &rarr; ThreatIndicator</em>, correlate related devices, assess transparent risk weights, and persist conclusions to FalkorDB.
                </p>
              </div>
            </div>
          </div>
        ) : (
          // Investigation Results View
          <>
            {activeTab === "overview" && (
              <div className="space-y-5 animate-in fade-in duration-150">
                {/* Verdict & Score Banner */}
                <div className={`p-5 rounded-2xl border ${vStyle.bg} ${vStyle.glow} relative overflow-hidden`}>
                  <div className="flex flex-col sm:flex-row items-start sm:items-center justify-between gap-4">
                    <div>
                      <div className="flex items-center gap-2 mb-1">
                        <span className="text-[10px] font-mono tracking-wider uppercase font-semibold text-slate-400">
                          LangGraph Agent Verdict
                        </span>
                        <span className="text-[10px] font-mono text-slate-500">&bull; ID: {investigation.investigation_id}</span>
                      </div>
                      <h2 className="text-2xl font-black tracking-tight text-white flex items-center gap-2">
                        {investigation.verdict} THREAT
                      </h2>
                    </div>

                    {/* Score Gauge */}
                    <div className="flex items-center gap-4 bg-slate-950/60 px-4 py-2.5 rounded-xl border border-slate-800">
                      <div className="text-right font-mono">
                        <span className="text-[10px] text-slate-400 uppercase tracking-wider block">Risk Score</span>
                        <div className="text-xl font-black text-white">
                          {investigation.risk_score.score}
                          <span className="text-xs text-slate-500 font-normal"> / 100</span>
                        </div>
                      </div>
                      <div className="w-16 h-2 bg-slate-800 rounded-full overflow-hidden">
                        <div
                          className={`h-full ${vStyle.bar}`}
                          style={{ width: `${Math.min(investigation.risk_score.score, 100)}%` }}
                        />
                      </div>
                    </div>
                  </div>

                  {/* Recommended Action */}
                  <div className="mt-4 pt-3 border-t border-slate-800/80 flex items-start gap-2.5 text-xs text-slate-200">
                    <CheckCircle2 className="w-4 h-4 text-cyan-400 shrink-0 mt-0.5" />
                    <div>
                      <strong className="text-cyan-300 font-semibold uppercase tracking-wider text-[10px] block">
                        Recommended Action Playbook:
                      </strong>
                      <p className="mt-0.5 text-slate-200 leading-relaxed font-sans">{investigation.recommendation}</p>
                    </div>
                  </div>
                </div>

                {/* Executive Summary */}
                <div className="p-4 rounded-xl border border-slate-800 bg-slate-900/50 space-y-2">
                  <div className="flex items-center gap-2 text-xs font-mono uppercase tracking-wider text-slate-400">
                    <FileText className="w-3.5 h-3.5 text-cyan-400" />
                    Investigation Summary
                  </div>
                  <p className="text-xs text-slate-300 leading-relaxed whitespace-pre-line font-sans">
                    {investigation.summary}
                  </p>
                </div>

                {/* Transparent Risk Score Breakdown */}
                <div className="p-4 rounded-xl border border-slate-800 bg-slate-900/50 space-y-3">
                  <div className="flex items-center justify-between">
                    <div className="flex items-center gap-2 text-xs font-mono uppercase tracking-wider text-slate-400">
                      <TrendingUp className="w-3.5 h-3.5 text-cyan-400" />
                      Heuristic Risk Factor Breakdown
                    </div>
                    <span className="text-[11px] font-mono text-slate-500">Deterministic Engine</span>
                  </div>

                  <div className="space-y-2">
                    {investigation.risk_score.factors.map((factor, idx) => (
                      <div
                        key={idx}
                        className="p-2.5 rounded-lg bg-slate-900/80 border border-slate-800/80 flex items-center justify-between text-xs"
                      >
                        <div className="space-y-0.5">
                          <span className="font-semibold text-slate-200 block">{factor.name}</span>
                          <span className="text-[11px] text-slate-400 block font-mono">{factor.reason}</span>
                        </div>
                        <span className="font-mono font-bold text-cyan-400 shrink-0 ml-3">
                          +{factor.points} pts
                        </span>
                      </div>
                    ))}
                  </div>

                  {/* Uncertainties & Nuance */}
                  {investigation.uncertainties.length > 0 && (
                    <div className="mt-3 p-3 rounded-lg bg-amber-500/10 border border-amber-500/30 space-y-1.5">
                      <div className="flex items-center gap-1.5 text-amber-300 text-xs font-semibold">
                        <AlertTriangle className="w-3.5 h-3.5" />
                        <span>Uncertainties &amp; Evidence Caveats</span>
                      </div>
                      <ul className="list-disc list-inside space-y-1 text-[11px] text-amber-200/90 font-mono">
                        {investigation.uncertainties.map((unc, i) => (
                          <li key={i}>{unc}</li>
                        ))}
                      </ul>
                    </div>
                  )}
                </div>

                {/* Verified Graph Evidence Findings */}
                <div className="p-4 rounded-xl border border-slate-800 bg-slate-900/50 space-y-3">
                  <div className="text-xs font-mono uppercase tracking-wider text-slate-400 flex items-center gap-2">
                    <CheckCircle2 className="w-3.5 h-3.5 text-emerald-400" />
                    Verified Evidence Findings ({investigation.findings.length})
                  </div>
                  <ul className="space-y-2 text-xs text-slate-300">
                    {investigation.findings.map((finding, idx) => (
                      <li
                        key={idx}
                        className="p-2.5 rounded-lg bg-slate-900 border border-slate-800 flex items-start gap-2.5"
                      >
                        <span className="font-mono text-cyan-400 text-[10px] shrink-0 mt-0.5">
                          [EVID-{idx + 1}]
                        </span>
                        <span className="leading-relaxed font-sans">{finding}</span>
                      </li>
                    ))}
                  </ul>
                </div>
              </div>
            )}

            {/* TAB: Multi-Hop Threat Paths */}
            {activeTab === "paths" && (
              <div className="space-y-4 animate-in fade-in duration-150">
                <div className="text-xs text-slate-400">
                  Multi-hop graph paths followed by the agent in FalkorDB:
                  <span className="font-mono text-cyan-300 block mt-0.5">
                    (Alert:Alert)&rarr;[:ON_ACCOUNT]&rarr;(Account)&rarr;[:USED_FROM]&rarr;(IP)&rarr;[:HAS_INDICATOR]&rarr;(ThreatIndicator)
                  </span>
                </div>

                {investigation.threat_paths.length === 0 ? (
                  <div className="p-8 text-center text-xs text-slate-500 border border-dashed border-slate-800 rounded-xl">
                    No multi-hop threat indicators linked to this alert account.
                  </div>
                ) : (
                  investigation.threat_paths.map((p, idx) => (
                    <div
                      key={idx}
                      className="p-4 rounded-xl border border-slate-800 bg-slate-900/60 space-y-3"
                    >
                      <div className="flex items-center justify-between text-xs font-mono text-slate-400 border-b border-slate-800 pb-2">
                        <span className="text-cyan-400 font-bold">Path #{idx + 1}</span>
                        <span>Confidence: {Math.round((p.indicator?.confidence || 0) * 100)}%</span>
                      </div>

                      {/* Breadcrumbs */}
                      <div className="grid grid-cols-1 sm:grid-cols-3 gap-2 text-xs font-mono">
                        <div className="p-2.5 rounded-lg bg-slate-950 border border-slate-800">
                          <div className="flex items-center gap-1.5 text-cyan-400 text-[10px] mb-1">
                            <User className="w-3 h-3" /> ACCOUNT
                          </div>
                          <span className="text-slate-200 font-bold truncate block">
                            {p.account?.username}
                          </span>
                        </div>

                        <div className="p-2.5 rounded-lg bg-slate-950 border border-slate-800">
                          <div className="flex items-center gap-1.5 text-indigo-400 text-[10px] mb-1">
                            <Network className="w-3 h-3" /> IP ({p.ip?.reputation})
                          </div>
                          <span className="text-slate-200 font-bold truncate block">
                            {p.ip?.address}
                          </span>
                        </div>

                        <div className="p-2.5 rounded-lg bg-slate-950 border border-slate-800">
                          <div className="flex items-center gap-1.5 text-red-400 text-[10px] mb-1">
                            <Bug className="w-3 h-3" /> IOC ({p.indicator?.type})
                          </div>
                          <span className="text-slate-200 font-bold truncate block">
                            {p.indicator?.id} ({p.indicator?.source})
                          </span>
                        </div>
                      </div>
                    </div>
                  ))
                )}
              </div>
            )}

            {/* TAB: Correlated Entities */}
            {activeTab === "entities" && (
              <div className="space-y-5 animate-in fade-in duration-150">
                {/* Related Devices */}
                <div className="space-y-3">
                  <h4 className="text-xs font-mono uppercase tracking-wider text-slate-400 flex items-center gap-2">
                    <Server className="w-4 h-4 text-emerald-400" />
                    Connected Devices ({investigation.devices.length})
                  </h4>
                  {investigation.devices.length === 0 ? (
                    <p className="text-xs text-slate-500">No device connections recorded for this account.</p>
                  ) : (
                    <div className="grid grid-cols-1 sm:grid-cols-2 gap-3">
                      {investigation.devices.map((devEntry, i) => {
                        const d = devEntry.device;
                        const isCompromised = d.status === "COMPROMISED" || d.status === "ISOLATED";
                        return (
                          <div
                            key={i}
                            className="p-3.5 rounded-xl border border-slate-800 bg-slate-900/60 space-y-2 text-xs"
                          >
                            <div className="flex items-center justify-between">
                              <span className="font-bold text-slate-200">{d.hostname}</span>
                              <span
                                className={`text-[10px] px-2 py-0.5 rounded font-bold ${
                                  isCompromised
                                    ? "bg-rose-500/20 text-rose-300 border border-rose-500/40"
                                    : "bg-emerald-500/20 text-emerald-300 border border-emerald-500/40"
                                }`}
                              >
                                {d.status}
                              </span>
                            </div>
                            <div className="text-[11px] font-mono text-slate-400 flex items-center justify-between">
                              <span>Criticality: {d.criticality}</span>
                              <span>ID: {d.id}</span>
                            </div>
                            {devEntry.connected_ips.length > 0 && (
                              <div className="pt-2 border-t border-slate-800/80 text-[11px] font-mono text-slate-400">
                                <span>Connected IPs: </span>
                                <span className="text-slate-200">
                                  {devEntry.connected_ips.map((c) => c.ip.address).join(", ")}
                                </span>
                              </div>
                            )}
                          </div>
                        );
                      })}
                    </div>
                  )}
                </div>

                {/* Related Accounts */}
                <div className="space-y-3">
                  <h4 className="text-xs font-mono uppercase tracking-wider text-slate-400 flex items-center gap-2">
                    <User className="w-4 h-4 text-cyan-400" />
                    Related Accounts via Shared IP / IOC ({investigation.related_accounts.length})
                  </h4>
                  {investigation.related_accounts.length === 0 ? (
                    <p className="text-xs text-slate-500">No other accounts share infrastructure with this alert.</p>
                  ) : (
                    <div className="grid grid-cols-1 sm:grid-cols-2 gap-3">
                      {investigation.related_accounts.map((rel, i) => (
                        <div
                          key={i}
                          className="p-3.5 rounded-xl border border-slate-800 bg-slate-900/60 space-y-2 text-xs"
                        >
                          <div className="flex items-center justify-between">
                            <span className="font-bold text-slate-200">{rel.account.username}</span>
                            <span className="text-[10px] px-2 py-0.5 rounded bg-slate-800 text-cyan-300 font-mono font-semibold">
                              {rel.connection_type}
                            </span>
                          </div>
                          <div className="text-[11px] font-mono text-slate-400">
                            <span>Department: {rel.account.department || "Unknown"}</span>
                          </div>
                          <div className="text-[11px] font-mono text-slate-500">
                            Shared {rel.shared_entity_type}:{" "}
                            <span className="text-slate-300">
                              {rel.shared_entity.address || rel.shared_entity.id}
                            </span>
                          </div>
                        </div>
                      ))}
                    </div>
                  )}
                </div>
              </div>
            )}

            {/* TAB: History */}
            {activeTab === "history" && (
              <div className="space-y-4 animate-in fade-in duration-150">
                <div className="text-xs text-slate-400">
                  Investigations persisted in FalkorDB for this alert:
                </div>
                {investigation.previous_cases.length === 0 ? (
                  <div className="p-8 text-center text-xs text-slate-500 border border-dashed border-slate-800 rounded-xl">
                    This is the first investigation recorded for this alert.
                  </div>
                ) : (
                  investigation.previous_cases.map((pc, idx) => (
                    <div
                      key={idx}
                      className="p-4 rounded-xl border border-slate-800 bg-slate-900/60 space-y-2 text-xs"
                    >
                      <div className="flex items-center justify-between font-mono">
                        <span className="text-cyan-400 font-bold">{pc.investigation.id}</span>
                        <span className="text-slate-400">
                          {new Date(pc.investigation.created_at).toLocaleString()}
                        </span>
                      </div>
                      <div className="flex items-center gap-3">
                        <span className="px-2 py-0.5 rounded font-bold text-[10px] bg-slate-800 text-slate-200">
                          Score: {pc.investigation.risk_score}
                        </span>
                        <span className="px-2 py-0.5 rounded font-bold text-[10px] bg-slate-800 text-cyan-300">
                          Verdict: {pc.investigation.verdict}
                        </span>
                      </div>
                      <p className="text-slate-300 text-[11px] leading-relaxed pt-1">
                        {pc.investigation.summary}
                      </p>
                    </div>
                  ))
                )}
              </div>
            )}
          </>
        )}
      </div>
    </div>
  );
};
