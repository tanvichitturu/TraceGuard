"use client";

import React, { useState } from "react";
import { Alert } from "../types";
import { Search, Filter, ShieldAlert, User, Clock, ChevronRight } from "lucide-react";

interface AlertsSidebarProps {
  alerts: Alert[];
  selectedAlertId: string | null;
  onSelectAlert: (alertId: string) => void;
  isLoading: boolean;
}

export const AlertsSidebar: React.FC<AlertsSidebarProps> = ({
  alerts,
  selectedAlertId,
  onSelectAlert,
  isLoading,
}) => {
  const [searchQuery, setSearchQuery] = useState("");
  const [severityFilter, setSeverityFilter] = useState<string>("ALL");

  const filteredAlerts = alerts.filter((alert) => {
    const matchesSearch =
      alert.id.toLowerCase().includes(searchQuery.toLowerCase()) ||
      alert.type.toLowerCase().includes(searchQuery.toLowerCase()) ||
      (alert.account_username && alert.account_username.toLowerCase().includes(searchQuery.toLowerCase())) ||
      alert.description.toLowerCase().includes(searchQuery.toLowerCase());

    const matchesSeverity =
      severityFilter === "ALL" || alert.severity.toUpperCase() === severityFilter;

    return matchesSearch && matchesSeverity;
  });

  const getSeverityBadge = (severity: string) => {
    switch (severity.toUpperCase()) {
      case "CRITICAL":
        return "bg-rose-500/20 text-rose-300 border-rose-500/40";
      case "HIGH":
        return "bg-orange-500/20 text-orange-300 border-orange-500/40";
      case "MEDIUM":
        return "bg-amber-500/20 text-amber-300 border-amber-500/40";
      case "LOW":
        return "bg-blue-500/20 text-blue-300 border-blue-500/40";
      default:
        return "bg-slate-500/20 text-slate-300 border-slate-500/40";
    }
  };

  return (
    <div className="w-full lg:w-96 flex flex-col h-[calc(100vh-4rem)] border-r border-slate-800 bg-slate-950/60 shrink-0">
      {/* Search & Filter Header */}
      <div className="p-4 border-b border-slate-800 space-y-3">
        <div className="flex items-center justify-between">
          <div className="flex items-center gap-2">
            <ShieldAlert className="w-4 h-4 text-cyan-400" />
            <h2 className="text-sm font-semibold tracking-wide uppercase text-slate-200">
              Security Alerts ({filteredAlerts.length})
            </h2>
          </div>
          <span className="text-[11px] font-mono text-slate-400">FalkorDB Synced</span>
        </div>

        {/* Search input */}
        <div className="relative">
          <Search className="w-4 h-4 text-slate-500 absolute left-3 top-2.5 pointer-events-none" />
          <input
            type="text"
            placeholder="Search by ID, type, user, keyword..."
            value={searchQuery}
            onChange={(e) => setSearchQuery(e.target.value)}
            className="w-full bg-slate-900 border border-slate-800 focus:border-cyan-500 rounded-lg pl-9 pr-3 py-2 text-xs text-slate-200 placeholder-slate-500 focus:outline-none transition-colors"
          />
        </div>

        {/* Severity filter pills */}
        <div className="flex items-center gap-1.5 overflow-x-auto pb-1 text-[11px]">
          {["ALL", "CRITICAL", "HIGH", "MEDIUM", "LOW"].map((sev) => (
            <button
              type="button"
              key={sev}
              onClick={() => setSeverityFilter(sev)}
              className={`px-2 py-1 rounded-md font-medium transition-colors shrink-0 cursor-pointer ${
                severityFilter === sev
                  ? "bg-cyan-500/20 text-cyan-300 border border-cyan-500/50"
                  : "bg-slate-900 text-slate-400 border border-slate-800 hover:text-slate-200"
              }`}
            >
              {sev}
            </button>
          ))}
        </div>
      </div>

      {/* Alerts list */}
      <div className="flex-1 overflow-y-auto divide-y divide-slate-800/60 p-2 space-y-2">
        {isLoading ? (
          <div className="p-8 text-center text-xs text-slate-500 animate-pulse">
            Loading alerts from FalkorDB...
          </div>
        ) : filteredAlerts.length === 0 ? (
          <div className="p-8 text-center text-xs text-slate-500">
            No matching alerts found in graph.
          </div>
        ) : (
          filteredAlerts.map((alert) => {
            const isSelected = alert.id === selectedAlertId;
            return (
              <div
                key={alert.id}
                onClick={() => onSelectAlert(alert.id)}
                className={`group p-3 rounded-xl border transition-all cursor-pointer relative ${
                  isSelected
                    ? "bg-slate-900/90 border-cyan-500/60 shadow-lg shadow-cyan-950/40"
                    : "bg-slate-900/40 border-slate-800/80 hover:bg-slate-900/70 hover:border-slate-700"
                }`}
              >
                {/* Active indicator bar */}
                {isSelected && (
                  <div className="absolute left-0 top-2 bottom-2 w-1 bg-cyan-400 rounded-r" />
                )}

                <div className="flex items-center justify-between mb-1.5 pl-1.5">
                  <div className="flex items-center gap-2">
                    <span className="font-mono text-xs font-bold text-slate-200">
                      {alert.id}
                    </span>
                    <span
                      className={`text-[10px] px-2 py-0.5 rounded-full border font-semibold ${getSeverityBadge(
                        alert.severity
                      )}`}
                    >
                      {alert.severity}
                    </span>
                  </div>
                  <ChevronRight
                    className={`w-4 h-4 transition-transform ${
                      isSelected
                        ? "text-cyan-400 translate-x-0.5"
                        : "text-slate-600 group-hover:text-slate-400"
                    }`}
                  />
                </div>

                <div className="pl-1.5 space-y-1">
                  <p className="text-xs font-medium text-slate-200 leading-snug">
                    {alert.type}
                  </p>
                  <p className="text-[11px] text-slate-400 line-clamp-2 leading-relaxed">
                    {alert.description}
                  </p>
                </div>

                <div className="mt-2.5 pt-2 border-t border-slate-800/60 flex items-center justify-between text-[11px] text-slate-500 pl-1.5 font-mono">
                  <div className="flex items-center gap-1.5 text-slate-400 truncate max-w-[180px]">
                    <User className="w-3 h-3 text-cyan-400 shrink-0" />
                    <span className="truncate">
                      {alert.account_username || "Unknown account"}
                    </span>
                  </div>
                  <div className="flex items-center gap-1 shrink-0">
                    <Clock className="w-3 h-3 text-slate-500" />
                    <span>{new Date(alert.timestamp).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' })}</span>
                  </div>
                </div>
              </div>
            );
          })
        )}
      </div>
    </div>
  );
};
