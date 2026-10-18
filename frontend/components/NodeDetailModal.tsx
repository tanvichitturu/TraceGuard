"use client";

import React from "react";
import { X, Copy, Check, Info } from "lucide-react";
import { GraphNodeData } from "../types";

interface NodeDetailModalProps {
  node: GraphNodeData | null;
  onClose: () => void;
}

export const NodeDetailModal: React.FC<NodeDetailModalProps> = ({ node, onClose }) => {
  const [copied, setCopied] = React.useState(false);

  if (!node) return null;

  const handleCopy = () => {
    navigator.clipboard.writeText(JSON.stringify(node.data, null, 2));
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  };

  const getBadgeColor = (type: string) => {
    switch (type.toLowerCase()) {
      case "alert":
        return "bg-rose-500/20 text-rose-300 border-rose-500/50";
      case "account":
        return "bg-cyan-500/20 text-cyan-300 border-cyan-500/50";
      case "device":
        return "bg-emerald-500/20 text-emerald-300 border-emerald-500/50";
      case "ip":
        return "bg-indigo-500/20 text-indigo-300 border-indigo-500/50";
      case "threatindicator":
        return "bg-red-500/20 text-red-300 border-red-500/50";
      default:
        return "bg-slate-500/20 text-slate-300 border-slate-500/50";
    }
  };

  return (
    <div className="fixed inset-y-0 right-0 w-96 bg-slate-950/95 backdrop-blur-xl border-l border-slate-800 shadow-2xl z-50 flex flex-col animate-in slide-in-from-right duration-200">
      {/* Header */}
      <div className="p-4 border-b border-slate-800 flex items-center justify-between">
        <div className="flex items-center gap-2">
          <span className={`text-[11px] px-2.5 py-0.5 rounded-full border font-bold uppercase tracking-wider ${getBadgeColor(node.label)}`}>
            {node.label}
          </span>
          <h3 className="text-sm font-bold text-white truncate max-w-[180px]">
            {node.data.id || node.data.address || node.data.hostname || node.id}
          </h3>
        </div>
        <div className="flex items-center gap-1">
          <button
            type="button"
            onClick={handleCopy}
            className="p-1.5 text-slate-400 hover:text-white hover:bg-slate-800 rounded-lg transition-colors cursor-pointer"
            title="Copy JSON"
          >
            {copied ? <Check className="w-4 h-4 text-emerald-400" /> : <Copy className="w-4 h-4" />}
          </button>
          <button
            type="button"
            onClick={onClose}
            className="p-1.5 text-slate-400 hover:text-white hover:bg-slate-800 rounded-lg transition-colors cursor-pointer"
          >
            <X className="w-4 h-4" />
          </button>
        </div>
      </div>

      {/* Body */}
      <div className="flex-1 overflow-y-auto p-4 space-y-4">
        <div>
          <h4 className="text-[11px] font-mono text-slate-400 uppercase tracking-wider mb-2 flex items-center gap-1.5">
            <Info className="w-3.5 h-3.5 text-cyan-400" />
            FalkorDB Node Attributes
          </h4>
          <div className="bg-slate-900/80 rounded-xl border border-slate-800 divide-y divide-slate-800/80 overflow-hidden text-xs">
            {Object.entries(node.data).map(([key, val]) => (
              <div key={key} className="p-2.5 flex items-start justify-between gap-3 font-mono">
                <span className="text-slate-400 shrink-0 font-medium">{key}</span>
                <span className="text-slate-200 text-right break-all">
                  {typeof val === "object" ? JSON.stringify(val) : String(val)}
                </span>
              </div>
            ))}
          </div>
        </div>

        <div>
          <h4 className="text-[11px] font-mono text-slate-400 uppercase tracking-wider mb-2">
            Raw JSON Representation
          </h4>
          <pre className="p-3 bg-slate-900 border border-slate-800 rounded-xl text-[11px] font-mono text-slate-300 overflow-x-auto">
            {JSON.stringify(node.data, null, 2)}
          </pre>
        </div>
      </div>
    </div>
  );
};
