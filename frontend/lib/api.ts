import { Alert, InvestigationResult, VisualizationData, GraphStats } from "../types";

export const API_BASE = process.env.NEXT_PUBLIC_API_URL || "http://127.0.0.1:8000";

async function parseResponse<T>(res: Response, endpoint: string): Promise<T> {
  if (!res.ok) {
    let errorDetail = res.statusText;
    try {
      const errorJson = await res.json();
      errorDetail = errorJson.detail || errorJson.message || JSON.stringify(errorJson);
    } catch {
      try {
        const text = await res.text();
        if (text) errorDetail = text;
      } catch {
        // use statusText
      }
    }
    throw new Error(`API Error [${res.status} ${endpoint}]: ${errorDetail}`);
  }

  try {
    return (await res.json()) as T;
  } catch (err: any) {
    throw new Error(`Failed to parse JSON response from ${endpoint}: ${err.message}`);
  }
}

export async function fetchAlerts(): Promise<Alert[]> {
  try {
    const res = await fetch(`${API_BASE}/api/alerts`, { cache: "no-store" });
    return await parseResponse<Alert[]>(res, "/api/alerts");
  } catch (err: any) {
    console.error("fetchAlerts failed:", err);
    throw err;
  }
}

export async function fetchAlertContext(alertId: string): Promise<any> {
  try {
    const res = await fetch(`${API_BASE}/api/alerts/${encodeURIComponent(alertId)}`, {
      cache: "no-store",
    });
    return await parseResponse<any>(res, `/api/alerts/${alertId}`);
  } catch (err: any) {
    console.error(`fetchAlertContext for ${alertId} failed:`, err);
    throw err;
  }
}

export async function runInvestigation(alertId: string): Promise<InvestigationResult> {
  try {
    const res = await fetch(`${API_BASE}/api/investigate/${encodeURIComponent(alertId)}`, {
      method: "POST",
      headers: {
        Accept: "application/json",
      },
      cache: "no-store",
    });
    return await parseResponse<InvestigationResult>(res, `/api/investigate/${alertId}`);
  } catch (err: any) {
    console.error(`runInvestigation for ${alertId} failed:`, err);
    throw err;
  }
}

export async function fetchInvestigationHistory(alertId: string): Promise<{
  previous_investigations: any[];
  count: number;
}> {
  try {
    const res = await fetch(
      `${API_BASE}/api/investigations/${encodeURIComponent(alertId)}/history`,
      { cache: "no-store" }
    );
    return await parseResponse<{ previous_investigations: any[]; count: number }>(
      res,
      `/api/investigations/${alertId}/history`
    );
  } catch (err: any) {
    console.error(`fetchInvestigationHistory for ${alertId} failed:`, err);
    throw err;
  }
}

export async function fetchVisualization(alertId: string): Promise<VisualizationData> {
  try {
    const res = await fetch(`${API_BASE}/api/visualize/${encodeURIComponent(alertId)}`, {
      cache: "no-store",
    });
    return await parseResponse<VisualizationData>(res, `/api/visualize/${alertId}`);
  } catch (err: any) {
    console.error(`fetchVisualization for ${alertId} failed:`, err);
    throw err;
  }
}

export async function fetchGraphStats(): Promise<GraphStats> {
  try {
    const res = await fetch(`${API_BASE}/api/graph/stats`, { cache: "no-store" });
    return await parseResponse<GraphStats>(res, "/api/graph/stats");
  } catch (err: any) {
    console.error("fetchGraphStats failed:", err);
    throw err;
  }
}

export async function reseedGraph(): Promise<{ status: string; message: string }> {
  try {
    const res = await fetch(`${API_BASE}/api/graph/reseed`, {
      method: "POST",
      headers: {
        Accept: "application/json",
      },
      cache: "no-store",
    });
    return await parseResponse<{ status: string; message: string }>(res, "/api/graph/reseed");
  } catch (err: any) {
    console.error("reseedGraph failed:", err);
    throw err;
  }
}

export async function checkBackendHealth(): Promise<{ online: boolean; message?: string }> {
  try {
    const res = await fetch(`${API_BASE}/health`, { cache: "no-store" });
    if (res.ok) {
      const data = await res.json().catch(() => ({}));
      return { online: true, message: data.service || "traceguard-backend" };
    }
    return { online: false, message: `HTTP ${res.status}: ${res.statusText}` };
  } catch (err: any) {
    return { online: false, message: err.message || "Failed to reach backend" };
  }
}
