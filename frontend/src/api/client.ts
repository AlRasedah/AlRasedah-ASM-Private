// Minimal API client.
// - The access token lives only in memory (never localStorage).
// - The refresh token is an HttpOnly cookie; refresh uses a double-submit CSRF header.
// - Concurrent 401s trigger a single refresh (the server rotates refresh tokens and
//   treats reuse as theft, so refreshes must never run in parallel).

export class ApiError extends Error {
  status: number;
  code: string;
  details?: unknown;
  constructor(status: number, code: string, message: string, details?: unknown) {
    super(message);
    this.status = status;
    this.code = code;
    this.details = details;
  }
}

let accessToken: string | null = null;
let refreshing: Promise<boolean> | null = null;
let onSessionLost: (() => void) | null = null;

export function setAccessToken(token: string | null) {
  accessToken = token;
}
export function hasAccessToken() {
  return accessToken !== null;
}
export function onUnauthenticated(cb: () => void) {
  onSessionLost = cb;
}

function csrfToken(): string {
  const m = document.cookie.match(/(?:^|;\s*)asm_csrf=([^;]+)/);
  return m ? decodeURIComponent(m[1]) : "";
}

export async function refreshSession(): Promise<boolean> {
  if (!refreshing) {
    refreshing = (async () => {
      try {
        const r = await fetch("/api/v1/auth/refresh", {
          method: "POST",
          credentials: "same-origin",
          headers: { "X-CSRF-Token": csrfToken() },
        });
        if (!r.ok) {
          accessToken = null;
          return false;
        }
        const body = await r.json();
        accessToken = body.access_token;
        return true;
      } catch {
        return false;
      } finally {
        setTimeout(() => (refreshing = null), 0);
      }
    })();
  }
  return refreshing;
}

type Query = Record<string, string | number | boolean | undefined | null | (string | number)[]>;

export function qs(params?: Query): string {
  if (!params) return "";
  const u = new URLSearchParams();
  for (const [k, v] of Object.entries(params)) {
    if (v === undefined || v === null || v === "") continue;
    if (Array.isArray(v)) v.forEach((x) => u.append(k, String(x)));
    else u.append(k, String(v));
  }
  const s = u.toString();
  return s ? `?${s}` : "";
}

async function parseError(r: Response): Promise<ApiError> {
  try {
    const body = await r.json();
    const e = body?.error ?? {};
    return new ApiError(r.status, e.code ?? "error", e.message ?? r.statusText, e.details);
  } catch {
    return new ApiError(r.status, "error", r.statusText || "Request failed");
  }
}

export async function api<T = unknown>(
  path: string,
  opts: { method?: string; body?: unknown; query?: Query; raw?: boolean } = {},
  retry = true,
): Promise<T> {
  const headers: Record<string, string> = {};
  if (accessToken) headers.Authorization = `Bearer ${accessToken}`;
  if (opts.body !== undefined) headers["Content-Type"] = "application/json";
  const r = await fetch(`/api/v1${path}${qs(opts.query)}`, {
    method: opts.method ?? "GET",
    headers,
    credentials: "same-origin",
    body: opts.body !== undefined ? JSON.stringify(opts.body) : undefined,
  });
  if (r.status === 401 && retry && !path.startsWith("/auth/login") && !path.startsWith("/auth/refresh")) {
    if (await refreshSession()) return api<T>(path, opts, false);
    onSessionLost?.();
  }
  if (!r.ok) throw await parseError(r);
  if (opts.raw) return (await r.blob()) as T;
  if (r.status === 204) return undefined as T;
  return (await r.json()) as T;
}

export async function download(path: string, query?: Query, filename?: string) {
  const blob = await api<Blob>(path, { query, raw: true });
  const url = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url;
  a.download = filename ?? path.split("/").pop() ?? "download";
  document.body.appendChild(a);
  a.click();
  a.remove();
  setTimeout(() => URL.revokeObjectURL(url), 5000);
}

export async function openBlob(path: string) {
  const blob = await api<Blob>(path, { raw: true });
  const url = URL.createObjectURL(blob);
  window.open(url, "_blank", "noopener");
  setTimeout(() => URL.revokeObjectURL(url), 60_000);
}
