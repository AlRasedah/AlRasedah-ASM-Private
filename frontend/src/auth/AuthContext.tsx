import { createContext, useCallback, useContext, useEffect, useMemo, useRef, useState, type ReactNode } from "react";
import { useQueryClient } from "@tanstack/react-query";
import { api, hasAccessToken, onUnauthenticated, refreshSession, setAccessToken } from "@/api/client";
import type { Me } from "@/api/types";

interface LoginResult {
  mfaRequired: boolean;
  mfaToken?: string;
}

interface AuthState {
  me: Me | null;
  ready: boolean;
  /** Why the last session ended, when it was not the user clicking Sign out. */
  endedReason: string | null;
  login: (email: string, password: string) => Promise<LoginResult>;
  verifyMfa: (mfaToken: string, code: string) => Promise<void>;
  logout: () => Promise<void>;
  switchTenant: (tenantId: string) => Promise<void>;
  reload: () => Promise<void>;
  can: (permission: string) => boolean;
}

/** Real user interaction — not the app's own polling, which never stops on its own. */
const ACTIVITY = ["pointerdown", "keydown", "wheel", "touchstart"] as const;

const Ctx = createContext<AuthState | null>(null);

export function AuthProvider({ children }: { children: ReactNode }) {
  const [me, setMe] = useState<Me | null>(null);
  const [ready, setReady] = useState(false);
  const [endedReason, setEndedReason] = useState<string | null>(null);
  const qc = useQueryClient();

  const reload = useCallback(async () => {
    const m = await api<Me>("/auth/me");
    setMe(m);
  }, []);

  useEffect(() => {
    onUnauthenticated(() => {
      setAccessToken(null);
      setMe(null);
      // The server ends a session on its own for idleness, expiry, a revoked membership
      // or a reused refresh token. Say that it ended rather than showing a bare login page.
      // Keep a reason we already have: signing out for idleness leaves in-flight polls that
      // 401 a moment later, and the specific message is the useful one.
      setEndedReason((prev) => prev ?? "Your session has ended. Please sign in again.");
      qc.clear();
    });
    // Restore a session from the refresh cookie after a page reload.
    (async () => {
      if (!hasAccessToken() && (await refreshSession())) {
        try {
          await reload();
        } catch {
          setMe(null);
        }
      }
      setReady(true);
    })();
  }, [qc, reload]);

  const login = useCallback(
    async (email: string, password: string): Promise<LoginResult> => {
      const r = await api<{ access_token: string | null; mfa_required: boolean; mfa_token: string | null }>(
        "/auth/login",
        { method: "POST", body: { email, password } },
      );
      if (r.mfa_required) return { mfaRequired: true, mfaToken: r.mfa_token ?? undefined };
      setAccessToken(r.access_token);
      setEndedReason(null);
      await reload();
      return { mfaRequired: false };
    },
    [reload],
  );

  const verifyMfa = useCallback(
    async (mfaToken: string, code: string) => {
      const r = await api<{ access_token: string }>("/auth/mfa/verify", { method: "POST", body: { mfa_token: mfaToken, code } });
      setAccessToken(r.access_token);
      await reload();
    },
    [reload],
  );

  const endSession = useCallback(async (reason: string | null) => {
    try {
      await api("/auth/logout", { method: "POST" });
    } catch {
      /* the session may already be gone server-side; sign out locally regardless */
    } finally {
      setAccessToken(null);
      setMe(null);
      setEndedReason(reason);
      qc.clear();
    }
  }, [qc]);

  // Exposed without arguments: a click handler must not pass its event as the reason.
  const logout = useCallback(() => endSession(null), [endSession]);

  // Idle timeout. The deployment sets the window (`session_idle_minutes`); the server
  // enforces the same limit on its side, so this is the part that makes it visible —
  // and the part that matters for an open tab, whose polling would otherwise keep the
  // session alive for as long as the browser is running.
  // `?? 30` rather than `?? 0`: a deployment that wants no timeout sends 0, but an API
  // older than this feature sends nothing at all — and failing open there would disable
  // the timeout silently on a half-upgraded stack, which is the case that matters.
  const idleMinutes = me?.session_idle_minutes ?? 30;
  const lastActivity = useRef(Date.now());
  useEffect(() => {
    if (!me || idleMinutes <= 0) return;
    const limit = idleMinutes * 60_000;
    const seen = () => { lastActivity.current = Date.now(); };
    const onVisible = () => { if (document.visibilityState === "visible") seen(); };
    for (const e of ACTIVITY) window.addEventListener(e, seen, { passive: true });
    document.addEventListener("visibilitychange", onVisible);
    lastActivity.current = Date.now();
    const timer = window.setInterval(() => {
      if (Date.now() - lastActivity.current >= limit) {
        void endSession(`You were signed out after ${idleMinutes} minutes without activity.`);
      }
    }, Math.min(30_000, limit));
    return () => {
      for (const e of ACTIVITY) window.removeEventListener(e, seen);
      document.removeEventListener("visibilitychange", onVisible);
      window.clearInterval(timer);
    };
  }, [me, idleMinutes, endSession]);

  const switchTenant = useCallback(
    async (tenantId: string) => {
      const r = await api<{ access_token: string }>("/auth/switch-tenant", { method: "POST", body: { tenant_id: tenantId } });
      setAccessToken(r.access_token);
      qc.clear();
      localStorage.removeItem("asm.org");
      await reload();
    },
    [qc, reload],
  );

  const can = useCallback((p: string) => !!me?.permissions.includes(p), [me]);

  const value = useMemo(
    () => ({ me, ready, endedReason, login, verifyMfa, logout, switchTenant, reload, can }),
    [me, ready, endedReason, login, verifyMfa, logout, switchTenant, reload, can],
  );
  return <Ctx.Provider value={value}>{children}</Ctx.Provider>;
}

export function useAuth(): AuthState {
  const v = useContext(Ctx);
  if (!v) throw new Error("useAuth outside AuthProvider");
  return v;
}
