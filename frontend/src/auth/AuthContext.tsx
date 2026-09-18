import { createContext, useCallback, useContext, useEffect, useMemo, useState, type ReactNode } from "react";
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
  login: (email: string, password: string) => Promise<LoginResult>;
  verifyMfa: (mfaToken: string, code: string) => Promise<void>;
  logout: () => Promise<void>;
  switchTenant: (tenantId: string) => Promise<void>;
  reload: () => Promise<void>;
  can: (permission: string) => boolean;
}

const Ctx = createContext<AuthState | null>(null);

export function AuthProvider({ children }: { children: ReactNode }) {
  const [me, setMe] = useState<Me | null>(null);
  const [ready, setReady] = useState(false);
  const qc = useQueryClient();

  const reload = useCallback(async () => {
    const m = await api<Me>("/auth/me");
    setMe(m);
  }, []);

  useEffect(() => {
    onUnauthenticated(() => {
      setAccessToken(null);
      setMe(null);
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

  const logout = useCallback(async () => {
    try {
      await api("/auth/logout", { method: "POST" });
    } finally {
      setAccessToken(null);
      setMe(null);
      qc.clear();
    }
  }, [qc]);

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
    () => ({ me, ready, login, verifyMfa, logout, switchTenant, reload, can }),
    [me, ready, login, verifyMfa, logout, switchTenant, reload, can],
  );
  return <Ctx.Provider value={value}>{children}</Ctx.Provider>;
}

export function useAuth(): AuthState {
  const v = useContext(Ctx);
  if (!v) throw new Error("useAuth outside AuthProvider");
  return v;
}
