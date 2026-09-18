import { createContext, useContext, useEffect, useState, type ReactNode } from "react";
import { useQuery } from "@tanstack/react-query";
import { api } from "@/api/client";
import type { Organization } from "@/api/types";

interface OrgState {
  orgId: string | undefined; // undefined = all organizations
  setOrgId: (id: string | undefined) => void;
  orgs: Organization[];
  orgName: (id: string | null | undefined) => string;
}

const Ctx = createContext<OrgState | null>(null);

export function OrgProvider({ children }: { children: ReactNode }) {
  const [orgId, setOrgIdState] = useState<string | undefined>(() => {
    try {
      return localStorage.getItem("asm.org") || undefined;
    } catch {
      return undefined;
    }
  });
  const { data: orgs = [] } = useQuery({ queryKey: ["orgs"], queryFn: () => api<Organization[]>("/organizations") });

  useEffect(() => {
    if (orgId && orgs.length && !orgs.some((o) => o.id === orgId)) setOrgIdState(undefined);
  }, [orgId, orgs]);

  const setOrgId = (id: string | undefined) => {
    setOrgIdState(id);
    try {
      if (id) localStorage.setItem("asm.org", id);
      else localStorage.removeItem("asm.org");
    } catch {
      /* storage unavailable */
    }
  };
  const orgName = (id: string | null | undefined) => orgs.find((o) => o.id === id)?.name ?? "—";
  return <Ctx.Provider value={{ orgId, setOrgId, orgs, orgName }}>{children}</Ctx.Provider>;
}

export function useOrg(): OrgState {
  const v = useContext(Ctx);
  if (!v) throw new Error("useOrg outside OrgProvider");
  return v;
}
