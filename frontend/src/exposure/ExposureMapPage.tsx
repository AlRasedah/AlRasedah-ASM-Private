import { useState } from "react";
import { useSearchParams } from "react-router-dom";
import { useQuery } from "@tanstack/react-query";
import { X } from "lucide-react";
import { api } from "@/api/client";
import type { Asset, Page } from "@/api/types";
import { useOrg } from "@/auth/OrgContext";
import { Card, Empty, PageHead, useDebounced } from "@/components/ui";
import { ASSET_TYPE_LABELS } from "@/lib/format";
import ExposureGraph from "./ExposureGraph";

export default function ExposureMapPage() {
  const { orgId, orgs, setOrgId } = useOrg();
  const [params, setParams] = useSearchParams();
  const start = params.get("asset") ?? undefined;
  const [search, setSearch] = useState("");
  const q = useDebounced(search);
  const found = useQuery({
    queryKey: ["assets", "exposure-start", orgId, q],
    queryFn: () => api<Page<Asset>>("/assets", { query: { organization_id: orgId, q, page_size: 8 } }),
    enabled: !!orgId && q.length >= 2,
  });
  const recenter = (id?: string) => { const n = new URLSearchParams(params); if (id) n.set("asset", id); else n.delete("asset"); setParams(n); };

  return (
    <>
      <PageHead title="Exposure map"
                sub="How your externally visible assets relate, as observed: domains, the addresses they resolve to, the services on them, the web applications they serve, and the findings recorded on them." />
      {!orgId ? (
        <Card>
          <Empty>
            The map shows one organization at a time.{" "}
            {orgs.length ? (
              <select aria-label="Choose an organization" defaultValue="" onChange={(e) => setOrgId(e.target.value || undefined)}>
                <option value="" disabled>Choose an organization…</option>
                {orgs.map((o) => <option key={o.id} value={o.id}>{o.name}</option>)}
              </select>
            ) : "Create an organization and run a scan first."}
          </Empty>
        </Card>
      ) : (
        <div className="stack">
          <Card>
            <div className="row" style={{ gap: 8, flexWrap: "wrap" }}>
              <span className="small muted">Start from</span>
              {start ? (
                <button className="btn sm" onClick={() => recenter(undefined)}><X /> a selected asset — show the organization instead</button>
              ) : <span className="small">the organization's domains</span>}
              <input placeholder="Find an asset to start from…" value={search} onChange={(e) => setSearch(e.target.value)}
                     aria-label="Find a starting asset" style={{ minWidth: 260 }} />
            </div>
            {found.data && q.length >= 2 && (
              <ul className="list small" style={{ margin: "8px -16px -8px" }}>
                {found.data.items.map((a) => (
                  <li key={a.id}><button className="btn ghost sm" onClick={() => { setSearch(""); recenter(a.id); }}>{a.value}</button>
                    <span className="muted">{ASSET_TYPE_LABELS[a.asset_type] ?? a.asset_type}</span></li>
                ))}
                {!found.data.items.length && <li className="muted">No matching asset in this organization.</li>}
              </ul>
            )}
          </Card>
          <ExposureGraph key={`${orgId}:${start ?? ""}`} organizationId={orgId} assetId={start} onRecenter={recenter} />
        </div>
      )}
    </>
  );
}
