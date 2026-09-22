import type { ReactNode } from "react";
import { Link } from "react-router-dom";
import { Building2 } from "lucide-react";
import { useAuth } from "@/auth/AuthContext";
import { useOrg } from "@/auth/OrgContext";

/**
 * Says when a page is empty because the *tenant* is, not because of the filters.
 *
 * Every query runs in a tenant-scoped session, so a user signed in to a tenant
 * that holds no data gets working pages with nothing in them and no explanation.
 * That is what a second administrator created in a tenant of their own sees: a
 * full sidebar, no scans, no assets, and no hint that they are in the wrong
 * place. Returns null when the tenant does have organizations, so callers fall
 * back to their own "no results" message.
 */
export function useTenantEmpty(): ReactNode | null {
  const { orgs } = useOrg();
  const { me, can } = useAuth();
  if (orgs.length) return null;

  const others = me?.memberships.filter((m) => m.tenant.id !== me.tenant?.id) ?? [];
  return (
    <div className="empty">
      <Building2 />
      <div className="stack">
        {me?.tenant ? (
          <p>
            Nothing has been added to <strong>{me.tenant.name}</strong> yet — this tenant has no organizations, so
            there is no data to show.
          </p>
        ) : (
          <p>You are not signed in to a tenant, so no data is visible.</p>
        )}
        {others.length > 0 && (
          <p className="muted small">
            You are also a member of {others.map((m) => m.tenant.name).join(", ")} — switch tenant in the top bar.
          </p>
        )}
        {!me?.tenant && can("tenants:admin") && (
          <p className="muted small">Open a tenant from <Link to="/platform">Platform → Tenants</Link>.</p>
        )}
        {me?.tenant && can("orgs:write") && (
          <div><Link className="btn primary" to="/organizations">Create an organization</Link></div>
        )}
      </div>
    </div>
  );
}
