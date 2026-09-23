/**
 * Threat Center, screenshots and exposure map: permissions, empty states, errors,
 * disabled features and tenant switching. The API is mocked; the point is what a
 * person with a given role sees and can do.
 */
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { cleanup, fireEvent, render, screen, waitFor } from "@testing-library/react";
import { MemoryRouter } from "react-router-dom";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { me, mockApi } from "./fixtures";
import { api, ApiError } from "@/api/client";

vi.mock("@/api/client", async () => {
  const actual = await vi.importActual<typeof import("@/api/client")>("@/api/client");
  return {
    ...actual,
    api: vi.fn(async (path: string) => mockApi(path)),
    refreshSession: vi.fn(async () => true),
    hasAccessToken: () => false,
    download: vi.fn(),
    openBlob: vi.fn(),
  };
});

import App from "@/App";
import { AuthProvider } from "@/auth/AuthContext";

type Handler = (path: string, opts?: { method?: string; body?: unknown; query?: Record<string, unknown> }) => unknown;

/** Serve `overrides` first, then the shared fixtures; records every call. */
function serve(overrides: Handler, calls: { path: string; method: string; body?: unknown; query?: Record<string, unknown> }[] = []) {
  vi.mocked(api).mockImplementation((async (path: string, opts?: { method?: string; body?: unknown; query?: Record<string, unknown> }) => {
    calls.push({ path, method: opts?.method ?? "GET", body: opts?.body, query: opts?.query });
    const r = overrides(path, opts);
    if (r instanceof Error) throw r;
    return r === undefined ? mockApi(path) : r;
  }) as never);
  return calls;
}

function as(role: string, permissions: string[]) {
  return { ...me, role, user: { ...me.user, is_platform_admin: false }, permissions };
}

const VIEWER = ["assets:read", "findings:read", "events:read", "scans:read", "scope:read", "orgs:read", "reports:read"];
const ANALYST = [...VIEWER, "assets:write", "findings:write", "events:ack", "scans:run", "reports:create", "integrations:read", "users:read"];

function renderAt(route: string) {
  const qc = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  return render(
    <QueryClientProvider client={qc}>
      <MemoryRouter initialEntries={[route]} future={{ v7_startTransition: true, v7_relativeSplatPath: true }}>
        <AuthProvider><App /></AuthProvider>
      </MemoryRouter>
    </QueryClientProvider>,
  );
}

beforeEach(() => { vi.mocked(api).mockImplementation((async (p: string) => mockApi(p)) as never); });
afterEach(() => cleanup());

describe("Threat Center", () => {
  it("a viewer sees assessments but no check, remediation or catalog actions", async () => {
    serve((p) => (p === "/auth/me" ? as("viewer", VIEWER) : undefined));
    renderAt("/threats/adv1");
    expect(await screen.findByText("Checked — not detected", { selector: ".badge" })).toBeTruthy();
    expect(screen.queryByRole("button", { name: /Check selected assets/ })).toBeNull();
    expect(screen.queryAllByRole("checkbox")).toHaveLength(0);
    // remediation is shown, not editable
    expect(screen.queryByRole("button", { name: /in progress/i })).toBeNull();
    cleanup();
    renderAt("/threats");
    await screen.findByText("Example VPN pre-auth RCE");
    expect(screen.queryByRole("link", { name: /Manage advisories/ })).toBeNull();
  });

  it("an analyst checks selected assets through the API and sees a conflict explained", async () => {
    const calls = serve((p, o) => {
      if (p === "/auth/me") return as("security_analyst", ANALYST);
      if (p === "/threats/adv1/checks" && o?.method === "POST")
        return new ApiError(409, "conflict", "A check for this advisory is already queued or running for this organization");
      return undefined;
    });
    renderAt("/threats/adv1");
    await screen.findByText("https://vpn2.example.com");
    const button = screen.getByRole("button", { name: /Check selected assets/ }) as HTMLButtonElement;
    expect(button.disabled).toBe(true);
    fireEvent.click(screen.getByRole("checkbox", { name: "Select https://vpn2.example.com" }));
    fireEvent.click(screen.getByRole("button", { name: /Check selected assets \(1\)/ }));
    expect(await screen.findByText(/already queued or running/)).toBeTruthy();
    expect(screen.getByText(/Wait for the running check to finish/)).toBeTruthy();
    const post = calls.find((c) => c.path === "/threats/adv1/checks" && c.method === "POST");
    expect(post?.body).toEqual({ match_ids: ["m2"] });
  });

  it("a completed check without detection is labelled as not proof of safety", async () => {
    renderAt("/threats/adv1");
    const badge = await screen.findByText("Checked — not detected", { selector: ".badge" });
    expect(badge.getAttribute("title")).toMatch(/not proof the asset is safe/);
    expect(screen.getByText("not proof of safety")).toBeTruthy();
  });

  it("no advisories yet, and an API error, both say so", async () => {
    serve((p) => (p === "/threats" ? { items: [], total: 0, page: 1, page_size: 25 } : undefined));
    renderAt("/threats");
    expect(await screen.findByText(/No advisories have been published yet/)).toBeTruthy();
    cleanup();
    serve((p) => (p === "/threats/adv1" ? new ApiError(404, "not_found", "Advisory not found") : undefined));
    renderAt("/threats/adv1");
    expect(await screen.findByText("Advisory not found")).toBeTruthy();
  });

  it("an advisory without an approved check explains that it is inventory-only", async () => {
    serve((p) => (p === "/threats/adv1" ? { ...mockApi(p) as object, check: null, has_check: false } : undefined));
    renderAt("/threats/adv1");
    expect(await screen.findByText(/No approved check exists for this advisory/)).toBeTruthy();
    expect(screen.queryByRole("button", { name: /Check selected assets/ })).toBeNull();
  });

  it("the catalog is closed to tenant administrators", async () => {
    serve((p) => (p === "/auth/me" ? as("tenant_admin", [...ANALYST, "settings:write"]) : undefined));
    renderAt("/threats/catalog");
    expect(await screen.findByText(/Only platform administrators manage the advisory catalog/)).toBeTruthy();
  });

  it("switching tenants refetches everything under the new tenant", async () => {
    const calls = serve((p, o) => {
      if (p === "/auth/me") return { ...me, memberships: [...me.memberships, { tenant: { id: "t2", name: "Beta", slug: "beta" }, role: "viewer" }] };
      if (p === "/auth/switch-tenant" && o?.method === "POST") return { access_token: "x", token_type: "bearer", expires_in: 900 };
      return undefined;
    });
    renderAt("/threats");
    await screen.findByText("Example VPN pre-auth RCE");
    const before = calls.filter((c) => c.path === "/threats").length;
    fireEvent.change(screen.getByLabelText("Tenant"), { target: { value: "t2" } });
    await waitFor(() => expect(calls.some((c) => c.path === "/auth/switch-tenant")).toBe(true));
    await waitFor(() => expect(calls.filter((c) => c.path === "/threats").length).toBeGreaterThan(before));
  });
});

