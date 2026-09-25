/**
 * Diagnostics & Support and first-run setup: who sees what, bundle preview before generation,
 * contents before download, unavailable telemetry, and the one-time setup token.
 */
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { cleanup, fireEvent, render, screen, waitFor } from "@testing-library/react";
import { MemoryRouter } from "react-router-dom";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { me, mockApi } from "./fixtures";
import { api, download } from "@/api/client";

vi.mock("@/api/client", async () => {
  const actual = await vi.importActual<typeof import("@/api/client")>("@/api/client");
  return {
    ...actual,
    api: vi.fn(async (path: string) => mockApi(path)),
    refreshSession: vi.fn(async () => true),
    hasAccessToken: () => false,
    download: vi.fn(async () => undefined),
    openBlob: vi.fn(),
  };
});

import App from "@/App";
import { AuthProvider } from "@/auth/AuthContext";

type Call = { path: string; method: string; body?: unknown; query?: Record<string, unknown> };

function serve(meBody: unknown, calls: Call[] = []) {
  vi.mocked(api).mockImplementation((async (path: string, opts?: { method?: string; body?: unknown; query?: Record<string, unknown> }) => {
    calls.push({ path, method: opts?.method ?? "GET", body: opts?.body, query: opts?.query });
    if (path === "/auth/me") return structuredClone(meBody);
    if (path === "/diagnostics/bundles" && opts?.method === "POST") return { ...(mockApi(path) as unknown[])[0] as object, status: "queued" };
    if (path === "/setup" && opts?.method === "POST") return { ok: true };
    return mockApi(path);
  }) as never);
  return calls;
}

function as(permissions: string[], platform = false) {
  return { ...me, role: "tenant_admin", user: { ...me.user, is_platform_admin: platform }, permissions };
}

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
afterEach(() => { cleanup(); vi.mocked(download).mockClear(); });

describe("navigation and permissions", () => {
  it("a tenant admin sees Diagnostics but not the platform page", async () => {
    serve(as(["assets:read", "scans:read", "diagnostics:read", "support:bundles"]));
    renderAt("/diagnostics");
    await screen.findByRole("tab", { name: "Support bundles" });
    expect(screen.getByRole("link", { name: /Diagnostics & Support/ })).toBeTruthy();
    expect(screen.queryByRole("link", { name: /Platform diagnostics/ })).toBeNull();
  });

  it("a user without support:bundles gets no bundle tab, and never calls the platform API", async () => {
    const calls = serve(as(["assets:read", "scans:read", "diagnostics:read"]));
    renderAt("/diagnostics");
    await screen.findByText("Scanner for your scans");
    expect(screen.queryByRole("tab", { name: "Support bundles" })).toBeNull();
    expect(calls.some((c) => c.path.startsWith("/diagnostics/platform"))).toBe(false);
  });

  it("a viewer without diagnostics:read has no nav entry", async () => {
    serve(as(["assets:read", "scans:read"]));
    renderAt("/inventory");
    await screen.findByText("Asset inventory");
    expect(screen.queryByRole("link", { name: /Diagnostics/ })).toBeNull();
  });
});

describe("tenant view", () => {
  it("shows missing telemetry as unavailable, not zero", async () => {
    serve(me);
    renderAt("/diagnostics");
    await screen.findByText("Typical stage run time");
    expect(screen.getAllByText("Unavailable").length).toBeGreaterThan(0);
    expect(screen.getByText("no stage timing recorded in the last 7 days")).toBeTruthy();
  });

  it("scan timelines separate queue wait, run time and ingestion", async () => {
    serve(me);
    renderAt("/diagnostics");
    fireEvent.click(await screen.findByRole("tab", { name: "Scan timelines" }));
    fireEvent.click(await screen.findByRole("button", { name: "Show stages" }));
    await screen.findByText("Passive subdomain discovery");
    for (const text of ["Queue wait", "Run time", "Ingestion", "340 ms", "timed out"]) {
      expect(screen.getAllByText(text).length).toBeGreaterThan(0);
    }
  });
});

describe("support bundles", () => {
  it("previews included and excluded categories before generating", async () => {
    const calls = serve(me);
    renderAt("/diagnostics");
    fireEvent.click(await screen.findByRole("tab", { name: "Support bundles" }));
    fireEvent.click(await screen.findByRole("button", { name: /Generate support bundle/ }));
    fireEvent.click(await screen.findByRole("checkbox"));
    expect(screen.queryByRole("button", { name: "Generate" })).toBeNull();
    fireEvent.click(screen.getByRole("button", { name: "Preview contents" }));
    await screen.findByText("Never included");
    expect(screen.getByText("database dumps")).toBeTruthy();
    fireEvent.click(screen.getByRole("button", { name: "Generate" }));
    await waitFor(() => expect(calls.some((c) => c.path === "/diagnostics/bundles" && c.method === "POST")).toBe(true));
    const post = calls.find((c) => c.path === "/diagnostics/bundles" && c.method === "POST")!;
    expect(post.body).toMatchObject({ scope: "tenant", scan_ids: ["s1"] });
  });

  it("shows the contents before download and downloads with the tenant scope", async () => {
    serve(me);
    renderAt("/diagnostics");
    fireEvent.click(await screen.findByRole("tab", { name: "Support bundles" }));
    fireEvent.click(await screen.findByRole("button", { name: /Review & download/ }));
    await screen.findByText("stage-output/s1-0.txt");
    expect(download).not.toHaveBeenCalled();
    fireEvent.click(screen.getByRole("button", { name: /^Download/ }));
    await waitFor(() => expect(download).toHaveBeenCalledWith("/diagnostics/bundles/b1/download", { scope: "tenant" },
      "exteriq-support-tenant-20260925-1200-b1.zip"));
  });
});

describe("platform view", () => {
  it("reports a missing service heartbeat as unavailable", async () => {
    serve(me);
    renderAt("/platform/diagnostics");
    await screen.findByText("Scanner pools");
    expect(screen.getByText("no heartbeat in the last 90 seconds")).toBeTruthy();
    expect(screen.getByText(/not a native install/)).toBeTruthy();
  });
});

describe("first-run setup", () => {
  it("sends the token from the URL fragment and removes it from the address bar", async () => {
    window.history.replaceState(null, "", "/setup#token=one-time-token-abcdefghijkl");
    const calls = serve(me);
    renderAt("/setup");
    await screen.findByRole("button", { name: "Create administrator" });
    expect(window.location.hash).toBe("");
    expect(screen.queryByLabelText("Setup token")).toBeNull();
    fireEvent.change(screen.getByLabelText("Your name"), { target: { value: "Admin" } });
    fireEvent.change(screen.getByLabelText("Email"), { target: { value: "admin@example.com" } });
    fireEvent.change(screen.getByLabelText("Password"), { target: { value: "Correct-Horse-9" } });
    fireEvent.change(screen.getByLabelText("Repeat password"), { target: { value: "Correct-Horse-9" } });
    fireEvent.click(screen.getByRole("button", { name: "Create administrator" }));
    await screen.findByText(/administrator account is ready/);
    const post = calls.find((c) => c.path === "/setup" && c.method === "POST")!;
    expect(post.body).toMatchObject({ token: "one-time-token-abcdefghijkl", email: "admin@example.com" });
  });
});
