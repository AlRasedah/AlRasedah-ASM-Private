import { afterEach, describe, expect, it, vi } from "vitest";
import { cleanup, fireEvent, render, screen, waitFor } from "@testing-library/react";
import { MemoryRouter } from "react-router-dom";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { me, mockApi } from "./fixtures";
import { api } from "@/api/client";

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

afterEach(() => cleanup());

const pages: [string, string | RegExp][] = [
  ["/", "Attack surface overview"],
  ["/inventory", "Asset inventory"],
  ["/assets/a1", "vpn.example.com"],
  ["/shadow-it", "Shadow IT review"],
  ["/findings", "Fortinet FortiOS - Path Traversal"],
  ["/findings/f1", "Why this risk score"],
  ["/web-apps", "Web applications"],
  ["/threats", "Example VPN pre-auth RCE"],
  ["/threats/adv1", "Checked — not detected"],
  ["/threats/catalog", "Advisory catalog"],
  ["/exposure-map", "The map shows one organization at a time."],
  ["/changes", "Attack surface changes"],
  ["/scans", "Standard ASM"],
  ["/scans/s1", "Pipeline"],
  ["/scan-profiles", "Scan profiles & schedules"],
  ["/organizations", "Organizations & authorized scope"],
  ["/organizations/o1", "Authorized scope"],
  ["/reports", "Executive Attack Surface Report"],
  ["/integrations", "Notification channels"],
  ["/users", "Sara Analyst"],
  ["/settings", "Asset lifecycle"],
  ["/audit", "scope.added"],
  ["/account", "Two-factor authentication"],
  ["/platform", "Tenants"],
];

describe("pages render with API data", () => {
  it.each(pages)("%s", async (route, text) => {
    const errors: unknown[] = [];
    const spy = vi.spyOn(console, "error").mockImplementation((...args) => { errors.push(args); });
    renderAt(route);
    expect((await screen.findAllByText(text, {}, { timeout: 4000 })).length).toBeGreaterThan(0);
    spy.mockRestore();
    const reactErrors = errors.filter((e) => String(e).includes("Error") && !String(e).includes("width(0) and height(0)"));
    expect(reactErrors).toEqual([]);
  });

  it("asset detail tabs all render", async () => {
    renderAt("/assets/a1");
    await screen.findByText("Ownership & classification");
    for (const tab of ["Relationships (3)", "DNS", "Web endpoints", "Findings (3)", "Timeline", "Raw observations"]) {
      fireEvent.click(screen.getByRole("tab", { name: tab }));
      await waitFor(() => expect(screen.getByRole("tab", { name: tab }).getAttribute("aria-selected")).toBe("true"));
    }
    expect(await screen.findByText(/"resolves": true/)).toBeTruthy();
  });

  it("scan authorization log shows rejected targets", async () => {
    renderAt("/scans/s1");
    fireEvent.click(await screen.findByRole("tab", { name: "Authorization log" }));
    expect(await screen.findByText("hostname excluded from scope")).toBeTruthy();
  });
});

type Call = [string, { method?: string; query?: Record<string, unknown>; body?: unknown }?];
const calls = () => (api as unknown as { mock: { calls: Call[] } }).mock.calls;

describe("fixes from the 2026-09-18 test reports", () => {
  it("clearing the findings search re-queries without the search term", async () => {
    renderAt("/findings");
    const box = await screen.findByRole("searchbox", { name: "Search findings" });
    fireEvent.change(box, { target: { value: "Plesk" } });
    await waitFor(() => expect(calls().some(([p, o]) => p === "/findings" && o?.query?.q === "Plesk")).toBe(true));
    const before = calls().length;
    fireEvent.change(box, { target: { value: "" } });
    await waitFor(() => {
      const after = calls().slice(before).filter(([p]) => p === "/findings");
      expect(after.length).toBeGreaterThan(0);
      expect(after[after.length - 1][1]?.query?.q).toBeUndefined();
    }, { timeout: 300 }); // no debounce wait on clear
  });

  it("suspending a tenant asks first, and the current tenant cannot be suspended", async () => {
    renderAt("/platform");
    await screen.findByText("Beta Holding");
    const [current, other] = screen.getAllByRole("button", { name: "Suspend" }) as HTMLButtonElement[];
    expect(current.disabled).toBe(true);
    fireEvent.click(other);
    expect(await screen.findByText(/Every member is signed out immediately/)).toBeTruthy();
    expect(calls().some(([p, o]) => p === "/tenants/t2" && o?.method === "PATCH")).toBe(false);
    fireEvent.click(screen.getByRole("button", { name: "Confirm" }));
    await waitFor(() => expect(calls().some(([p, o]) => p === "/tenants/t2" && o?.method === "PATCH")).toBe(true));
  });

  it("audit rows open the full entry", async () => {
    renderAt("/audit");
    fireEvent.click(await screen.findByText("scope.added"));
    expect(await screen.findByText("Audit entry #7")).toBeTruthy();
    expect(screen.getByText("After")).toBeTruthy();
  });

  it("actively-verified web findings (OWASP ZAP) get a DAST badge", async () => {
    renderAt("/findings");
    await screen.findByText("SQL Injection");
    expect(await screen.findByText("DAST")).toBeTruthy();
  });

  it("only API-sortable columns get a sort control", async () => {
    renderAt("/inventory");
    await screen.findByText("Asset inventory");
    const sortable = (await screen.findAllByRole("columnheader")).filter((th) => th.querySelector("button.th-sort"));
    const names = sortable.map((th) => th.textContent?.replace(/[↕↑↓]/g, "").trim());
    expect(names).toEqual(expect.arrayContaining(["Asset", "Status", "Owner", "Risk"]));
    expect(names).not.toContain("IP");
    expect(names).not.toContain("Tags");
  });
});

describe("sessions do not last forever", () => {
  // An open tab polls by itself, so "idle" has to mean no *user* activity.
  afterEach(() => vi.useRealTimers());

  /** Renders the dashboard and waits for the session to be live, on fake timers. */
  async function signedIn() {
    vi.useFakeTimers();
    renderAt("/");
    for (let i = 0; i < 20 && !screen.queryByText("Attack surface overview"); i++) {
      await vi.advanceTimersByTimeAsync(50);
    }
    expect(screen.getByText("Attack surface overview")).toBeTruthy();
  }

  it("signs itself out after the idle window and says why", async () => {
    await signedIn();
    await vi.advanceTimersByTimeAsync(31 * 60_000);
    // The sign-out and the re-render after it are asynchronous; let them land.
    for (let i = 0; i < 20 && !screen.queryByText(/signed out after/); i++) {
      await vi.advanceTimersByTimeAsync(1_000);
    }
    expect(screen.getByText(/signed out after 30 minutes without activity/)).toBeTruthy();
    expect(screen.getByRole("button", { name: "Sign in" })).toBeTruthy();
  });

  it("an API too old to state a window still times out", async () => {
    // A half-upgraded stack (new web image, old API) must not fail open.
    vi.mocked(api).mockImplementation(async (path: string) => {
      if (path === "/auth/me") {
        const { session_idle_minutes: _omitted, ...withoutTheField } = me;
        return withoutTheField as never;
      }
      return mockApi(path) as never;
    });
    try {
      await signedIn();
      await vi.advanceTimersByTimeAsync(31 * 60_000);
      for (let i = 0; i < 20 && !screen.queryByText(/signed out after/); i++) {
        await vi.advanceTimersByTimeAsync(1_000);
      }
      expect(screen.getByRole("button", { name: "Sign in" })).toBeTruthy();
    } finally {
      vi.mocked(api).mockImplementation(async (path: string) => mockApi(path) as never);
    }
  });

  it("interaction keeps the session, however long the tab stays open", async () => {
    await signedIn();
    for (let i = 0; i < 6; i++) {
      await vi.advanceTimersByTimeAsync(20 * 60_000);
      fireEvent.keyDown(window, { key: "a" });
    }
    expect(screen.getByText("Attack surface overview")).toBeTruthy();
    expect(screen.queryByRole("button", { name: "Sign in" })).toBeNull();
  });
});

describe("a tenant with no data says so", () => {
  // Signed in to a tenant that holds nothing — the state a second administrator lands in
  // when their account was created in a tenant of its own. Pages used to render empty.
  function signedInToAnEmptyTenant(memberships = me.memberships) {
    vi.mocked(api).mockImplementation(async (path: string) => {
      if (path === "/organizations") return [] as never;
      if (path === "/auth/me") return { ...me, memberships } as never;
      const body = mockApi(path) as unknown;
      // RLS returns nothing for every list in a tenant that holds nothing.
      if (body && typeof body === "object" && "items" in body) {
        return { items: [], total: 0, page: 1, page_size: 25 } as never;
      }
      return body as never;
    });
  }

  afterEach(() => {
    vi.mocked(api).mockImplementation(async (path: string) => mockApi(path) as never);
  });

  it.each([["/scans", "Scans"], ["/inventory", "Asset inventory"], ["/findings", "Findings"],
           ["/changes", "Attack surface changes"]])(
    "%s names the tenant instead of showing an empty table", async (route, heading) => {
      signedInToAnEmptyTenant();
      renderAt(route);
      await screen.findAllByText(heading);
      expect(await screen.findByText(/this tenant has no organizations/)).toBeTruthy();
      expect((await screen.findAllByText("Acme")).length).toBeGreaterThan(0);
    });

  it("points at the other tenants the account belongs to", async () => {
    signedInToAnEmptyTenant([...me.memberships,
                             { tenant: { id: "t2", name: "Beta Holding", slug: "beta" }, role: "tenant_admin" }]);
    renderAt("/scans");
    expect(await screen.findByText(/switch tenant in the top bar/)).toBeTruthy();
    expect((await screen.findAllByText(/Beta Holding/)).length).toBeGreaterThan(0);
  });

  it("the dashboard stops claiming this is a new deployment", async () => {
    signedInToAnEmptyTenant([...me.memberships,
                             { tenant: { id: "t2", name: "Beta Holding", slug: "beta" }, role: "tenant_admin" }]);
    renderAt("/");
    expect(await screen.findByText("Acme has no data yet")).toBeTruthy();
    expect((await screen.findAllByText(/Beta Holding/)).length).toBeGreaterThan(0);
  });
});
