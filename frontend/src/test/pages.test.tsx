import { afterEach, describe, expect, it, vi } from "vitest";
import { cleanup, fireEvent, render, screen, waitFor } from "@testing-library/react";
import { MemoryRouter } from "react-router-dom";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { mockApi } from "./fixtures";
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
