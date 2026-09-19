import { lazy, Suspense } from "react";
import { Navigate, Route, Routes, useLocation } from "react-router-dom";
import { useAuth } from "@/auth/AuthContext";
import { OrgProvider } from "@/auth/OrgContext";
import Layout from "@/components/Layout";
import { Loading } from "@/components/ui";
import Login from "@/pages/Login";
import ResetPassword from "@/pages/ResetPassword";

// Route-level code splitting keeps the initial bundle small.
const Dashboard = lazy(() => import("@/dashboard/Dashboard"));
const Inventory = lazy(() => import("@/assets/Inventory"));
const AssetDetail = lazy(() => import("@/assets/AssetDetail"));
const ShadowIT = lazy(() => import("@/assets/ShadowIT"));
const Findings = lazy(() => import("@/findings/Findings"));
const FindingDetail = lazy(() => import("@/findings/FindingDetail"));
const WebApps = lazy(() => import("@/pages/WebApps"));
const Changes = lazy(() => import("@/pages/Changes"));
const Scans = lazy(() => import("@/scans/Scans"));
const ScanDetail = lazy(() => import("@/scans/ScanDetail"));
const Profiles = lazy(() => import("@/scans/Profiles"));
const Organizations = lazy(() => import("@/pages/Organizations"));
const OrganizationDetail = lazy(() => import("@/pages/OrganizationDetail"));
const Reports = lazy(() => import("@/pages/Reports"));
const Integrations = lazy(() => import("@/pages/Integrations"));
const UsersPage = lazy(() => import("@/pages/Users"));
const SettingsPage = lazy(() => import("@/pages/Settings"));
const Audit = lazy(() => import("@/pages/Audit"));
const Account = lazy(() => import("@/pages/Account"));
const Platform = lazy(() => import("@/pages/Platform"));

function RequireAuth({ children }: { children: JSX.Element }) {
  const { me, ready } = useAuth();
  const loc = useLocation();
  if (!ready) return <Loading text="Starting…" />;
  if (!me) return <Navigate to="/login" replace state={{ from: loc.pathname }} />;
  return children;
}

const page = (el: JSX.Element) => <Suspense fallback={<Loading />}>{el}</Suspense>;

export default function App() {
  return (
    <Routes>
      <Route path="/login" element={<Login />} />
      <Route path="/reset-password" element={<ResetPassword />} />
      <Route element={<RequireAuth><OrgProvider><Layout /></OrgProvider></RequireAuth>}>
        <Route index element={page(<Dashboard />)} />
        <Route path="inventory" element={page(<Inventory />)} />
        <Route path="assets/:id" element={page(<AssetDetail />)} />
        <Route path="shadow-it" element={page(<ShadowIT />)} />
        <Route path="findings" element={page(<Findings />)} />
        <Route path="findings/:id" element={page(<FindingDetail />)} />
        <Route path="web-apps" element={page(<WebApps />)} />
        <Route path="changes" element={page(<Changes />)} />
        <Route path="scans" element={page(<Scans />)} />
        <Route path="scans/:id" element={page(<ScanDetail />)} />
        <Route path="scan-profiles" element={page(<Profiles />)} />
        <Route path="organizations" element={page(<Organizations />)} />
        <Route path="organizations/:id" element={page(<OrganizationDetail />)} />
        <Route path="reports" element={page(<Reports />)} />
        <Route path="integrations" element={page(<Integrations />)} />
        <Route path="users" element={page(<UsersPage />)} />
        <Route path="settings" element={page(<SettingsPage />)} />
        <Route path="audit" element={page(<Audit />)} />
        <Route path="account" element={page(<Account />)} />
        <Route path="platform" element={page(<Platform />)} />
        <Route path="*" element={<Navigate to="/" replace />} />
      </Route>
    </Routes>
  );
}
