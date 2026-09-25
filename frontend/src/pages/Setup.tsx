import { useEffect, useState, type FormEvent } from "react";
import { Link } from "react-router-dom";
import { useQuery } from "@tanstack/react-query";
import { api } from "@/api/client";
import { Brand } from "@/components/Layout";
import { ErrorBox, Field, Loading } from "@/components/ui";

// First-run setup. The installer prints a link of the form https://<host>/setup#token=<one-time token>.
// The token rides in the URL fragment so it never reaches server or proxy access logs; it is read once and
// removed from the address bar. There is no default password: this page creates the first platform
// administrator, once, and the server refuses it afterwards.
function tokenFromHash(): string {
  const m = window.location.hash.match(/(?:^#|&)token=([^&]+)/);
  return m ? decodeURIComponent(m[1]) : "";
}

export default function Setup() {
  const [token, setToken] = useState(tokenFromHash);
  const [fromLink] = useState(() => token !== "");
  const [email, setEmail] = useState("");
  const [name, setName] = useState("");
  const [org, setOrg] = useState("");
  const [pw, setPw] = useState("");
  const [pw2, setPw2] = useState("");
  const [done, setDone] = useState(false);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<unknown>(null);
  const status = useQuery({ queryKey: ["setup"], queryFn: () => api<{ needed: boolean }>("/setup") });

  useEffect(() => {
    if (window.location.hash) window.history.replaceState(null, "", "/setup");
  }, []);

  async function submit(e: FormEvent) {
    e.preventDefault();
    setError(null);
    if (pw !== pw2) {
      setError(new Error("Passwords do not match"));
      return;
    }
    setBusy(true);
    try {
      await api("/setup", { method: "POST", body: { token, email, password: pw, full_name: name, tenant_name: org || "Default" } });
      setDone(true);
    } catch (err) {
      setError(err);
    } finally {
      setBusy(false);
    }
  }

  return (
    <div className="login-shell">
      <form className="card login-card form" onSubmit={submit}>
        <Brand />
        <h2>Set up ExteriQ</h2>
        {status.isLoading ? <Loading /> : done || status.data?.needed === false ? (
          <div className="info-box">
            {done ? "Your administrator account is ready." : "Setup is already complete."} <Link to="/login">Sign in</Link>
          </div>
        ) : (
          <>
            <div className="small muted">Create the first platform administrator. This link works once and expires 30 minutes after it was issued.</div>
            <ErrorBox error={error ?? status.error} />
            {!fromLink && (
              <Field label="Setup token">
                <input value={token} onChange={(e) => setToken(e.target.value.trim())} required autoComplete="off" />
              </Field>
            )}
            <Field label="Your name"><input required value={name} onChange={(e) => setName(e.target.value)} autoFocus /></Field>
            <Field label="Email"><input type="email" autoComplete="username" required value={email} onChange={(e) => setEmail(e.target.value)} /></Field>
            <Field label="Organization name"><input placeholder="Default" value={org} onChange={(e) => setOrg(e.target.value)} /></Field>
            <Field label="Password">
              <input type="password" autoComplete="new-password" minLength={12} required value={pw} onChange={(e) => setPw(e.target.value)} />
            </Field>
            <Field label="Repeat password">
              <input type="password" autoComplete="new-password" required value={pw2} onChange={(e) => setPw2(e.target.value)} />
            </Field>
            <div className="small muted">At least 12 characters with three of: lowercase, uppercase, digits, symbols.</div>
            <button className="btn primary" disabled={busy} style={{ justifyContent: "center", height: 36 }}>
              {busy ? "Please wait…" : "Create administrator"}
            </button>
          </>
        )}
      </form>
    </div>
  );
}
