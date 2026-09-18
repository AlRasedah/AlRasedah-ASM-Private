import { useState, type FormEvent } from "react";
import { Link, Navigate, useLocation, useNavigate } from "react-router-dom";
import { useAuth } from "@/auth/AuthContext";
import { Brand } from "@/components/Layout";
import { ErrorBox, Field } from "@/components/ui";
import { api } from "@/api/client";

export default function Login() {
  const { me, login, verifyMfa } = useAuth();
  const nav = useNavigate();
  const loc = useLocation() as { state?: { from?: string } };
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [code, setCode] = useState("");
  const [mfaToken, setMfaToken] = useState<string | null>(null);
  const [forgot, setForgot] = useState(false);
  const [message, setMessage] = useState<string | null>(null);
  const [error, setError] = useState<unknown>(null);
  const [busy, setBusy] = useState(false);

  if (me) return <Navigate to={loc.state?.from ?? "/"} replace />;

  async function submit(e: FormEvent) {
    e.preventDefault();
    setError(null);
    setBusy(true);
    try {
      if (forgot) {
        const r = await api<{ message: string }>("/auth/password/forgot", { method: "POST", body: { email } });
        setMessage(r.message);
        setForgot(false);
      } else if (mfaToken) {
        await verifyMfa(mfaToken, code);
        nav(loc.state?.from ?? "/", { replace: true });
      } else {
        const r = await login(email, password);
        if (r.mfaRequired) setMfaToken(r.mfaToken ?? null);
        else nav(loc.state?.from ?? "/", { replace: true });
      }
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
        <h2>{forgot ? "Reset your password" : mfaToken ? "Two-factor verification" : "Sign in"}</h2>
        {message && <div className="info-box">{message}</div>}
        <ErrorBox error={error} />
        {!mfaToken && (
          <Field label="Email">
            <input type="email" autoComplete="username" required value={email} onChange={(e) => setEmail(e.target.value)} autoFocus />
          </Field>
        )}
        {!mfaToken && !forgot && (
          <Field label="Password">
            <input type="password" autoComplete="current-password" required value={password} onChange={(e) => setPassword(e.target.value)} />
          </Field>
        )}
        {mfaToken && (
          <Field label="Authentication code">
            <input inputMode="numeric" pattern="[0-9]{6,8}" autoComplete="one-time-code" required value={code}
                   onChange={(e) => setCode(e.target.value.trim())} autoFocus />
          </Field>
        )}
        <button className="btn primary" disabled={busy} style={{ justifyContent: "center", height: 36 }}>
          {busy ? "Please wait…" : forgot ? "Send reset link" : mfaToken ? "Verify" : "Sign in"}
        </button>
        <div className="row small">
          {!mfaToken && (
            <a href="#" onClick={(e) => { e.preventDefault(); setForgot(!forgot); setError(null); }}>
              {forgot ? "Back to sign in" : "Forgot password?"}
            </a>
          )}
          <span className="right muted">Authorized use only</span>
        </div>
        <div className="small muted">Have a reset link? <Link to="/reset-password">Set a new password</Link></div>
      </form>
    </div>
  );
}
