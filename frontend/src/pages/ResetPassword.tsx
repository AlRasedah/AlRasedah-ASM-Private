import { useState, type FormEvent } from "react";
import { Link, useSearchParams } from "react-router-dom";
import { api } from "@/api/client";
import { Brand } from "@/components/Layout";
import { ErrorBox, Field } from "@/components/ui";

export default function ResetPassword() {
  const [params] = useSearchParams();
  const [token, setToken] = useState(params.get("token") ?? "");
  const [pw, setPw] = useState("");
  const [pw2, setPw2] = useState("");
  const [done, setDone] = useState(false);
  const [error, setError] = useState<unknown>(null);

  async function submit(e: FormEvent) {
    e.preventDefault();
    setError(null);
    if (pw !== pw2) {
      setError(new Error("Passwords do not match"));
      return;
    }
    try {
      await api("/auth/password/reset", { method: "POST", body: { token, new_password: pw } });
      setDone(true);
      // Remove the one-time token from the address bar and history.
      window.history.replaceState(null, "", "/reset-password");
    } catch (err) {
      setError(err);
    }
  }

  return (
    <div className="login-shell">
      <form className="card login-card form" onSubmit={submit}>
        <Brand />
        <h2>Set a new password</h2>
        {done ? (
          <div className="info-box">Your password was updated. <Link to="/login">Sign in</Link></div>
        ) : (
          <>
            <ErrorBox error={error} />
            {!params.get("token") && (
              <Field label="Reset token"><input value={token} onChange={(e) => setToken(e.target.value)} required /></Field>
            )}
            <Field label="New password">
              <input type="password" autoComplete="new-password" minLength={12} required value={pw} onChange={(e) => setPw(e.target.value)} />
            </Field>
            <Field label="Repeat password">
              <input type="password" autoComplete="new-password" required value={pw2} onChange={(e) => setPw2(e.target.value)} />
            </Field>
            <div className="small muted">At least 12 characters with three of: lowercase, uppercase, digits, symbols.</div>
            <button className="btn primary" style={{ justifyContent: "center", height: 36 }}>Update password</button>
          </>
        )}
      </form>
    </div>
  );
}
