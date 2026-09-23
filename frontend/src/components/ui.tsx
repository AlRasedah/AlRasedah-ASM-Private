import { useEffect, useState, type ReactNode } from "react";
import clsx from "clsx";
import { Link } from "react-router-dom";
import { AlertTriangle, ChevronLeft, ChevronRight, Inbox, X } from "lucide-react";
import { ApiError } from "@/api/client";
import { label, riskColor } from "@/lib/format";

export function Card({ title, hint, right, children, flush, className }: {
  title?: ReactNode; hint?: ReactNode; right?: ReactNode; children: ReactNode; flush?: boolean; className?: string;
}) {
  return (
    <section className={clsx("card", className)}>
      {(title || right) && (
        <header className="card-head">
          {title && <h3>{title}</h3>}
          {hint && <span className="hint">{hint}</span>}
          {right && <div className="right">{right}</div>}
        </header>
      )}
      <div className={clsx("card-body", flush && "flush")}>{children}</div>
    </section>
  );
}

export function PageHead({ title, sub, actions }: { title: ReactNode; sub?: ReactNode; actions?: ReactNode }) {
  return (
    <div className="page-head">
      <div>
        <h1>{title}</h1>
        {sub && <div className="sub">{sub}</div>}
      </div>
      {actions && <div className="actions">{actions}</div>}
    </div>
  );
}

/** A sortable column header. Only columns the API can sort get one; plain <th> stays inert. */
export function SortTh({ id, children, sort, order, onSort, className }: {
  id: string; children: ReactNode; sort: string; order: string; onSort: (id: string, order: "asc" | "desc") => void; className?: string;
}) {
  const active = sort === id;
  return (
    <th className={clsx("sortable", active && "sorted", className)} aria-sort={active ? (order === "desc" ? "descending" : "ascending") : "none"}>
      <button type="button" className="th-sort" onClick={() => onSort(id, active && order === "desc" ? "asc" : "desc")}>
        {children}<span className="sort-ind" aria-hidden="true">{active ? (order === "desc" ? "↓" : "↑") : "↕"}</span>
      </button>
    </th>
  );
}

export function SeverityBadge({ value }: { value: string }) {
  return <span className={clsx("badge", `sev-${value}`)}>{value}</span>;
}

export function RiskScore({ score }: { score: number }) {
  const color = riskColor(score);
  return (
    <span className="risk" title={`Risk ${score}/100`}>
      <span className="risk-num" style={{ color }}>{score}</span>
      <span className="risk-bar"><i style={{ width: `${Math.max(score, 3)}%`, background: color }} /></span>
    </span>
  );
}

const STATUS_TONE: Record<string, string> = {
  active: "ok", inactive: "neutral", completed: "ok", running: "accent", pending: "neutral", queued: "neutral",
  partial: "warn", failed: "bad", cancelled: "neutral", skipped: "neutral",
  approved: "ok", expected: "ok", third_party: "neutral", unverified: "warn", unknown: "warn", unauthorized: "bad",
  decommissioned: "neutral", new: "accent", investigating: "warn", accepted_risk: "neutral", false_positive: "neutral",
  remediated: "ok", reopened: "bad", sent: "ok", in_scope: "ok", derived: "neutral", out_of_scope: "neutral",
  allowed: "ok", rejected: "bad", verified: "ok", not_required: "neutral",
  succeeded: "ok", blocked: "bad", inconclusive: "warn", resolved: "ok", in_progress: "warn", open: "neutral",
  not_applicable: "neutral", published: "ok", archived: "neutral", draft: "warn",
};

export function StatusBadge({ value }: { value: string | null | undefined }) {
  if (!value) return <span className="muted">—</span>;
  return <span className={clsx("badge", STATUS_TONE[value] ?? "neutral")}>{label(value)}</span>;
}

export function Tags({ tags }: { tags: string[] }) {
  if (!tags?.length) return <span className="muted">—</span>;
  return <>{tags.map((t) => <span key={t} className="tag">{t}</span>)}</>;
}

export function Loading({ text = "Loading…" }: { text?: string }) {
  return <div className="loading"><span className="spinner" /> {text}</div>;
}

export function Empty({ children = "Nothing to show yet." }: { children?: ReactNode }) {
  return <div className="empty"><Inbox /><div>{children}</div></div>;
}

export function ErrorBox({ error }: { error: unknown }) {
  if (!error) return null;
  const msg = error instanceof ApiError ? error.message : error instanceof Error ? error.message : String(error);
  const details = error instanceof ApiError && Array.isArray(error.details) ? error.details : null;
  return (
    <div className="error-box">
      <div className="row"><AlertTriangle size={15} /> {msg}</div>
      {details && (
        <ul className="small" style={{ margin: "6px 0 0 18px" }}>
          {details.slice(0, 8).map((d, i) => {
            if (typeof d === "string") return <li key={i}>{d}</li>;
            const item = d as { field?: string | null; msg?: string };
            return <li key={i}>{item.field ? `${label(item.field)}: ` : ""}{item.msg ?? "Invalid value"}</li>;
          })}
        </ul>
      )}
    </div>
  );
}

export function Pagination({ page, pageSize, total, onPage }: {
  page: number; pageSize: number; total: number; onPage: (p: number) => void;
}) {
  const pages = Math.max(1, Math.ceil(total / pageSize));
  const from = total === 0 ? 0 : (page - 1) * pageSize + 1;
  const to = Math.min(total, page * pageSize);
  return (
    <div className="pagination">
      <span>{from}–{to} of {total.toLocaleString()}</span>
      <span className="spacer" />
      <button className="btn sm" disabled={page <= 1} onClick={() => onPage(page - 1)}><ChevronLeft /> Prev</button>
      <span>Page {page} / {pages}</span>
      <button className="btn sm" disabled={page >= pages} onClick={() => onPage(page + 1)}>Next <ChevronRight /></button>
    </div>
  );
}

export function Tabs<T extends string>({ tabs, value, onChange }: {
  tabs: { id: T; label: ReactNode }[]; value: T; onChange: (v: T) => void;
}) {
  return (
    <div className="tabs" role="tablist">
      {tabs.map((t) => (
        <button key={t.id} role="tab" aria-selected={value === t.id} className={clsx(value === t.id && "active")}
                onClick={() => onChange(t.id)}>
          {t.label}
        </button>
      ))}
    </div>
  );
}

export function Modal({ title, onClose, children, footer, wide }: {
  title: ReactNode; onClose: () => void; children: ReactNode; footer?: ReactNode; wide?: boolean;
}) {
  useEffect(() => {
    const h = (e: KeyboardEvent) => e.key === "Escape" && onClose();
    window.addEventListener("keydown", h);
    return () => window.removeEventListener("keydown", h);
  }, [onClose]);
  return (
    <div className="modal-backdrop" onMouseDown={(e) => e.target === e.currentTarget && onClose()}>
      <div className={clsx("modal", wide && "wide")} role="dialog" aria-modal="true">
        <div className="modal-head">
          <h2>{title}</h2>
          <button className="btn ghost sm right" onClick={onClose} aria-label="Close"><X /></button>
        </div>
        <div className="modal-body">{children}</div>
        {footer && <div className="modal-foot">{footer}</div>}
      </div>
    </div>
  );
}

/** Headline number. With `to` the whole card links there; with `onClick` it is a button. */
export function Kpi({ label: l, value, delta, tone, to, onClick }: {
  label: string; value: ReactNode; delta?: ReactNode; tone?: string; to?: string; onClick?: () => void;
}) {
  const body = (
    <>
      <div className="label">{l}</div>
      <div className="value">{value}</div>
      {delta && <div className="delta">{delta}</div>}
    </>
  );
  if (to) return <Link to={to} className={clsx("card kpi link", tone)}>{body}</Link>;
  if (onClick) return <button type="button" onClick={onClick} className={clsx("card kpi link", tone)}>{body}</button>;
  return <div className={clsx("card kpi", tone)}>{body}</div>;
}

export function Field({ label: l, children }: { label: string; children: ReactNode }) {
  return <label className="field"><span>{l}</span>{children}</label>;
}

export function JsonView({ value }: { value: unknown }) {
  return <pre className="json">{JSON.stringify(value, null, 2)}</pre>;
}

export function useDebounced<T>(value: T, ms = 300): T {
  const [v, setV] = useState(value);
  useEffect(() => {
    const t = setTimeout(() => setV(value), ms);
    return () => clearTimeout(t);
  }, [value, ms]);
  return v;
}

export function Confirm({ text, onConfirm, onClose, danger }: {
  text: ReactNode; onConfirm: () => void; onClose: () => void; danger?: boolean;
}) {
  return (
    <Modal title="Please confirm" onClose={onClose} footer={
      <>
        <button className="btn" onClick={onClose}>Cancel</button>
        <button className={clsx("btn", danger ? "danger" : "primary")} onClick={() => { onConfirm(); onClose(); }}>Confirm</button>
      </>
    }>
      {text}
    </Modal>
  );
}
