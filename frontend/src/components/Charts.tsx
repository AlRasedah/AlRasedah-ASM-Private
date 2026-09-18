import {
  Area, AreaChart, Bar, BarChart, CartesianGrid, Cell, ResponsiveContainer, Tooltip, XAxis, YAxis,
} from "recharts";
import { Empty } from "./ui";

const grid = "var(--border)";
const tooltipStyle = {
  background: "var(--surface-elevated)", border: "1px solid var(--border-strong)", borderRadius: 6,
  color: "var(--foreground)", fontSize: 12,
};

export function TrendChart({ data, keys, height = 220, max }: {
  data: Record<string, unknown>[];
  keys: { key: string; color: string; name: string }[];
  height?: number;
  max?: number;
}) {
  if (data.length < 2) return <Empty>Trends appear after a few days of continuous monitoring.</Empty>;
  return (
    <ResponsiveContainer width="100%" height={height}>
      <AreaChart data={data} margin={{ top: 8, right: 8, left: -18, bottom: 0 }}>
        <defs>
          {keys.map((k) => (
            <linearGradient key={k.key} id={`g-${k.key}`} x1="0" y1="0" x2="0" y2="1">
              <stop offset="0%" stopColor={k.color} stopOpacity={0.35} />
              <stop offset="100%" stopColor={k.color} stopOpacity={0} />
            </linearGradient>
          ))}
        </defs>
        <CartesianGrid stroke={grid} vertical={false} />
        <XAxis dataKey="day" tickLine={false} axisLine={false} tickFormatter={(d: string) => d.slice(5)} />
        <YAxis tickLine={false} axisLine={false} domain={max ? [0, max] : undefined} allowDecimals={false} />
        <Tooltip contentStyle={tooltipStyle} />
        {keys.map((k) => (
          <Area key={k.key} type="monotone" dataKey={k.key} name={k.name} stroke={k.color} strokeWidth={2}
                fill={`url(#g-${k.key})`} />
        ))}
      </AreaChart>
    </ResponsiveContainer>
  );
}

export function HBarChart({ data, height, colors }: {
  data: { name: string; value: number }[];
  height?: number;
  colors?: Record<string, string>;
}) {
  if (!data.length || data.every((d) => !d.value)) return <Empty>No data yet.</Empty>;
  return (
    <ResponsiveContainer width="100%" height={height ?? Math.max(120, data.length * 32)}>
      <BarChart data={data} layout="vertical" margin={{ top: 4, right: 24, left: 8, bottom: 4 }}>
        <CartesianGrid stroke={grid} horizontal={false} />
        <XAxis type="number" tickLine={false} axisLine={false} allowDecimals={false} />
        <YAxis type="category" dataKey="name" width={120} tickLine={false} axisLine={false} />
        <Tooltip contentStyle={tooltipStyle} cursor={{ fill: "var(--copper-tint)" }} />
        <Bar dataKey="value" radius={[0, 4, 4, 0]} barSize={16}>
          {data.map((d) => <Cell key={d.name} fill={colors?.[d.name] ?? "var(--brand)"} />)}
        </Bar>
      </BarChart>
    </ResponsiveContainer>
  );
}
