"""Tiny dependency-free SVG charts for reports (render identically in HTML and PDF)."""

from __future__ import annotations

from html import escape

SEVERITY_COLORS = {"critical": "#b42318", "high": "#dc6803", "medium": "#ca8504", "low": "#1570ef", "info": "#667085"}


def hbars(items: list[tuple[str, int]], colors: dict[str, str] | None = None, width: int = 520) -> str:
    if not items:
        return '<p class="muted">No data</p>'
    maxv = max(v for _, v in items) or 1
    row_h, label_w = 26, 150
    h = row_h * len(items) + 8
    parts = [f'<svg xmlns="http://www.w3.org/2000/svg" width="{width}" height="{h}" role="img">']
    for i, (label, value) in enumerate(items):
        y = i * row_h + 4
        bw = int((width - label_w - 60) * value / maxv)
        color = (colors or {}).get(label, "#a3571f")
        parts.append(f'<text x="0" y="{y + 15}" font-size="12" fill="#344054">{escape(label[:24])}</text>')
        parts.append(f'<rect x="{label_w}" y="{y + 3}" width="{max(bw, 2)}" height="16" rx="3" fill="{color}"/>')
        parts.append(f'<text x="{label_w + max(bw, 2) + 6}" y="{y + 15}" font-size="12" fill="#101828">{value}</text>')
    parts.append("</svg>")
    return "".join(parts)


def line(points: list[tuple[str, float]], width: int = 560, height: int = 160, color: str = "#a3571f",
         max_value: float | None = None) -> str:
    if len(points) < 2:
        return '<p class="muted">Not enough history yet — trends appear after a few days of monitoring.</p>'
    pad = 28
    top = max_value or max(v for _, v in points) or 1
    step = (width - 2 * pad) / (len(points) - 1)
    coords = [(pad + i * step, height - pad - (v / top) * (height - 2 * pad)) for i, (_, v) in enumerate(points)]
    path = " ".join(f"{x:.1f},{y:.1f}" for x, y in coords)
    parts = [f'<svg xmlns="http://www.w3.org/2000/svg" width="{width}" height="{height}" role="img">',
             f'<line x1="{pad}" y1="{height - pad}" x2="{width - pad}" y2="{height - pad}" stroke="#d0d5dd"/>',
             f'<polyline fill="none" stroke="{color}" stroke-width="2.5" points="{path}"/>']
    for x, y in coords:
        parts.append(f'<circle cx="{x:.1f}" cy="{y:.1f}" r="2.5" fill="{color}"/>')
    parts.append(f'<text x="{pad}" y="{height - 8}" font-size="11" fill="#667085">{escape(points[0][0])}</text>')
    parts.append(f'<text x="{width - pad}" y="{height - 8}" font-size="11" fill="#667085" text-anchor="end">'
                 f'{escape(points[-1][0])}</text>')
    parts.append(f'<text x="{pad}" y="14" font-size="11" fill="#667085">max {top:g}</text>')
    parts.append("</svg>")
    return "".join(parts)
