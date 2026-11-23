"""Gráficos vectoriales de barras para la evidencia de Explore y Assess."""

from html import escape

from vulnminer.io import write_text


def bars(path, title, entries, *, domain=None):
    rows = list(entries)
    upper = domain or max((value for _, value in rows), default=1) or 1
    height = 92 + 34 * len(rows)
    parts = [
        f'<svg xmlns="http://www.w3.org/2000/svg" width="850" height="{height}" viewBox="0 0 850 {height}" role="img">',
        f"<title>{escape(title)}</title>",
        '<rect width="850" height="100%" fill="#f5f7fb" rx="12"/>',
        f'<text x="26" y="39" font-size="24" font-weight="700" fill="#142241">{escape(title)}</text>',
        '<g font-family="system-ui, sans-serif" font-size="15" fill="#253552">',
    ]
    for index, (label, value) in enumerate(rows):
        y = 59 + 34 * index
        width = 490 * value / upper
        text = f"{value:.3f}" if domain == 1 else str(value)
        parts.extend((
            f'<text x="26" y="{y + 17}">{escape(label)}</text>',
            f'<rect x="270" y="{y}" width="490" height="23" rx="4" fill="#dfe7f2"/>',
            f'<rect x="270" y="{y}" width="{width:.1f}" height="23" rx="4" fill="#2359aa"/>',
            f'<text x="775" y="{y + 17}">{text}</text>',
        ))
    parts.append("</g></svg>")
    write_text(path, "\n".join(parts) + "\n")
