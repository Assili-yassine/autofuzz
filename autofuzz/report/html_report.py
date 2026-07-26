"""Stage 20: generate report.html summarizing a run."""
from __future__ import annotations

from pathlib import Path

from jinja2 import Environment, BaseLoader, select_autoescape

from ..models import TargetResult

_TEMPLATE = """
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>AutoFuzz Report</title>
<style>
  body { font-family: -apple-system, Segoe UI, Roboto, sans-serif; margin: 2rem; background:#0f1117; color:#e6e6e6; }
  h1 { color:#7dd3fc; }
  h2 { border-bottom: 1px solid #333; padding-bottom: .3rem; margin-top: 2.5rem; }
  .target { background:#161a23; border-radius:8px; padding:1.2rem 1.5rem; margin-bottom:2rem; }
  table { border-collapse: collapse; width:100%; margin-top: .5rem; }
  th, td { text-align:left; padding: .4rem .6rem; border-bottom: 1px solid #262b36; font-size: .9rem; }
  th { color:#94a3b8; }
  .stat { display:inline-block; margin-right:1.5rem; font-size:.9rem; color:#9ca3af;}
  .stat b { color:#e6e6e6; font-size:1.1rem; display:block; }
  code { background:#1e293b; padding:.1rem .35rem; border-radius:4px; }
  .badge { display:inline-block; padding:.1rem .5rem; border-radius:12px; font-size:.75rem; margin-right:.3rem; }
  .b-live { background:#065f46; }
  .b-dead { background:#7f1d1d; }
</style>
</head>
<body>
<h1>AutoFuzz Report</h1>
<p>Authorized reconnaissance summary — {{ targets|length }} target(s).</p>

{% for t in targets %}
<div class="target">
  <h2>{{ t.url }} <span class="badge {{ 'b-live' if t.alive else 'b-dead' }}">{{ 'alive' if t.alive else 'dead' }}</span></h2>

  <div class="stat"><b>{{ t.js_files|length }}</b>JS files</div>
  <div class="stat"><b>{{ t.linkfinder_endpoints|length }}</b>LinkFinder endpoints</div>
  <div class="stat"><b>{{ t.js_endpoints|length }}</b>JS endpoints</div>
  <div class="stat"><b>{{ t.secrets|length }}</b>Secret-pattern hits</div>
  <div class="stat"><b>{{ t.ffuf_results|length }}</b>ffuf results</div>
  <div class="stat"><b>{{ t.interesting|length }}</b>Interesting</div>
  <div class="stat"><b>{{ t.api_endpoints|length }}</b>API endpoints</div>

  {% if t.technologies %}
  <p>Detected technologies: {% for tech in t.technologies %}<code>{{ tech }}</code> {% endfor %}</p>
  {% endif %}

  {% if t.interesting %}
  <h3>Interesting responses</h3>
  <table>
    <tr><th>Status</th><th>URL</th><th>Length</th><th>Reasons</th></tr>
    {% for r in t.interesting[:200] %}
    <tr><td>{{ r.status }}</td><td>{{ r.url }}</td><td>{{ r.length }}</td><td>{{ r.reasons|join(', ') }}</td></tr>
    {% endfor %}
  </table>
  {% endif %}

  {% if t.secrets %}
  <h3>Secret-pattern hits (truncated matches only)</h3>
  <table>
    <tr><th>Type</th><th>Match</th><th>Source</th></tr>
    {% for s in t.secrets[:200] %}
    <tr><td>{{ s.type }}</td><td><code>{{ s.match }}</code></td><td>{{ s.source }}</td></tr>
    {% endfor %}
  </table>
  {% endif %}

  {% if t.api_endpoints %}
  <h3>API endpoints</h3>
  <ul>{% for e in t.api_endpoints[:200] %}<li><code>{{ e }}</code></li>{% endfor %}</ul>
  {% endif %}
</div>
{% endfor %}

</body>
</html>
"""


def render_report(targets: list[TargetResult], output_path: Path) -> None:
    env = Environment(loader=BaseLoader(), autoescape=select_autoescape(["html"]))
    template = env.from_string(_TEMPLATE)
    html = template.render(targets=targets)
    output_path.write_text(html, encoding="utf-8")
