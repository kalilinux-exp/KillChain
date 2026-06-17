"""A zero-dependency local web app for Killchain (stdlib http.server only).

Routes
  GET  /                -> the upload page (drag a log in, or pick a sample)
  GET  /demo            -> generate a fresh attack log and analyze it
  GET  /sample/<name>   -> analyze a bundled sample (basename-guarded)
  POST /analyze         -> analyze the raw request body (the dropped file's text)

The browser sends the dropped file's *text* as the raw POST body (read via
FileReader), so we never need multipart parsing — handy, since Python removed
the `cgi` module in 3.13. Bound to 127.0.0.1 only; this is a local analyst tool.
"""

from __future__ import annotations

import http.server
import os
import threading
import urllib.parse
import webbrowser

from . import analyze_text
from .report import render_report
from .scenarios import generate_scenario, list_archetypes

SAMPLES_DIR = os.path.join(os.path.dirname(__file__), "samples")
_MAX_UPLOAD = 8 * 1024 * 1024  # 8 MB cap so a huge paste can't exhaust memory


def _list_samples() -> list[str]:
    if not os.path.isdir(SAMPLES_DIR):
        return []
    return sorted(f for f in os.listdir(SAMPLES_DIR) if f.endswith(".log"))


def _upload_page() -> str:
    # A random roll plus one button per archetype, so judges can try every
    # attack shape — and see the engine react differently to each.
    buttons = ['<a class="btn primary" href="/demo">Generate a random attack</a>']
    for key, label in list_archetypes():
        buttons.append(f'<a class="btn" href="/demo?type={urllib.parse.quote(key)}">{label}</a>')
    return _PAGE_TEMPLATE.replace("__BUTTONS__", "".join(buttons))


def _message_page(title: str, message: str) -> str:
    note = (f'<div id="drop"><div class="big">{title}</div>'
            f'<div class="small">{message}</div></div>')
    page = _PAGE_TEMPLATE.replace(
        "__BUTTONS__", '<a class="btn" href="/">&larr; back to start</a>')
    # Replace the whole drop-zone block (from its open tag up to the file input)
    # with the message — there is exactly one #drop element in the template.
    start = page.index('<div id="drop">')
    end = page.index('<input id="file"', start)
    return page[:start] + note + page[end:]


class Handler(http.server.BaseHTTPRequestHandler):
    server_version = "Killchain"

    # -- helpers ----------------------------------------------------------- #
    def _send_html(self, body: str, code: int = 200) -> None:
        data = body.encode("utf-8")
        self.send_response(code)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def log_message(self, *args) -> None:  # keep the console quiet
        pass

    # -- routes ------------------------------------------------------------ #
    def do_GET(self) -> None:
        path = urllib.parse.urlparse(self.path).path
        if path == "/":
            self._send_html(_upload_page())
        elif path == "/demo":
            qs = urllib.parse.parse_qs(urllib.parse.urlparse(self.path).query)
            atype = qs.get("type", [None])[0]
            text, truth = generate_scenario(atype)
            report = analyze_text(text, truth["label"])
            self._send_html(render_report(report))
        elif path.startswith("/sample/"):
            self._serve_sample(path[len("/sample/"):])
        else:
            self.send_error(404, "Not found")

    def _serve_sample(self, raw_name: str) -> None:
        name = os.path.basename(urllib.parse.unquote(raw_name))  # block traversal
        target = os.path.join(SAMPLES_DIR, name)
        if not name.endswith(".log") or not os.path.isfile(target):
            self.send_error(404, "Sample not found")
            return
        with open(target, "r", encoding="utf-8", errors="replace") as fh:
            text = fh.read()
        self._send_html(render_report(analyze_text(text, name)))

    def do_POST(self) -> None:
        if urllib.parse.urlparse(self.path).path != "/analyze":
            self.send_error(404, "Not found")
            return
        length = int(self.headers.get("Content-Length", 0) or 0)
        if length > _MAX_UPLOAD:
            self._send_html(_message_page("File too large", "Maximum upload is 8 MB."), 413)
            return
        text = self.rfile.read(length).decode("utf-8", errors="replace") if length else ""
        if not text.strip():
            self._send_html(_message_page("Empty file", "Nothing to analyze."))
            return
        self._send_html(render_report(analyze_text(text, "(uploaded log)")))


def serve(port: int = 8000, open_browser: bool = True) -> None:
    """Start the local web app (blocking)."""
    httpd = http.server.ThreadingHTTPServer(("127.0.0.1", port), Handler)
    url = f"http://127.0.0.1:{port}/"
    print(f"Killchain running at {url}  (Ctrl+C to stop)")
    if open_browser:
        threading.Timer(0.6, lambda: webbrowser.open(url)).start()
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        print("\nstopped")
    finally:
        httpd.server_close()


# The landing page. Kept visually consistent with the report; __BUTTONS__ is
# replaced at request time with the sample/demo links.
_PAGE_TEMPLATE = """<!doctype html><html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>killchain</title><style>
:root{--bg:#0a0c0f;--panel:#12151b;--line:#21262e;--line2:#2b323c;
 --ink:#e6e9ef;--muted:#8b93a1;--dim:#5a626e;--accent:#e0443e;
 --mono:ui-monospace,"SF Mono","Cascadia Mono",Menlo,Consolas,monospace;
 --sans:Inter,system-ui,-apple-system,"Segoe UI",sans-serif;}
* { box-sizing:border-box; }
body { margin:0; background:var(--bg); color:var(--ink); min-height:100vh; font-family:var(--sans);
  font-size:15px; -webkit-font-smoothing:antialiased; display:flex; align-items:center; justify-content:center; }
.box { width:100%; max-width:540px; padding:32px 24px; }
.title { font-family:var(--mono); font-size:15px; font-weight:600; letter-spacing:.2em; text-transform:uppercase; }
.title::before { content:""; display:inline-block; width:8px; height:8px; margin-right:10px;
  background:var(--accent); vertical-align:middle; }
.sub { color:var(--muted); font-family:var(--mono); font-size:12.5px; letter-spacing:.02em; margin:10px 0 28px; }
#drop { border:1px solid var(--line2); border-radius:5px; padding:44px 20px; text-align:center;
  cursor:pointer; transition:.15s; background:var(--panel); }
#drop:hover, #drop.over { border-color:var(--accent); background:#14171d; }
#drop .big { font-size:15px; color:var(--ink); }
#drop code { font-family:var(--mono); color:var(--accent); font-size:13px; }
#drop .small { color:var(--dim); font-size:12px; margin-top:7px; font-family:var(--mono); }
.or { color:var(--dim); margin:22px 0 14px; font-size:11px; letter-spacing:.22em; text-transform:uppercase; font-family:var(--mono); }
.btns { display:flex; flex-wrap:wrap; gap:9px; }
.btn { display:inline-block; padding:10px 15px; border-radius:4px; text-decoration:none; font-size:12.5px;
  background:transparent; color:var(--muted); border:1px solid var(--line2); font-family:var(--mono); transition:.15s; }
.btn:hover { border-color:var(--muted); color:var(--ink); }
.btn.primary { background:transparent; color:var(--accent); border-color:#e0443e66; font-weight:600; }
.btn.primary:hover { background:#e0443e14; border-color:var(--accent); color:#fff; }
.foot { color:var(--dim); font-size:11px; margin-top:30px; font-family:var(--mono); letter-spacing:.03em; }
</style></head><body><div class="box">
<div class="title">killchain</div>
<div class="sub">SSH auth.log &rarr; attack-chain reconstruction</div>
<div id="drop">
  <div class="big">Drop an <code>auth.log</code> to analyze</div>
  <div class="small">or click to choose a file</div>
</div>
<input id="file" type="file" accept=".log,.txt,text/plain" style="display:none">
<div class="or">or load a sample</div>
<div class="btns">__BUTTONS__</div>
<div class="foot">pure-Python stdlib &middot; no installs &middot; MITRE ATT&amp;CK mapped</div>
</div>
<script>
var drop=document.getElementById('drop'), file=document.getElementById('file');
function analyze(text){
  fetch('/analyze',{method:'POST',body:text})
    .then(function(r){return r.text();})
    .then(function(html){document.open();document.write(html);document.close();});
}
function handle(f){ var r=new FileReader(); r.onload=function(e){analyze(e.target.result);}; r.readAsText(f); }
drop.addEventListener('dragover',function(e){e.preventDefault();drop.classList.add('over');});
drop.addEventListener('dragleave',function(){drop.classList.remove('over');});
drop.addEventListener('drop',function(e){e.preventDefault();drop.classList.remove('over');
  if(e.dataTransfer.files[0])handle(e.dataTransfer.files[0]);});
drop.addEventListener('click',function(){file.click();});
file.addEventListener('change',function(e){if(e.target.files[0])handle(e.target.files[0]);});
</script>
</body></html>"""
