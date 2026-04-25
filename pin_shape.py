"""mitmproxy addon. pins shape scripts.

  mitmdump -p 8080 -s pin_shape.py
"""
from pathlib import Path
from mitmproxy import http

PIN_DIR = Path(__file__).resolve().parent / "pin"
HOST = "idp.movistar.com.ar"
STRIP_CSP = True

PINS = {
    "matcher": PIN_DIR / "matcher.js",
    "single":  PIN_DIR / "single.js",
    "async":   PIN_DIR / "async.beauty.stage6.js",
}

HIT_COUNT = {k: 0 for k in PINS}
DUMP_DIR = PIN_DIR.parent


def response(flow: http.HTTPFlow) -> None:
    if STRIP_CSP and flow.request.host == HOST:
        for h in ("content-security-policy", "content-security-policy-report-only",
                  "x-webkit-csp"):
            if h in flow.response.headers:
                del flow.response.headers[h]


def request(flow: http.HTTPFlow) -> None:
    req = flow.request
    if req.host != HOST:
        return
    path, _, raw_query = req.path.partition("?")

    if path.startswith("/__dump/") and req.method == "POST":
        name = path.rsplit("/", 1)[1]
        safe = "".join(c for c in name if c.isalnum() or c in "._-")[:64]
        if not safe:
            flow.response = http.Response.make(400, b"bad name", {})
            return
        out = DUMP_DIR / safe
        out.write_bytes(req.content)
        print(f"[pin_shape] dumped {safe} ({len(req.content)} bytes) -> {out}")
        flow.response = http.Response.make(
            200, b"OK",
            {"content-type": "text/plain",
             "access-control-allow-origin": "*"},
        )
        return

    if path != "/domaindomain.js":
        return
    variant = raw_query if raw_query in PINS else None
    if variant is None:
        return

    body = PINS[variant].read_bytes()
    HIT_COUNT[variant] += 1
    print(f"[pin_shape] served {variant}  (#{HIT_COUNT[variant]})  {len(body)} bytes")

    flow.response = http.Response.make(
        200,
        body,
        {
            "content-type": "application/javascript; charset=UTF-8",
            "cache-control": "no-cache, no-store, must-revalidate",
            "x-pinned-by": "pin_shape.py",
        },
    )
