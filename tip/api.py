"""API REST mínima para o TIP usando apenas a stdlib (http.server).

Rotas:
  GET  /health
  GET  /stats
  GET  /lookup?value=<ioc>
  GET  /search?type=&threat=&min_confidence=
  POST /ioc            {value, threat, source, confidence, tags}
"""

from __future__ import annotations

import json
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlparse, parse_qs

from .store import TIPStore, IOC


def make_handler(store: TIPStore):
    class Handler(BaseHTTPRequestHandler):
        def log_message(self, *args):
            pass

        def _send(self, code: int, payload: dict):
            body = json.dumps(payload, ensure_ascii=False).encode()
            self.send_response(code)
            self.send_header("Content-Type", "application/json; charset=utf-8")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def do_GET(self):
            u = urlparse(self.path)
            qs = parse_qs(u.query)
            if u.path == "/health":
                return self._send(200, {"status": "ok"})
            if u.path == "/stats":
                return self._send(200, store.stats())
            if u.path == "/lookup":
                val = qs.get("value", [""])[0]
                if not val:
                    return self._send(400, {"error": "value obrigatório"})
                res = store.lookup(val)
                return self._send(200, {"found": bool(res), "results": res})
            if u.path == "/search":
                res = store.search(
                    type=qs.get("type", [None])[0],
                    threat=qs.get("threat", [None])[0],
                    min_confidence=int(qs.get("min_confidence", ["0"])[0]),
                )
                return self._send(200, {"count": len(res), "results": res})
            return self._send(404, {"error": "rota não encontrada"})

        def do_POST(self):
            u = urlparse(self.path)
            if u.path != "/ioc":
                return self._send(404, {"error": "rota não encontrada"})
            length = int(self.headers.get("Content-Length", 0))
            try:
                data = json.loads(self.rfile.read(length) or b"{}")
            except json.JSONDecodeError:
                return self._send(400, {"error": "JSON inválido"})
            if "value" not in data:
                return self._send(400, {"error": "campo 'value' obrigatório"})
            ioc = IOC(
                value=data["value"], type=data.get("type", ""),
                threat=data.get("threat", ""), source=data.get("source", ""),
                confidence=int(data.get("confidence", 50)),
                tags=data.get("tags", ""),
            )
            ioc_id = store.add(ioc)
            return self._send(201, {"id": ioc_id, "value": ioc.value})

    return Handler


def serve(store: TIPStore, host: str = "127.0.0.1", port: int = 8088):
    httpd = ThreadingHTTPServer((host, port), make_handler(store))
    return httpd
