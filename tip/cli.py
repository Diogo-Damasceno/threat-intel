"""CLI do Threat Intelligence Platform."""

from __future__ import annotations

import argparse
import json
import sys

from .store import TIPStore, IOC, detect_type
from .api import serve


def main(argv=None):
    p = argparse.ArgumentParser(description="Threat Intelligence Platform (IOCs).")
    p.add_argument("--db", default="tip.db")
    sub = p.add_subparsers(dest="cmd", required=True)

    a = sub.add_parser("add", help="adiciona um IOC")
    a.add_argument("value")
    a.add_argument("--threat", default="")
    a.add_argument("--source", default="")
    a.add_argument("--confidence", type=int, default=50)
    a.add_argument("--tags", default="")

    lk = sub.add_parser("lookup", help="consulta um IOC")
    lk.add_argument("value")

    s = sub.add_parser("search", help="busca IOCs")
    s.add_argument("--type")
    s.add_argument("--threat")
    s.add_argument("--min-confidence", type=int, default=0)

    imp = sub.add_parser("import", help="importa IOCs de um arquivo (um por linha)")
    imp.add_argument("file")
    imp.add_argument("--threat", default="")
    imp.add_argument("--source", default="")
    imp.add_argument("--confidence", type=int, default=50)

    sub.add_parser("stats", help="estatísticas")

    srv = sub.add_parser("serve", help="inicia a API REST")
    srv.add_argument("--host", default="127.0.0.1")
    srv.add_argument("--port", type=int, default=8088)

    args = p.parse_args(argv)
    store = TIPStore(args.db)

    if args.cmd == "add":
        iid = store.add(IOC(args.value, detect_type(args.value), args.threat,
                            args.source, args.confidence, args.tags))
        print(f"IOC #{iid} adicionado ({detect_type(args.value)}): {args.value}")
    elif args.cmd == "lookup":
        res = store.lookup(args.value)
        print(json.dumps({"found": bool(res), "results": res},
                         ensure_ascii=False, indent=2))
    elif args.cmd == "search":
        res = store.search(type=args.type, threat=args.threat,
                           min_confidence=args.min_confidence)
        print(json.dumps({"count": len(res), "results": res},
                         ensure_ascii=False, indent=2))
    elif args.cmd == "import":
        with open(args.file) as f:
            lines = f.readlines()
        n = store.import_bulk(lines, args.threat, args.source, args.confidence)
        print(f"{n} IOCs importados.")
    elif args.cmd == "stats":
        print(json.dumps(store.stats(), ensure_ascii=False, indent=2))
    elif args.cmd == "serve":
        httpd = serve(store, args.host, args.port)
        print(f"[*] API TIP em http://{args.host}:{args.port} (Ctrl+C para parar)")
        try:
            httpd.serve_forever()
        except KeyboardInterrupt:
            print("\n[*] Encerrado.")
            httpd.shutdown()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
