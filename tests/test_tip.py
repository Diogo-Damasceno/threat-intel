import json
import threading
import urllib.request

from tip.store import TIPStore, IOC, detect_type
from tip.api import serve


def test_detect_type():
    assert detect_type("8.8.8.8") == "ip"
    assert detect_type("http://evil.com/x") == "url"
    assert detect_type("evil.com") == "domain"
    assert detect_type("a@b.com") == "email"
    assert detect_type("d41d8cd98f00b204e9800998ecf8427e") == "md5"
    assert detect_type("da39a3ee5e6b4b0d3255bfef95601890afd80709") == "sha1"
    assert detect_type("e3b0c44298fc1c149afbf4c8996fb92427ae41e4"
                       "649b934ca495991b7852b855") == "sha256"


def test_add_and_lookup():
    s = TIPStore(":memory:")
    s.add(IOC("1.2.3.4", "ip", threat="C2", source="test", confidence=90))
    res = s.lookup("1.2.3.4")
    assert len(res) == 1
    assert res[0]["threat"] == "C2"
    assert res[0]["confidence"] == 90


def test_dedup_updates():
    s = TIPStore(":memory:")
    id1 = s.add(IOC("1.2.3.4", "ip", threat="C2"))
    id2 = s.add(IOC("1.2.3.4", "ip", threat="phishing", confidence=80))
    assert id1 == id2  # mesmo registro
    res = s.lookup("1.2.3.4")[0]
    assert res["threat"] == "phishing"


def test_search_filters():
    s = TIPStore(":memory:")
    s.add(IOC("1.1.1.1", "ip", threat="C2", confidence=90))
    s.add(IOC("evil.com", "domain", threat="phishing", confidence=40))
    ips = s.search(type="ip")
    assert len(ips) == 1
    high = s.search(min_confidence=80)
    assert len(high) == 1 and high[0]["value"] == "1.1.1.1"


def test_import_bulk():
    s = TIPStore(":memory:")
    n = s.import_bulk(["8.8.8.8", "# comentário", "", "bad.com"], threat="test")
    assert n == 2
    assert s.stats()["total"] == 2


def test_stats():
    s = TIPStore(":memory:")
    s.add(IOC("1.1.1.1", "ip", threat="C2"))
    s.add(IOC("2.2.2.2", "ip", threat="C2"))
    st = s.stats()
    assert st["total"] == 2
    assert st["by_type"]["ip"] == 2
    assert st["by_threat"]["C2"] == 2


def test_rest_api_roundtrip():
    s = TIPStore(":memory:")
    httpd = serve(s, "127.0.0.1", 8091)
    t = threading.Thread(target=httpd.serve_forever, daemon=True)
    t.start()
    try:
        # POST
        req = urllib.request.Request(
            "http://127.0.0.1:8091/ioc",
            data=json.dumps({"value": "9.9.9.9", "threat": "C2",
                             "confidence": 95}).encode(),
            headers={"Content-Type": "application/json"}, method="POST")
        r = urllib.request.urlopen(req, timeout=3)
        assert r.status == 201
        # lookup
        r2 = urllib.request.urlopen(
            "http://127.0.0.1:8091/lookup?value=9.9.9.9", timeout=3)
        data = json.loads(r2.read())
        assert data["found"] is True
        assert data["results"][0]["threat"] == "C2"
        # health
        r3 = urllib.request.urlopen("http://127.0.0.1:8091/health", timeout=3)
        assert json.loads(r3.read())["status"] == "ok"
    finally:
        httpd.shutdown()
