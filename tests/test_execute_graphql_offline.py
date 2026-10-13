"""Offline tests for Execute GraphQL Query - a loopback fake Horizon3.ai
server, no network and no real credentials."""

import json
import sys
import threading
import types
import logging
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

import pytest

if "connectors.core.connector" not in sys.modules:
    _c = types.ModuleType("connectors")
    _c.__path__ = []
    _core = types.ModuleType("connectors.core")
    _core.__path__ = []
    _mod = types.ModuleType("connectors.core.connector")

    class _ConnectorError(Exception):
        pass

    _mod.ConnectorError = _ConnectorError
    _mod.get_logger = logging.getLogger
    _mod.Connector = object
    _core.connector = _mod
    _c.core = _core
    sys.modules.update({"connectors": _c, "connectors.core": _core,
                        "connectors.core.connector": _mod})

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from connectors.core.connector import ConnectorError  # noqa: E402
from horizonAi.operations import operations  # noqa: E402

run = operations["execute_graphql_query"]
GOOD_KEY = "good-key"
JWT = "jwt-abc"
SEEN = []


class Handler(BaseHTTPRequestHandler):
    def log_message(self, fmt, *args):
        pass

    def _send(self, status, body):
        raw = json.dumps(body).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(raw)))
        self.end_headers()
        self.wfile.write(raw)

    def do_POST(self):
        n = int(self.headers.get("Content-Length") or 0)
        body = json.loads(self.rfile.read(n) or b"{}")
        if self.path == "/v1/auth":
            if body.get("key") == GOOD_KEY:
                self._send(200, {"token": JWT})
            else:
                self._send(401, {"error": "bad key"})
        elif self.path == "/v1/graphql":
            if self.headers.get("Authorization") != "Bearer " + JWT:
                self._send(401, {"error": "unauthorized"})
                return
            SEEN.append(body)
            if "boom" in body["query"]:
                self._send(200, {"data": None, "errors": [
                    {"message": "Cannot query field boom"}, {"message": "second"}]})
            else:
                self._send(200, {"data": {"echo": body.get("variables")}})
        else:
            self._send(404, {})


@pytest.fixture()
def config():
    del SEEN[:]
    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    yield {"server_url": "http://127.0.0.1:%d" % server.server_address[1],
           "api_token": GOOD_KEY, "verify_ssl": False}
    server.shutdown()
    server.server_close()


def test_success_with_variables_and_auth(config):
    resp = run(config, {"query": "query q($a: Int) { echo }",
                        "variables": '{"a": 1}', "operation_name": "q"})
    assert resp == {"data": {"echo": {"a": 1}}}
    assert SEEN[0]["operationName"] == "q"
    assert SEEN[0]["variables"] == {"a": 1}


def test_variables_as_dict(config):
    resp = run(config, {"query": "{ echo }", "variables": {"b": 2}})
    assert resp["data"]["echo"] == {"b": 2}


def test_blank_variables(config):
    resp = run(config, {"query": "{ echo }", "variables": "  "})
    assert resp["data"]["echo"] is None
    assert "variables" not in SEEN[0]


def test_graphql_errors_surfaced(config):
    with pytest.raises(ConnectorError) as exc:
        run(config, {"query": "{ boom }"})
    assert "Cannot query field boom" in str(exc.value)
    assert "second" in str(exc.value)


def test_auth_failure(config):
    config["api_token"] = "wrong"
    with pytest.raises(ConnectorError) as exc:
        run(config, {"query": "{ echo }"})
    assert "Authentication failed" in str(exc.value)


def test_invalid_variables_json(config):
    with pytest.raises(ConnectorError) as exc:
        run(config, {"query": "{ echo }", "variables": "{nope"})
    assert "not valid JSON" in str(exc.value)


def test_variables_not_object(config):
    with pytest.raises(ConnectorError):
        run(config, {"query": "{ echo }", "variables": "[1, 2]"})


def test_missing_query(config):
    for params in ({}, {"query": "  "}):
        with pytest.raises(ConnectorError) as exc:
            run(config, params)
        assert "query is required" in str(exc.value)
