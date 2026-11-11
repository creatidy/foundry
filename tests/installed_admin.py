"""Private SR bootstrap and verified HTTPS session for installed test adapters."""

import http.client
import json
import re
import secrets
from html.parser import HTMLParser


class _CSRF(HTMLParser):
    def __init__(self):
        super().__init__()
        self.tokens = []

    def handle_starttag(self, tag, attrs):
        attributes = dict(attrs)
        if tag == "input" and attributes.get("name") == "csrf" and attributes.get("value"):
            self.tokens.append(attributes["value"])


class AdminSession:
    def __init__(self, project):
        self.project = project
        self.password = secrets.token_urlsafe(32)
        self.cookie = None
        self.csrf = None

    def _request(self, method, path, body=None, headers=None):
        if (method not in ("GET", "POST", "DELETE") or not path.startswith("/") or
                path.startswith("//") or "\r" in path or "\n" in path):
            raise ValueError("invalid local HTTP request")
        wire = None if body is None else json.dumps(body, separators=(",", ":")).encode()
        if wire is not None and len(wire) > 1024 * 1024:
            raise ValueError("request too large")
        request_headers = dict(headers or {})
        if wire is not None:
            request_headers["Content-Type"] = "application/json"
        connection = http.client.HTTPSConnection("127.0.0.1", self.project.port,
                                                context=self.project.tls_context(), timeout=10)
        try:
            connection.request(method, path, body=wire, headers=request_headers)
            response = connection.getresponse()
            raw = response.read(1024 * 1024 + 1)
            if len(raw) > 1024 * 1024:
                raise ValueError("response too large")
            return response.status, raw, response.getheaders()
        finally:
            connection.close()

    def _establish(self, path, body):
        status, _, headers = self._request("POST", path, body)
        if status != 200:
            raise RuntimeError("administrator session creation failed")
        cookies = [value.split(";", 1)[0] for name, value in headers
                   if name.lower() == "set-cookie" and value.startswith("scarcity-router-admin=")]
        if len(cookies) != 1 or not re.fullmatch(r"scarcity-router-admin=[A-Za-z0-9_-]+", cookies[0]):
            raise ValueError("invalid administrator session cookie")
        status, page, _ = self._request("GET", "/admin", headers={"Cookie": cookies[0]})
        if status != 200:
            raise RuntimeError("administrator page unavailable")
        parser = _CSRF()
        parser.feed(page.decode("utf-8"))
        if not parser.tokens or len(set(parser.tokens)) != 1:
            raise ValueError("administrator CSRF token unavailable")
        self.cookie, self.csrf = cookies[0], parser.tokens[0]

    def bootstrap(self):
        project = self.project
        if project.port is None:
            raise ValueError("expected running owned router and proxy required")
        project.require_roles()
        try:
            claim = project._docker("exec", project.container_id, "python", "-m",
                                    "scarcity_router.control_server", "--data-dir", "/data",
                                    "--issue-bootstrap-claim", timeout=20).strip()
        except Exception:
            raise RuntimeError("bootstrap claim issuance failed") from None
        if not re.fullmatch(r"[A-Za-z0-9_-]{32,128}", claim):
            raise ValueError("invalid bootstrap claim")
        self._establish("/control/bootstrap/admin", {"claim": claim, "password": self.password, "confirm": True})

    def login(self):
        self._establish("/control/session", {"password": self.password})

    def exchange(self, method, path, body, headers, *, admin):
        headers = dict(headers)
        if any(key.lower() in ("cookie", "x-scarcity-csrf") for key in headers):
            raise ValueError("caller cannot supply session headers")
        if admin:
            if not self.cookie or not self.csrf:
                raise ValueError("administrator session not established")
            headers.update({"Cookie": self.cookie, "X-Scarcity-CSRF": self.csrf})
        status, raw, _ = self._request(method, path, body, headers)
        try:
            payload = json.loads(raw)
        except (ValueError, UnicodeDecodeError):
            raise ValueError("server returned non-JSON response") from None
        return status, payload

    def assert_auth_boundaries(self):
        """Check installed session/CSRF separation over the verified connection."""
        if not self.cookie or not self.csrf:
            raise ValueError("administrator session not established")
        for headers in ({"Cookie": self.cookie},
                        {"Cookie": self.cookie, "X-Scarcity-CSRF": "invalid-test-csrf"}):
            status, _, _ = self._request("POST", "/control/mi/reload", {}, headers)
            if status != 403:
                raise AssertionError("administrator mutation did not reject missing or invalid CSRF")
        status, _, _ = self._request("POST", "/v1/select", {
            "requirement": {"task_level": "L0", "capability_minima": {}, "hard_constraints": {}}
        }, {"Cookie": self.cookie, "X-Scarcity-CSRF": self.csrf})
        if status != 401:
            raise AssertionError("administrator session authorized an inference request")
