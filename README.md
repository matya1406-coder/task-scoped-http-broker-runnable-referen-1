# Task-scoped HTTP broker: runnable reference deliverable

This addresses three concrete requirements: an agent cannot edit its egress policy, upstream credentials stay outside its environment, and each task has a hard call budget. It also provides short-lived, operation-scoped **broker capabilities**. These are not provider-native temporary credentials.

## Assumptions and boundary

- Python 3.12 standard library; Docker Compose v2 for the container example. The code blocks below are the complete files to extract into a separate evaluation directory. This delivery kit itself contains only four files.
- One trusted broker and trusted host; an untrusted, unprivileged agent with no host networking, Docker socket, host mounts, extra networks or access to the broker database or secret mount. Host administrators can bypass these controls.
- The reference connector is exactly `POST http://mock:9000/echo`, taking a text string of at most 1,000 characters. No caller-selected URLs, methods, headers or paths. Both Docker networks are internal: there is **no external API egress** in this demo.
- Only a trusted host operator issues tasks through a local CLI. Each task has one token, one scope, a maximum 15-minute lifetime and a fixed budget. There is no agent-facing issuance, refresh or reset endpoint. Never mint a replacement task automatically for an exhausted task.
- SQLite survives broker restarts. Reservations are atomic and committed before upstream I/O. Failures, timeouts and invalid upstream responses consume an attempt; rejected authorization and invalid inputs do not. No retries. Calls admitted before expiry can finish after expiry.
- The agent can steal its own token; this limits its authority rather than making the token secret from the agent. Keep issuance output private. Broker keys remain powerful credentials and broker compromise is out of scope.
- The mock uses plaintext on isolated networks and a fake key only. Real deployment needs authenticated TLS, provider-specific input/output schemas, and an externally enforced egress firewall or proxy with DNS/IP controls. Do not merely connect the broker to an unrestricted internet network. Block private, loopback, link-local and metadata destinations unless explicitly required; prevent DNS rebinding; pin approved destinations at the network boundary. Restrict agent access to other containers, host gateways and DNS too.

## `broker.py`

```python
import hashlib
import http.client
import json
import os
import secrets
import sqlite3
import sys
import time
from contextlib import closing
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

DB = os.environ.get("DB", "/state/tasks.db")
KEY_FILE = os.environ.get("KEY_FILE", "/run/secrets/service_key")
LIMIT = 4096

class Denied(Exception):
    pass

def connect():
    db = sqlite3.connect(DB, timeout=10, isolation_level=None)
    db.execute("PRAGMA synchronous=FULL")
    return db

def init():
    with closing(connect()) as db:
        db.execute("""CREATE TABLE IF NOT EXISTS tasks (
            id TEXT PRIMARY KEY, digest TEXT UNIQUE NOT NULL,
            operation TEXT NOT NULL, expires INTEGER NOT NULL,
            remaining INTEGER NOT NULL CHECK(remaining >= 0))""")

def mint(task, budget, ttl, operation="echo"):
    if not task or len(task) > 100 or not 1 <= budget <= 100:
        raise ValueError("invalid task or budget")
    if not 1 <= ttl <= 900 or operation != "echo":
        raise ValueError("invalid lifetime or operation")
    token = secrets.token_urlsafe(32)
    digest = hashlib.sha256(token.encode()).hexdigest()
    with closing(connect()) as db:
        # Duplicate task IDs fail; issuance never resets existing budgets.
        db.execute("INSERT INTO tasks VALUES (?,?,?,?,?)",
                   (task, digest, operation, int(time.time()) + ttl, budget))
    return token

def reserve(token, operation):
    digest = hashlib.sha256(token.encode()).hexdigest()
    db = connect()
    try:
        db.execute("BEGIN IMMEDIATE")
        row = db.execute("SELECT id, operation, expires, remaining FROM tasks "
                         "WHERE digest=?", (digest,)).fetchone()
        if not row or row[1] != operation or row[2] <= time.time() or row[3] <= 0:
            raise Denied()
        db.execute("UPDATE tasks SET remaining=remaining-1 WHERE id=?", (row[0],))
        db.commit()
    except Exception:
        db.rollback()
        raise
    finally:
        db.close()

def validate(value):
    if not isinstance(value, dict) or set(value) != {"operation", "text"}:
        raise ValueError()
    if value["operation"] != "echo" or not isinstance(value["text"], str):
        raise ValueError()
    if len(value["text"]) > 1000:
        raise ValueError()
    return value

def upstream(value):
    # No redirects, proxies, dynamic hostname, custom headers or arbitrary path.
    with open(KEY_FILE, encoding="utf-8") as f:
        key = f.read().strip()
    if not key or "\r" in key or "\n" in key:
        raise ValueError()
    conn = http.client.HTTPConnection("mock", 9000, timeout=5)
    try:
        conn.request("POST", "/echo", json.dumps({"text": value["text"]}),
                     {"Authorization": "Bearer " + key,
                      "Content-Type": "application/json"})
        response = conn.getresponse()
        raw = response.read(LIMIT + 1)
        if response.status != 200 or len(raw) > LIMIT:
            raise ValueError()
        result = json.loads(raw)
        # Only return this connector's agreed field; never forward headers/errors.
        if not isinstance(result, dict) or result.get("text") != value["text"]:
            raise ValueError()
        return {"text": value["text"]}
    finally:
        conn.close()

class Handler(BaseHTTPRequestHandler):
    def setup(self):
        super().setup()
        self.connection.settimeout(5)

    def log_message(self, *args):
        pass  # Never log authorization, request bodies or upstream errors.

    def reply(self, status, payload):
        body = json.dumps(payload).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(body)

    def do_POST(self):
        if self.path != "/call":
            return self.reply(404, {"error": "unknown route"})
        try:
            if self.headers.get("Transfer-Encoding") is not None:
                raise ValueError()
            lengths = self.headers.get_all("Content-Length", [])
            if len(lengths) != 1 or not 0 < int(lengths[0]) <= LIMIT:
                raise ValueError()
            if self.headers.get("Content-Type") != "application/json":
                raise ValueError()
            value = validate(json.loads(self.rfile.read(int(lengths[0]))))
            auth = self.headers.get_all("Authorization", [])
            if len(auth) != 1 or not auth[0].startswith("Bearer "):
                raise Denied()
            token = auth[0][7:]
            if not 20 <= len(token) <= 200:
                raise Denied()
        except Denied:
            return self.reply(403, {"error": "denied"})
        except Exception:
            return self.reply(400, {"error": "invalid request"})
        try:
            reserve(token, value["operation"])
        except Denied:
            return self.reply(403, {"error": "denied"})
        except Exception:
            return self.reply(503, {"error": "authorization unavailable"})
        try:
            result = upstream(value)
        except Exception:
            return self.reply(502, {"error": "upstream failed; attempt consumed"})
        self.reply(200, result)

if __name__ == "__main__":
    init()
    if len(sys.argv) > 1 and sys.argv[1] == "mint":
        print(mint(sys.argv[2], int(sys.argv[3]), int(sys.argv[4])))
    else:
        ThreadingHTTPServer(("0.0.0.0", 8080), Handler).serve_forever()
```

## `mock.py`

```python
import json
from http.server import BaseHTTPRequestHandler, HTTPServer

class Mock(BaseHTTPRequestHandler):
    def log_message(self, *args):
        pass

    def do_POST(self):
        if self.path != "/echo" or self.headers.get("Authorization") != "Bearer demo-only":
            self.send_error(403)
            return
        try:
            length = int(self.headers.get("Content-Length", "0"))
            if not 0 < length <= 4096:
                raise ValueError()
            value = json.loads(self.rfile.read(length))
            body = json.dumps({"text": value["text"]}).encode()
        except Exception:
            self.send_error(400)
            return
        self.send_response(200)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

HTTPServer(("0.0.0.0", 9000), Mock).serve_forever()
```

## `Dockerfile`

```dockerfile
FROM python:3.12-slim
WORKDIR /app
ENV PYTHONDONTWRITEBYTECODE=1
RUN mkdir /state && chown 10001:10001 /state
COPY broker.py mock.py /app/
USER 10001:10001
CMD ["python", "broker.py"]
```

## `compose.yaml`

```yaml
services:
  broker:
    build: .
    read_only: true
    cap_drop: [ALL]
    security_opt: [no-new-privileges:true]
    pids_limit: 64
    mem_limit: 128m
    volumes: [state:/state]
    secrets: [service_key]
    networks: [agent_net, service_net]
  mock:
    build: .
    command: [python, mock.py]
    read_only: true
    cap_drop: [ALL]
    security_opt: [no-new-privileges:true]
    networks: [service_net]
  agent:
    image: python:3.12-slim
    user: "10002:10002"
    command: [python, -c, "import time; time.sleep(86400)"]
    read_only: true
    cap_drop: [ALL]
    security_opt: [no-new-privileges:true]
    networks: [agent_net]
networks:
  agent_net:
    internal: true
  service_net:
    internal: true
volumes:
  state:
secrets:
  service_key:
    file: ./demo-key.txt
```

Create `demo-key.txt` containing only `demo-only` and a newline. It is a fake credential. Compose mounts it into the broker only; the mock knows the fake value in code. Never replace the mock's literal with a real service secret. For production use the customer's secret manager; Compose file-backed secrets are not an encrypted secret store.

## Local use and integration

These are instructions for the recipient, not commands executed during preparation. With the Python base image already available, run `docker compose build --pull=false`, then `docker compose up -d`. Initial image acquisition requires network access if it is not cached. Pin an approved image digest for deployment. No packages are downloaded by this Dockerfile.

On the trusted host, issue one task:

```text
docker compose exec -T broker python broker.py mint example-task 2 300
```

Copy the printed token into the placeholder below. Send this snippet through `docker compose exec -T agent python -` with standard input, or use the same code in your agent. The token is the only credential given to the agent. Avoid storing it in shared shell history.

```python
import json
import urllib.request

token = "PASTE_TASK_TOKEN"
request = urllib.request.Request(
    "http://broker:8080/call",
    data=json.dumps({"operation": "echo", "text": "hello"}).encode(),
    headers={"Content-Type": "application/json", "Authorization": "Bearer " + token},
    method="POST",
)
with urllib.request.urlopen(request, timeout=10) as response:
    print(response.read().decode())
```

Two calls return `{"text": "hello"}`; a third returns HTTP 403. Restart the broker with `docker compose restart broker`: the third call must still fail. Issuing `example-task` again must fail rather than reset the budget. Keep the state volume; deleting or restoring an old database can resurrect budgets. Retain task IDs for the duration of the evaluation. There is no automatic task cleanup.

## `test_broker.py`: local tests, no network required

```python
import concurrent.futures
import os
import sqlite3
import tempfile
import unittest
from unittest.mock import patch
import broker

class Tests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        broker.DB = os.path.join(self.tmp.name, "tasks.db")
        broker.init()

    def tearDown(self):
        self.tmp.cleanup()

    def test_budget_persists_and_task_cannot_reset(self):
        token = broker.mint("a", 1, 300)
        broker.reserve(token, "echo")
        broker.init()
        with self.assertRaises(broker.Denied):
            broker.reserve(token, "echo")
        with self.assertRaises(sqlite3.IntegrityError):
            broker.mint("a", 1, 300)

    def test_expiry_unknown_token_and_scope(self):
        with patch.object(broker.time, "time", return_value=1000):
            token = broker.mint("a", 1, 1)
            with self.assertRaises(broker.Denied):
                broker.reserve(token, "delete")
            with self.assertRaises(broker.Denied):
                broker.reserve("unknown-token", "echo")
        with patch.object(broker.time, "time", return_value=1001):
            with self.assertRaises(broker.Denied):
                broker.reserve(token, "echo")

    def test_atomic_budget(self):
        token = broker.mint("a", 3, 300)
        def attempt(_):
            try:
                broker.reserve(token, "echo")
                return 1
            except broker.Denied:
                return 0
        with concurrent.futures.ThreadPoolExecutor(max_workers=8) as pool:
            self.assertEqual(sum(pool.map(attempt, range(20))), 3)

    def test_reject_arbitrary_destination_and_input(self):
        for value in [
            {"operation": "echo", "text": "x", "url": "http://metadata/"},
            {"operation": "delete", "text": "x"},
            {"operation": "echo", "text": "x" * 1001},
            {"operation": "echo", "text": 7},
        ]:
            with self.assertRaises(ValueError):
                broker.validate(value)

    def test_fixed_connector_filters_secret_and_redirects(self):
        class Response:
            status = 200
            def read(self, limit):
                return b'{"text":"hi","secret":"demo-only"}'
        class Connection:
            def __init__(self, host, port, timeout):
                assert (host, port, timeout) == ("mock", 9000, 5)
            def request(self, method, path, body, headers):
                assert (method, path) == ("POST", "/echo")
                assert headers["Authorization"] == "Bearer demo-only"
            def getresponse(self):
                return Response()
            def close(self):
                pass
        from unittest.mock import mock_open
        with patch("builtins.open", mock_open(read_data="demo-only")), \
             patch.object(broker.http.client, "HTTPConnection", Connection):
            self.assertEqual(broker.upstream({"text": "hi"}), {"text": "hi"})
            Response.status = 302
            with self.assertRaises(ValueError):
                broker.upstream({"text": "hi"})

if __name__ == "__main__":
    unittest.main()
```

Run `python -B -m unittest -v test_broker` after extracting the files. These tests exercise budget persistence through new database connections, concurrent reservations, duplicate issuance, expiry, scope, strict input and the fixed connector. They do not prove container isolation or full HTTP parsing correctness.

## Deployment acceptance checks

1. Run the container integration example and verify the exact 200/200/403 sequence, then restart and confirm continued denial. Verify missing/expired/incorrect bearer tokens are denied without an upstream call.
2. Stop the mock, issue a new one-call task, and call the broker: expect 502; start the mock and retry the same token: expect 403. A reservation is spent even if the process crashes before dispatch. This favors a hard upper bound over availability.
3. From the agent, verify no route to the mock, internet, host services, cloud metadata or private production networks, and no way to read the secret/database. Check the actual host firewall, IPv4/IPv6 and Docker DNS behavior; Compose `internal` alone is not proof of complete host isolation. For an offline test use an isolated external-network canary controlled by the operator, not a public destination.
4. Confirm redirect responses do not trigger a second request, arbitrary URL fields fail, and responses/errors/logs never contain the fake upstream credential. Review each future connector: a permitted API can itself expose secrets or trigger server-side requests.
5. Production hardening still required: authenticated encrypted transport, ingress concurrency/rate limits, total request deadlines, trusted issuance authentication and audit events without tokens, revocation, schema review, resource exhaustion tests, encrypted backup policy, and a deployment-specific network test. The standard-library threaded HTTP server is for a controlled pilot, not hostile public traffic.

To revoke a task immediately, a trusted operator may set its `remaining` to zero with a parameterized SQLite update; already dispatched calls cannot be recalled. Stop the agent and broker to end the pilot (`docker compose stop`). Do not use volume deletion as a routine restart mechanism. Native provider tokens, financial budgets, multiple broker hosts, arbitrary browser traffic and production certification are outside this reference scope.
