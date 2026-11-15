# Henbane as a ForwardAuth / auth_request sidecar

Run Henbane in front of your existing **nginx** or **Traefik** without replacing
it. Your front proxy asks Henbane about each request; Henbane runs the full
decision pipeline and answers:

- **`204 No Content`** → allow; the front proxy serves the real backend.
- **non-`2xx`** → deny, with the challenge page / maze / `403` as the body.

```bash
henbane --sidecar --config /etc/henbane.yaml   # same YAML as the reverse proxy; no upstream
```

The sidecar reconstructs the original request from the headers the front proxy
forwards, so the classifier sees the real path, method, host, and client IP:

| What | Headers read (first non-empty wins) |
|------|-------------------------------------|
| Path + query | `X-Forwarded-Uri` |
| Method | `X-Forwarded-Method` |
| Host | `X-Forwarded-Host` |
| Client IP | `X-Forwarded-For` (via `trusted_proxies`) |

Henbane trusts **only** these canonical `X-Forwarded-*` names (not `X-Original-*`
aliases). Your front proxy **must overwrite** them — nginx `proxy_set_header` and
Traefik's `forwardAuth` both do — so a client cannot forge a value the proxy
didn't set. A forwarded URI that is present but unparseable is rejected (fail
closed), never evaluated as the auth endpoint's own path.

## Security

- **Bind the sidecar to your internal network** (e.g. `listen: "127.0.0.1:8080"`
  or a private interface). Only the front proxy should reach it — these forwarded
  headers are authoritative only because the proxy sets them; a client that could
  reach the sidecar directly, **or** a proxy that forwards rather than overwrites
  `X-Forwarded-Uri`, could forge the request path and bypass path-based rules
  (honeypot, path denylists). Both recipes below overwrite it.
- Set `trusted_proxies` to the front proxy's address so the real client IP is
  taken from `X-Forwarded-For` rather than the proxy's own IP.

## Traefik

Traefik's `forwardAuth` returns a non-`2xx` auth response (status **and body**)
straight to the client, so the challenge and maze render with no extra config.

```yaml
# dynamic configuration
http:
  middlewares:
    henbane:
      forwardAuth:
        address: "http://henbane:8080/auth"
        # copy the action onto the upstream request when allowed (optional)
        authResponseHeaders: ["X-Henbane-Action"]

  routers:
    site:
      rule: "Host(`example.com`)"
      middlewares: ["henbane"]
      service: backend
```

The proof-of-work solution endpoint must reach Henbane directly (not through the
auth middleware), so it can set the session cookie. Add a higher-priority router:

```yaml
  routers:
    henbane-verify:
      rule: "Host(`example.com`) && PathPrefix(`/.well-known/henbane/`)"
      priority: 100
      service: henbane
  services:
    henbane:
      loadBalancer:
        servers: [{ url: "http://henbane:8080" }]
```

## nginx

nginx `auth_request` reads only the **status** of the auth subrequest, so the
deny *body* (challenge/maze) is surfaced with an `error_page` that re-proxies the
same request to Henbane.

```nginx
upstream henbane { server 127.0.0.1:8080; }

server {
    listen 443 ssl;
    server_name example.com;

    location / {
        auth_request /henbane_auth;
        error_page 401 403 = @henbane_deny;   # serve Henbane's body, not the backend
        proxy_pass http://backend;
    }

    # Internal auth subrequest — forwards the original request's identity.
    # proxy_set_header OVERWRITES any client-supplied value, so a client cannot
    # forge X-Forwarded-Uri to make the engine evaluate a different (allowed) path.
    location = /henbane_auth {
        internal;
        proxy_pass http://henbane/auth;
        proxy_pass_request_body off;
        proxy_set_header Content-Length "";
        proxy_set_header X-Forwarded-Uri    $request_uri;
        proxy_set_header X-Forwarded-Method $request_method;
        proxy_set_header X-Forwarded-Host   $host;
        proxy_set_header X-Forwarded-For    $proxy_add_x_forwarded_for;
    }

    # On a deny, fetch the challenge/maze/403 body from Henbane.
    location @henbane_deny {
        proxy_pass http://henbane/auth;
        proxy_set_header X-Forwarded-Uri    $request_uri;
        proxy_set_header X-Forwarded-Method $request_method;
        proxy_set_header X-Forwarded-Host   $host;
        proxy_set_header X-Forwarded-For    $proxy_add_x_forwarded_for;
    }

    # Proof-of-work solution endpoint — straight to Henbane so it can set the cookie.
    location = /.well-known/henbane/verify {
        proxy_pass http://henbane/.well-known/henbane/verify;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
    }
}
```

## What works, and the one caveat

- **Allow / block** work exactly as in reverse-proxy mode.
- **Proof-of-work** works: the challenge is served on the deny, the solver posts
  to the verify path (routed above), and the `hb_pow` cookie round-trips through
  the front proxy on later requests, which the auth check then passes.
- **Tarpit / poison**: the maze and poison are served as the deny body. Because a
  `2xx` auth response means "allow" to the front proxy, the maze cannot be served
  with a `200` here — it is delivered with the deny status. If you want the maze
  served as a normal `200` page (and to meter bytes-into-tarpit precisely), run
  Henbane as the reverse proxy or Caddy module instead; the sidecar is first and
  foremost an authorization gate for infrastructure you already run.
