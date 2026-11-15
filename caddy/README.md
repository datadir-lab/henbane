# Henbane Caddy plugin

A [Caddy v2](https://caddyserver.com) HTTP handler module that runs the
[Henbane](https://github.com/datadir-lab/henbane) anti-AI-scraper gateway in
front of your site.

This is a **separate Go module** (`caddy/go.mod`) on purpose: Caddy's dependency
tree is large, and Henbane's core is zero-dependency by policy. Keeping the
plugin in its own module means importing Henbane as a library never pulls in
Caddy, and building the plugin never compromises the core's dependency guarantee.

## Build

```bash
xcaddy build --with github.com/datadir-lab/henbane/caddy
```

Until the core has its first tagged release, the plugin depends on the parent
module via a local `replace`, so build it against a checkout of this repo:

```bash
git clone https://github.com/datadir-lab/henbane
xcaddy build --with github.com/datadir-lab/henbane/caddy=./henbane/caddy
```

## Use

```caddyfile
example.com {
    henbane /etc/henbane.yaml   # same YAML the standalone binary reads
    reverse_proxy localhost:8081
}
```

Or with an explicit block:

```caddyfile
henbane {
    config_file /etc/henbane.yaml
}
```

Requests Henbane allows continue down the Caddy handler chain; suspect,
confirmed, and blocked requests are challenged, tarpitted, or blocked by Henbane
first. With no config file the directive is passive (every posture off).

See the [main README](../README.md) for the configuration reference.

## Status

v0 / experimental, tracking the `github.com/datadir-lab/henbane` package. The
config file is the full feature surface today, including federation (its
background tasks start in `Provision` and stop on reload/shutdown). Decision-log
bridging into Caddy's logger and a metrics route are future work.
