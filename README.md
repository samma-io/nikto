# Samma scanner: Nikto

![Samma-io](assets/samma_logo.png)

[Nikto](https://cirt.net/Nikto2) wrapped as a Samma scanner. It is one of the open-source scanners
that the [Samma operator](https://github.com/samma-io/operator) runs in your Kubernetes cluster,
against the hosts in your annotated Ingresses. Every finding goes to Grafana in that same cluster.

## What it checks

Nikto is a web server scanner. It probes for the kind of issues in the OWASP Top 10 that you can
see from outside:

- dangerous files and programs left on the server
- outdated server software and version-specific problems
- server misconfiguration, such as default files, directory indexing and risky HTTP methods
- missing or weak security headers

**Use it for** OWASP-style findings on websites and APIs. Nikto sends real probe requests and is
noisy in logs and WAFs. Only point it at hosts you are allowed to test.

## Run it locally

```sh
docker build -t samma-nikto .
docker run --rm -e TARGET=example.com -e PORT=443 samma-nikto
```

Findings are printed to stdout.

## Settings

All settings are environment variables:

| Variable | Default | Description |
|---|---|---|
| `TARGET` | **required** | Host to scan |
| `PORT` | `443` | Port to scan |
| `TUNING` | — | Nikto `-Tuning` value to limit the test types, e.g. `23` (see `nikto -H`) |
| `SAMMA_IO_SCANNER` | `nikto` | Scanner label on every finding |
| `SAMMA_IO_ID` | `1234` | Id added to every finding |
| `SAMMA_IO_TAGS` | `scanner` | Comma-separated tags added to every finding |
| `SAMMA_IO_JSON` | `{}` | Extra JSON added to every finding |
| `TARGET_ID` | — | samma.io target id, so findings show on that target |
| `WRITE_TO_FILE` | `False` | `true` writes findings to `/out/<PARSER>.json` |
| `PARSER` | `nikto` | Output file name |
| `NATS_ENABLED` | `False` | `true` publishes every finding to NATS |
| `NATS_URL` | `nats://localhost:4222` | NATS server |
| `NATS_SUBJECT` | `scans` | NATS subject (the operator uses `samma-io.scan`) |

## In Kubernetes

Don't deploy this image by hand. Install the [Samma operator](https://github.com/samma-io/operator)
and pick a profile that includes Nikto (`web`, `classic`, `default` or `all`) on an Ingress:

```yaml
metadata:
  annotations:
    samma-io.alpha.kubernetes.io/enable: "true"
    samma-io.alpha.kubernetes.io/profile: "web"
```

The operator runs the scan once straight away and then weekly. When you delete the Ingress, the
scanners are removed. Findings flow through NATS and TimescaleDB to Grafana. The
[Samma guide](https://github.com/samma-io/guide) covers the whole setup.
