# Weedout Detection Engine

The engine is a deterministic dependency vulnerability detector. It is an
independent Go module and service: it knows manifests, dependency graphs,
advisories, affected versions, reachability evidence, rules, findings, and
explanations. It does not know users, projects, sessions, billing, dashboards,
or the Weedout product database.

## Run it

```bash
go test ./...
go run ./cmd/weedout-engine
curl http://localhost:8080/healthz
```

Or as a container:

```bash
docker build -t weedout-engine ./engine
docker run --rm -p 8080:8080 weedout-engine
```

The process is stateless. `ENGINE_ADDR` controls the listener (default
`:8080`). `ENGINE_ADVISORY_FILE` can point at a normalized JSON advisory array
for an offline/local mirror. `ENGINE_DATABASE_URL` activates the PostgreSQL
mirror provider used by Weedout production; it queries only `vulnerabilities`,
`vulnerability_affected`, `kev_entries`, and `epss_scores`. Production
deployments should keep port 8080 on an internal network;
the Weedout web application is the authenticated public boundary.

## Public API

`POST /v1/scan` accepts the public `model.ScanRequest` and returns
`model.ScanResult`. `GET /healthz` is the liveness endpoint, `GET /readyz`
checks the configured advisory provider, and `GET /version`
reports build and schema versions. The request can carry inline normalized
advisories; deployments can instead inject any implementation of
`advisory.Source`, such as an OSV mirror or company advisory store.

```json
{
  "schema_version": "v1",
  "manifests": [{
    "path": "requirements.txt",
    "content": "Django==4.2.0"
  }],
  "rules": {"direct_threshold": "high"},
  "advisories": {"provider": "inline", "inline": []}
}
```

Results contain a normalized dependency graph and findings with the matched
advisory, affected-range reason, fixed version, KEV and EPSS data, source
evidence, every rule decision, final verdict, remediation, and explanation.
The response is stable under schema version `v1`; incompatible changes require
a new model and endpoint version.

## Go library

```go
engine := scanner.Scanner{
    Parsers: builtin.Registry(),
    Advisories: myAdvisorySource,
    Rules: myRuleEngine,
}
result, err := engine.Scan(ctx, request)
```

The HTTP service calls this same method. There is no second scan implementation.

## Extension points

- `manifest.Parser`: detect and parse a manifest into a normalized graph.
- `advisory.Source`: resolve normalized advisories for package queries.
- `rules.Engine` and `rules.Rule`: evaluate deterministic policy.
- `model.*`: public consumer-safe models with no ORM types.

Registering another ecosystem requires a parser implementation and registry
registration. Matching, rules, API, and consumers do not change. Advisory
providers normalize their records into `model.Advisory`; matching never
depends on an OSV database schema.

Built-in parsers cover package.json, package-lock.json, requirements files,
go.mod, Cargo.lock, pom.xml, Gradle lockfiles, and build.sbt.lock. Parser parity
is intentionally fixture-driven because several declaration formats provide a
range rather than an installed version.

## Parity

`testdata/parity` is the shared contract corpus. Go tests run requests through
the new engine. `parity/python_reference.py` runs the same fixtures through the
legacy pure Python core. The corpus currently covers every supported ecosystem
(npm, PyPI, Go, crates.io, and Maven) plus Cargo dependency depth, Maven
properties and managed versions, Gradle/sbt development scopes, KEV, EPSS,
ignored findings, source reachability, fixed versions, and severity policy.
Add fixtures for further parser and version edge cases before retiring the
Python detector.

```bash
go test ./...
python ../.venv/Scripts/python.exe parity/python_reference.py
```

## Building another product

See `examples/` for library, custom CLI, CI gate, HTTP backend, and IDE client
examples. They consume only the public engine contract and do not depend on
the Weedout web application.
