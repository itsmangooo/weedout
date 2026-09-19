# Architecture

The dependency direction is one-way:

```text
public model
  ↑
manifest parsers   advisory sources   reachability   rules   matching
  \________________________  _____________________________/
                           scanner
                              ↑
                    library or HTTP adapter
```

`scanner.Scanner` is orchestration, not storage. A caller supplies a parser
registry, advisory source, and rules engine. The scanner returns a canonical
result and retains nothing between calls.

The Weedout deployment uses the web application as the public authenticated
boundary. Web loads project data and advisory records, calls the engine over a
private network, and stores selected result/history data. The engine never
receives an account or product project ID unless the caller uses an opaque
`request_id` for tracing.

## Adding an ecosystem

1. Implement `manifest.Parser` in a package owned by that ecosystem.
2. Return only normalized `model.Dependency` records.
3. Add parser fixtures for direct, transitive, development, malformed, and
   lockfile cases.
4. Register it with `manifest.Registry` in the consuming binary.

No switch statement in scanner or rules needs editing.

## Adding an advisory provider

Implement `advisory.Source`. Query only by normalized ecosystem/name and return
`model.Advisory`. Providers own caching, mirror schema, freshness, and network
policy; the matching package owns affected-version evaluation.

## Adding rules

Implement `rules.Rule` for an additional deterministic policy, or replace
`rules.Engine` for a complete policy. Every decision must name the rule,
outcome, and explanation. Avoid clocks, network calls, and mutable global state
inside rules so identical inputs remain identical.
