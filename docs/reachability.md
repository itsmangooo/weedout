# What "reachable" means in Weedout

Weedout claims to alert on vulnerabilities that are *reachable*. That word is
overloaded in the security industry, and vendors use it to mean things they
cannot actually determine. This document states exactly what Weedout means by
it, so nobody has to infer the definition from behaviour.

## What Weedout does not do

**It does not analyse your source code.** It never determines whether you call
the vulnerable function, whether the vulnerable code path is reachable from your
entry points, or whether the vulnerable feature is one you use. Doing that
requires call-graph analysis of your application, which is a different product.

If a tool tells you "this CVE is not reachable because you never call
`parseUrl()`", that tool is doing something Weedout does not do. Weedout
will never make that claim.

## What Weedout does determine

Weedout reads dependency manifests. From a manifest it can establish two facts,
and both meaningfully reduce noise:

### 1. Does this package ship to production?

A dependency declared in `devDependencies` is used to build and test your
project. It is not part of your deployed application, so an attacker interacting
with your running service has no path to it.

| Manifest | Ships to production | Dev only |
|---|---|---|
| `package.json` | `dependencies`, `peerDependencies`, `optionalDependencies` | `devDependencies` |
| `package-lock.json` | entries without `"dev": true` | entries with `"dev": true` |
| `requirements.txt` | everything (the format has no dev/prod split) | — |
| `go.mod` | everything | — |

This is the single highest-yield filter. Build tooling — webpack, jest, eslint,
their transitive trees — accounts for a large share of advisories in a typical
npm project, and essentially none of it is exposed in production.

Note the honest limitation: `requirements.txt` and `go.mod` carry no dev/prod
distinction, so everything in them is treated as shipping. Splitting your Python
dev tooling into a separate `requirements-dev.txt` that you simply do not upload
is the way to get the same benefit there.

### 2. Did you declare it, or did something else pull it in?

A **direct** dependency is one your project names itself. You can upgrade it
today by editing one line.

A **transitive** dependency arrived because something else depends on it.
Upgrading it usually means waiting for the intermediate package to bump its own
constraint, or forcing an override. The advisory is equally true, but it is far
less actionable, and it arrives in far greater volume.

Weedout distinguishes these from `package-lock.json` (the root entry's
`dependencies` list versus everything else) and from `go.mod` (`// indirect`
comments). A bare `package.json` lists only direct dependencies.

## The resulting policy

A finding is surfaced when any of these holds:

1. **The CVE is in CISA's Known Exploited Vulnerabilities catalog.** This
   overrides everything, including dev-only scope. KEV is a published,
   evidence-backed list of vulnerabilities with observed exploitation. If
   someone has a working exploit, "it only runs in CI" is thin comfort.
2. **Critical severity in a package that ships to production**, direct or
   transitive.
3. **High severity in a direct dependency that ships to production.**

Everything else is recorded as suppressed, with the reason attached, and shown
on the Filtered tab. Nothing is discarded.

The thresholds live in `MatchPolicy` in `app/core/matching.py` and are data, not
branches, so they can be varied per user or per plan later without rewriting the
decision logic.

## Version accuracy

There is a second honesty problem, separate from reachability: **a manifest
range is not an installed version.**

If your `package.json` says `"lodash": "^4.17.4"`, the installed version could be
anything from 4.17.4 to 4.17.21. Weedout resolves the range to the *lowest*
version it permits — the conservative floor — and marks the resulting finding
`version_exact = false`. The UI then says so on every affected finding:

> Your manifest requests `^4.17.4`, which does not pin an exact version.
> Weedout assumed the lowest version that range allows (4.17.4). Upload your
> lockfile for an exact answer — the version you actually have installed may
> already be patched.

Guessing high would hide real vulnerabilities. Guessing low without saying so
would produce confident-looking alerts about versions the user does not have.
Guessing low and labelling it is the only option that is both safe and truthful.

**Upload a lockfile when you can.** `package-lock.json` and `go.mod` state exact
installed versions, and findings derived from them carry no such caveat.

## Why this is worth stating

The premise of this product is that most advisories touching your dependency
tree will never be exploited against you, and that a tool reporting all of them
trains you to ignore it. That argument only works if you can check the tool's
reasoning. Every suppressed finding is therefore kept, counted, and browsable
with its reason — and the definition of every term used in that reason is here.
