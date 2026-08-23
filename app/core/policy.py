"""`.weedout.yml` — scan rules that live in the repository they describe.

The point of a policy file rather than a settings page is that a rule about a
codebase belongs beside the codebase: it goes through review, it moves with a
branch, and `git log` answers "who silenced this and when" without a separate
audit trail. So when both exist, the file wins.

Two rules shape the parsing, and both point the same way.

**A broken policy file can only ever make Weedout noisier.** If parsing fails
the file is discarded and the scan runs on the defaults, which means every
ignore in it stops applying and every raised threshold reverts. The failure
mode is extra alerts, never silence. A parser that failed the other way could
turn a typo into a vulnerability nobody hears about.

**An ignore needs a reason.** Not because the reason is validated -- it cannot
be -- but because writing one down is the difference between a decision and a
reflex, and because six months later the reason is the only thing that makes
the entry reviewable. An ignore without one is refused.

`yaml.safe_load` and never `yaml.load`: the input is a file from somebody's
repository, and full-fat YAML can construct arbitrary Python objects.
"""

from __future__ import annotations

from dataclasses import dataclass, field

import yaml

from app.core.types import IgnoreKind, Severity

__all__ = [
    "MATCHES_EVERYTHING",
    "MAX_PATTERN_LENGTH",
    "MAX_POLICY_BYTES",
    "IgnoreEntry",
    "ParsedPolicy",
    "parse_policy",
]

#: A policy file is a short document. Anything larger is a mistake or an
#: attempt to make the parser work hard, and refusing early costs nothing.
MAX_POLICY_BYTES = 64 * 1024

#: What a severity threshold may be set to. `unknown` is deliberately absent:
#: it is what an advisory gets when nobody scored it, not a level to gate on.
_THRESHOLDS = {
    "low": Severity.LOW,
    "medium": Severity.MEDIUM,
    "high": Severity.HIGH,
    "critical": Severity.CRITICAL,
}


#: A pattern that matches every package name is not an ignore rule, it is the
#: product switched off, and a project is switched off by deactivating it. The
#: distinction matters because these two are silent in different ways: a
#: deactivated project says so on the dashboard, and a rule that happens to
#: match everything does not.
MATCHES_EVERYTHING = {"*", "**", "?*", "*?"}

#: Long enough for the longest real package name (npm caps at 214) plus glob
#: syntax around it. Anything past that is not a package name.
MAX_PATTERN_LENGTH = 256


@dataclass(frozen=True, slots=True)
class IgnoreEntry:
    """One thing this project has chosen not to hear about.

    `identifier` is an advisory id or a package-name glob depending on `kind`.
    Two shapes rather than two classes because everything downstream of here --
    the reason requirement, the audit trail, the Filtered tab -- treats them
    identically, and the only difference is what they are matched against.
    """

    identifier: str
    reason: str
    kind: IgnoreKind = IgnoreKind.ADVISORY


@dataclass(slots=True)
class ParsedPolicy:
    """What a `.weedout.yml` asked for, plus anything wrong with it.

    `warnings` is not an error channel. A policy file that mentions a key this
    version does not know about is a policy file written for a later version,
    and refusing it would break a repository on every upgrade. It is reported
    so the author can see it was skipped rather than honoured.
    """

    direct_threshold: Severity | None = None
    transitive_threshold: Severity | None = None
    #: Severity floor for dependencies that never ship. See
    #: `MatchPolicy.dev_threshold`.
    dev_threshold: Severity | None = None
    #: Probability at or above which to alert, 0.0 to 1.0. None gates nothing.
    epss_threshold: float | None = None
    ignores: tuple[IgnoreEntry, ...] = ()
    #: A named rule profile this repository asks for. Resolved server-side
    #: against the account's own profiles, so this is a request rather than a
    #: rule -- see `profile_service.profile_for_scan`.
    profile: str | None = None
    warnings: tuple[str, ...] = field(default_factory=tuple)
    #: Set when the document could not be used at all. The scan continues on
    #: defaults and says so.
    error: str | None = None

    @property
    def is_empty(self) -> bool:
        return (
            self.direct_threshold is None
            and self.transitive_threshold is None
            and self.dev_threshold is None
            and self.epss_threshold is None
            and self.profile is None
            and not self.ignores
        )

    @property
    def ignored_ids(self) -> tuple[str, ...]:
        return tuple(
            entry.identifier for entry in self.ignores if entry.kind is IgnoreKind.ADVISORY
        )

    @property
    def ignored_packages(self) -> tuple[str, ...]:
        return tuple(entry.identifier for entry in self.ignores if entry.kind is IgnoreKind.PACKAGE)


def parse_policy(content: str | bytes | None) -> ParsedPolicy:
    """Read a policy document. Never raises."""
    if content is None:
        return ParsedPolicy()

    if isinstance(content, bytes):
        if len(content) > MAX_POLICY_BYTES:
            return ParsedPolicy(error="The policy file is too large to read.")
        try:
            content = content.decode("utf-8")
        except UnicodeDecodeError:
            return ParsedPolicy(error="The policy file is not valid UTF-8.")

    if len(content) > MAX_POLICY_BYTES:
        return ParsedPolicy(error="The policy file is too large to read.")

    if not content.strip():
        return ParsedPolicy()

    try:
        # safe_load, always. This is a file out of somebody's repository, and
        # yaml.load on untrusted input constructs arbitrary Python objects.
        document = yaml.safe_load(content)
    except yaml.YAMLError as exc:
        return ParsedPolicy(error=f"The policy file is not valid YAML: {_first_line(exc)}")

    if document is None:
        return ParsedPolicy()

    if not isinstance(document, dict):
        return ParsedPolicy(error="The policy file should be a mapping of settings.")

    warnings: list[str] = []
    known = {"version", "severity", "ignore", "epss", "profile"}
    for key in document:
        if key not in known:
            warnings.append(f"Ignoring unknown setting {key!r}.")

    direct, transitive, dev, severity_warnings = _read_severity(document.get("severity"))
    warnings.extend(severity_warnings)

    ignores, ignore_warnings = _read_ignores(document.get("ignore"))
    warnings.extend(ignore_warnings)

    epss, epss_warnings = _read_epss(document.get("epss"))
    warnings.extend(epss_warnings)

    profile, profile_warnings = _read_profile(document.get("profile"))
    warnings.extend(profile_warnings)

    return ParsedPolicy(
        direct_threshold=direct,
        transitive_threshold=transitive,
        dev_threshold=dev,
        epss_threshold=epss,
        ignores=tuple(ignores),
        profile=profile,
        warnings=tuple(warnings),
    )


def _read_profile(value: object) -> tuple[str | None, list[str]]:
    """`profile: production` -- which of the account's rule profiles to use.

    A name, not a rule. Nothing here checks that it exists, because this parser
    knows nothing about accounts; resolution happens server-side, where a name
    that does not resolve is an error rather than a silent fall back to the
    defaults.
    """
    if value is None:
        return None, []
    if not isinstance(value, str) or not value.strip():
        return None, ["`profile` should be the name of a rule profile; ignoring it."]
    return value.strip()[:80], []


def _read_epss(block: object) -> tuple[float | None, list[str]]:
    """`epss: {alert_above: 0.5}` -- a probability, not a percentage.

    Both spellings of the same number are plausible to write, so a value above
    1 is read as a percentage rather than silently clamped: somebody writing
    `alert_above: 50` means half, and treating that as "always alert" would be
    the loudest possible misreading.
    """
    if block is None:
        return None, []
    if not isinstance(block, dict):
        return None, ["`epss` should be a mapping; ignoring it."]

    warnings = [f"Ignoring unknown epss setting {key!r}." for key in block if key != "alert_above"]

    raw = block.get("alert_above")
    if raw is None:
        return None, warnings
    if isinstance(raw, bool) or not isinstance(raw, int | float):
        return None, [*warnings, "`epss.alert_above` should be a number; ignoring it."]

    value = float(raw)
    if value > 1.0:
        value = value / 100.0
    if not (0.0 < value <= 1.0):
        return None, [*warnings, "`epss.alert_above` should be between 0 and 1; ignoring it."]

    return value, warnings


#: The severity floors a policy file may set, and the reachability each one
#: governs. `dev` is the odd one: leaving it unset does not mean "default", it
#: means the coarse on/off switch decides — see `MatchPolicy.dev_threshold`.
_SEVERITY_KEYS = ("direct", "transitive", "dev")


def _read_severity(
    block: object,
) -> tuple[Severity | None, Severity | None, Severity | None, list[str]]:
    if block is None:
        return None, None, None, []
    if not isinstance(block, dict):
        return None, None, None, ["`severity` should be a mapping; ignoring it."]

    warnings: list[str] = []
    out: dict[str, Severity | None] = dict.fromkeys(_SEVERITY_KEYS)

    for key in _SEVERITY_KEYS:
        raw = block.get(key)
        if raw is None:
            continue
        if not isinstance(raw, str) or raw.strip().lower() not in _THRESHOLDS:
            allowed = ", ".join(_THRESHOLDS)
            warnings.append(f"`severity.{key}` should be one of {allowed}; ignoring it.")
            continue
        out[key] = _THRESHOLDS[raw.strip().lower()]

    for key in block:
        if key not in _SEVERITY_KEYS:
            warnings.append(f"Ignoring unknown severity setting {key!r}.")

    return out["direct"], out["transitive"], out["dev"], warnings


def _read_ignores(block: object) -> tuple[list[IgnoreEntry], list[str]]:
    if block is None:
        return [], []
    if not isinstance(block, list):
        return [], ["`ignore` should be a list; ignoring it."]

    entries: list[IgnoreEntry] = []
    warnings: list[str] = []
    seen: set[tuple[IgnoreKind, str]] = set()

    for index, raw in enumerate(block):
        position = f"ignore[{index}]"

        if not isinstance(raw, dict):
            warnings.append(
                f"{position} should be a mapping with `cve` or `package`, and `reason`; skipped."
            )
            continue

        parsed = _read_one_ignore(position, raw)
        if isinstance(parsed, str):
            warnings.append(parsed)
            continue

        key = (parsed.kind, parsed.identifier)
        if key in seen:
            warnings.append(f"{parsed.identifier} is listed more than once; using the first entry.")
            continue

        seen.add(key)
        entries.append(parsed)

    return entries, warnings


def _read_one_ignore(position: str, raw: dict) -> IgnoreEntry | str:
    """One entry, or the warning explaining why it was skipped."""
    advisory = raw.get("cve") or raw.get("id")
    package = raw.get("package")

    if advisory and package:
        # Two subjects in one entry has no single reading, and guessing which
        # one was meant would silence something the author did not ask to
        # silence.
        return f"{position} sets both `cve` and `package`; write them as two entries. Skipped."

    if package is not None:
        identifier, problem = _read_package_pattern(position, package)
    else:
        identifier, problem = _read_advisory_id(position, advisory)
    if problem is not None:
        return problem

    reason = raw.get("reason")
    if not isinstance(reason, str) or not reason.strip():
        # Required, and the refusal is the feature. An ignore with no reason is
        # unreviewable six months later, and the person who wrote it is the
        # only one who can supply it.
        return (
            f"{position} ({identifier}) has no `reason`, so it was skipped. Every ignore needs one."
        )

    kind = IgnoreKind.PACKAGE if package is not None else IgnoreKind.ADVISORY
    return IgnoreEntry(identifier=identifier, reason=reason.strip()[:500], kind=kind)


def _read_advisory_id(position: str, value: object) -> tuple[str, str | None]:
    if not isinstance(value, str) or not value.strip():
        return "", f"{position} has no `cve` or `package`; skipped."
    return value.strip().upper(), None


def _read_package_pattern(position: str, value: object) -> tuple[str, str | None]:
    """A glob over dependency names.

    Not upper-cased, unlike an advisory id: matching is case-insensitive
    anyway, and keeping the stored form close to what was written makes the
    rule readable where it is listed back.
    """
    if not isinstance(value, str) or not value.strip():
        return "", f"{position} has an empty `package`; skipped."

    pattern = value.strip().lower()

    if len(pattern) > MAX_PATTERN_LENGTH:
        return "", f"{position} has a `package` pattern that is too long; skipped."

    if pattern in MATCHES_EVERYTHING:
        return "", (
            f"{position} would ignore every package, which turns the scan off rather than "
            "filtering it. Deactivate the project instead. Skipped."
        )

    return pattern, None


def _first_line(exc: Exception) -> str:
    """YAML errors are several lines of context. The first is the useful one."""
    return str(exc).splitlines()[0][:200] if str(exc) else exc.__class__.__name__
