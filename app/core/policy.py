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

from app.core.types import Severity

__all__ = [
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


@dataclass(frozen=True, slots=True)
class IgnoreEntry:
    """One advisory this project has chosen not to hear about."""

    identifier: str
    reason: str


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
    ignores: tuple[IgnoreEntry, ...] = ()
    warnings: tuple[str, ...] = field(default_factory=tuple)
    #: Set when the document could not be used at all. The scan continues on
    #: defaults and says so.
    error: str | None = None

    @property
    def is_empty(self) -> bool:
        return (
            self.direct_threshold is None and self.transitive_threshold is None and not self.ignores
        )

    @property
    def ignored_ids(self) -> tuple[str, ...]:
        return tuple(entry.identifier for entry in self.ignores)


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
    known = {"version", "severity", "ignore"}
    for key in document:
        if key not in known:
            warnings.append(f"Ignoring unknown setting {key!r}.")

    direct, transitive, severity_warnings = _read_severity(document.get("severity"))
    warnings.extend(severity_warnings)

    ignores, ignore_warnings = _read_ignores(document.get("ignore"))
    warnings.extend(ignore_warnings)

    return ParsedPolicy(
        direct_threshold=direct,
        transitive_threshold=transitive,
        ignores=tuple(ignores),
        warnings=tuple(warnings),
    )


def _read_severity(block: object) -> tuple[Severity | None, Severity | None, list[str]]:
    if block is None:
        return None, None, []
    if not isinstance(block, dict):
        return None, None, ["`severity` should be a mapping; ignoring it."]

    warnings: list[str] = []
    out: dict[str, Severity | None] = {"direct": None, "transitive": None}

    for key in ("direct", "transitive"):
        raw = block.get(key)
        if raw is None:
            continue
        if not isinstance(raw, str) or raw.strip().lower() not in _THRESHOLDS:
            allowed = ", ".join(_THRESHOLDS)
            warnings.append(f"`severity.{key}` should be one of {allowed}; ignoring it.")
            continue
        out[key] = _THRESHOLDS[raw.strip().lower()]

    for key in block:
        if key not in ("direct", "transitive"):
            warnings.append(f"Ignoring unknown severity setting {key!r}.")

    return out["direct"], out["transitive"], warnings


def _read_ignores(block: object) -> tuple[list[IgnoreEntry], list[str]]:
    if block is None:
        return [], []
    if not isinstance(block, list):
        return [], ["`ignore` should be a list; ignoring it."]

    entries: list[IgnoreEntry] = []
    warnings: list[str] = []
    seen: set[str] = set()

    for index, raw in enumerate(block):
        position = f"ignore[{index}]"

        if not isinstance(raw, dict):
            warnings.append(f"{position} should be a mapping with `cve` and `reason`; skipped.")
            continue

        identifier = raw.get("cve") or raw.get("id")
        if not isinstance(identifier, str) or not identifier.strip():
            warnings.append(f"{position} has no `cve`; skipped.")
            continue
        identifier = identifier.strip().upper()

        reason = raw.get("reason")
        if not isinstance(reason, str) or not reason.strip():
            # Required, and the refusal is the feature. An ignore with no
            # reason is unreviewable six months later, and the person who
            # wrote it is the only one who can supply it.
            warnings.append(
                f"{position} ({identifier}) has no `reason`, so it was skipped. "
                "Every ignore needs one."
            )
            continue

        if identifier in seen:
            warnings.append(f"{identifier} is listed more than once; using the first entry.")
            continue

        seen.add(identifier)
        entries.append(IgnoreEntry(identifier=identifier, reason=reason.strip()[:500]))

    return entries, warnings


def _first_line(exc: Exception) -> str:
    """YAML errors are several lines of context. The first is the useful one."""
    return str(exc).splitlines()[0][:200] if str(exc) else exc.__class__.__name__
