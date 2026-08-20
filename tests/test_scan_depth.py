"""How deep a scan looks, and who gets how deep.

The property that matters is that the limit is *enforced*, not merely
advertised: a Free project must not return a finding that only exists three
levels down, even though the parser found the package and the mirror holds the
advisory. A pricing page claiming a difference the pipeline does not make is
worse than not claiming it.

The second property is that skipping is not the same as filtering. A package
out of the plan's reach was never looked up, and reporting it as "filtered as
noise" would claim work that did not happen -- the same rule that makes CLI
exit code 2 distinct from 1.
"""

from __future__ import annotations

import json
from dataclasses import replace

import pytest

from app.core.manifests import parse_manifest
from app.core.matching import DEFAULT_POLICY, triage_all
from app.core.types import (
    AffectedPackage,
    AffectedRange,
    Dependency,
    Ecosystem,
    ManifestKind,
    Reachability,
    Severity,
    Tier,
    Vulnerability,
)
from app.tiers import depth_label, scan_depth_for


def dep(name: str, depth: int, via: tuple[str, ...] = ()) -> Dependency:
    return Dependency(
        ecosystem=Ecosystem.NPM,
        name=name,
        version="1.0.0",
        version_spec="1.0.0",
        reachability=(
            Reachability.RUNTIME_DIRECT if depth == 0 else Reachability.RUNTIME_TRANSITIVE
        ),
        depth=depth,
        via=via,
    )


def critical(name: str) -> Vulnerability:
    """A critical advisory that genuinely matches 1.0.0.

    `affected` has to be real: with an empty tuple the triage decides
    NOT_AFFECTED and the test would pass for the wrong reason -- nothing
    reaching the actionable list because nothing matched, rather than because
    the depth limit stopped it.
    """
    return Vulnerability(
        id=f"GHSA-{name}",
        aliases=(f"CVE-2099-{name}",),
        summary=f"{name} is broken",
        severity=Severity.CRITICAL,
        affected=(
            AffectedPackage(
                ecosystem=Ecosystem.NPM,
                name=name,
                ranges=(AffectedRange(introduced="0", fixed="2.0.0"),),
            ),
        ),
    )


class TestTheParserRecordsTheRoute:
    def test_a_hoisted_package_gets_its_real_depth(self):
        """npm v2 and v3 lockfiles hoist.

        `qs` sits at `node_modules/qs`, which looks direct, but nothing depends
        on it except through express. Reading depth off the path would call it
        a direct dependency; walking the graph gets it right.
        """
        lock = {
            "lockfileVersion": 3,
            "packages": {
                "": {"name": "demo", "dependencies": {"express": "^4"}},
                "node_modules/express": {
                    "version": "4.18.2",
                    "dependencies": {"body-parser": "1.20.1"},
                },
                "node_modules/body-parser": {
                    "version": "1.20.1",
                    "dependencies": {"qs": "6.11.0"},
                },
                "node_modules/qs": {"version": "6.11.0"},
            },
        }
        parsed = parse_manifest(ManifestKind.PACKAGE_LOCK_JSON, json.dumps(lock))
        by_name = {d.name: d for d in parsed.dependencies}

        assert by_name["express"].depth == 0
        assert by_name["body-parser"].depth == 1
        assert by_name["qs"].depth == 2
        assert by_name["qs"].via == ("express", "body-parser")
        assert by_name["qs"].chain_label == "express → body-parser → qs"

    def test_a_dependency_cycle_terminates(self):
        """a depends on b depends on a. Without a visited set this recurses
        until the stack gives out, and a malformed lockfile becomes an outage."""
        lock = {
            "lockfileVersion": 3,
            "packages": {
                "": {"name": "demo", "dependencies": {"a": "1"}},
                "node_modules/a": {"version": "1.0.0", "dependencies": {"b": "1"}},
                "node_modules/b": {"version": "1.0.0", "dependencies": {"a": "1"}},
            },
        }
        parsed = parse_manifest(ManifestKind.PACKAGE_LOCK_JSON, json.dumps(lock))
        depths = {d.name: d.depth for d in parsed.dependencies}
        assert depths == {"a": 0, "b": 1}

    def test_a_v1_lockfile_takes_the_chain_from_its_nesting(self):
        lock = {
            "lockfileVersion": 1,
            "dependencies": {
                "express": {
                    "version": "4.18.2",
                    "dependencies": {
                        "body-parser": {
                            "version": "1.20.1",
                            "dependencies": {"qs": {"version": "6.11.0"}},
                        }
                    },
                }
            },
        }
        parsed = parse_manifest(ManifestKind.PACKAGE_LOCK_JSON, json.dumps(lock))
        by_name = {d.name: d for d in parsed.dependencies}
        assert by_name["qs"].depth == 2
        assert by_name["qs"].via == ("express", "body-parser")

    def test_a_direct_dependency_has_an_empty_chain(self):
        parsed = parse_manifest(
            ManifestKind.PACKAGE_JSON, json.dumps({"dependencies": {"lodash": "4.17.21"}})
        )
        only = parsed.dependencies[0]
        assert only.depth == 0
        assert only.via == ()
        assert only.chain_label == "lodash"

    def test_go_indirect_modules_are_at_least_one_hop_away(self):
        """go.mod flattens. `// indirect` says "not required directly" without
        saying by what, so depth 1 is the honest floor rather than a guess."""
        parsed = parse_manifest(
            ManifestKind.GO_MOD,
            "module example.com/demo\ngo 1.22\n"
            "require (\n"
            "\tgithub.com/gin-gonic/gin v1.9.1\n"
            "\tgolang.org/x/sys v0.10.0 // indirect\n"
            ")\n",
        )
        depths = {d.name.rsplit("/", 1)[-1]: d.depth for d in parsed.dependencies}
        assert depths == {"gin": 0, "sys": 1}


class TestTheLimitIsEnforced:
    def _scan(self, max_depth):
        deps = [
            dep("direct", 0),
            dep("first", 1, ("direct",)),
            dep("second", 2, ("direct", "first")),
            dep("third", 3, ("direct", "first", "second")),
        ]
        advisories = {d.key: [critical(d.name)] for d in deps}
        policy = replace(DEFAULT_POLICY, max_depth=max_depth)
        # Every advisory matches every version, so anything reached is found.
        return triage_all(deps, advisories, kev_index={"CVE-2099-second"}, policy=policy)

    def test_unlimited_depth_reaches_everything(self):
        result = self._scan(None)
        assert result.dependencies_scanned == 4
        assert result.unreached_by_depth == 0

    def test_a_depth_of_one_stops_after_the_first_level(self):
        result = self._scan(1)
        assert result.dependencies_scanned == 2
        assert result.unreached_by_depth == 2

    def test_a_finding_three_levels_down_is_invisible_at_depth_one(self):
        """The property the pricing page depends on.

        `second` is KEV-listed here, which would otherwise alert whatever its
        severity or scope -- so this also pins that the depth limit is applied
        before triage rather than as one more suppression rule that KEV
        overrides.
        """
        shallow = self._scan(1)
        reached = {d.dependency.name for d in (*shallow.actionable, *shallow.suppressed)}
        assert "second" not in reached
        assert "third" not in reached

        deep = self._scan(None)
        deep_reached = {d.dependency.name for d in (*deep.actionable, *deep.suppressed)}
        assert {"second", "third"} <= deep_reached

    def test_what_was_not_reached_is_counted_not_called_filtered(self):
        """ "Not checked" and "checked and found nothing" must never look the
        same coming out of a security tool."""
        result = self._scan(1)
        assert result.unreached_by_depth == 2
        # The two out-of-reach packages are not hiding in the suppressed list
        # dressed up as noise we decided about.
        suppressed = {d.dependency.name for d in result.suppressed}
        assert "second" not in suppressed
        assert "third" not in suppressed

    def test_dependencies_scanned_counts_what_was_examined(self):
        """Reporting the parsed total would overstate the work."""
        assert self._scan(0).dependencies_scanned == 1
        assert self._scan(None).dependencies_scanned == 4


class TestThePlanOwnsTheNumber:
    def test_free_stops_after_the_first_level(self):
        assert scan_depth_for(Tier.FREE) == 1

    def test_pro_goes_all_the_way(self):
        assert scan_depth_for(Tier.PRO) is None

    def test_an_unknown_tier_gets_the_free_limit(self):
        """`limits_for` falls back rather than raising, so a subscription row
        written by a future version degrades instead of failing the scan."""
        assert scan_depth_for("enterprise-plus") == 1

    @pytest.mark.parametrize(
        ("tier", "phrase"),
        [(Tier.FREE, "direct dependencies and theirs"), (Tier.PRO, "the whole tree")],
    )
    def test_the_reach_has_a_phrase_the_interface_can_say(self, tier, phrase):
        assert depth_label(tier) == phrase


class TestEndToEnd:
    async def test_a_free_project_does_not_report_a_deep_finding(self, db, user):
        """Through the real pipeline, not the pure core.

        The advisory is in the mirror and the package is in the tree; the only
        thing standing between them is the plan.
        """
        from app.services.scan_service import scan_target
        from tests.test_scan_pipeline import LODASH_ADVISORY, make_target, seed_mirror

        await seed_mirror(db, LODASH_ADVISORY)

        # lodash sits three levels down, reachable only through the chain.
        lock = {
            "lockfileVersion": 3,
            "packages": {
                "": {"name": "demo", "dependencies": {"top": "^1"}},
                "node_modules/top": {"version": "1.0.0", "dependencies": {"middle": "1.0.0"}},
                "node_modules/middle": {"version": "1.0.0", "dependencies": {"lodash": "4.17.15"}},
                "node_modules/lodash": {"version": "4.17.15"},
            },
        }
        target = await make_target(db, user)
        target.manifest_kind = ManifestKind.PACKAGE_LOCK_JSON
        target.manifest_content = json.dumps(lock)

        outcome = await scan_target(db, target)

        assert outcome.actionable_count == 0
        assert outcome.unreached_by_depth >= 1

    async def test_the_same_project_on_pro_does_report_it(self, db, pro_user):
        from app.services.scan_service import scan_target
        from tests.test_scan_pipeline import LODASH_ADVISORY, make_target, seed_mirror

        await seed_mirror(db, LODASH_ADVISORY)
        lock = {
            "lockfileVersion": 3,
            "packages": {
                "": {"name": "demo", "dependencies": {"top": "^1"}},
                "node_modules/top": {"version": "1.0.0", "dependencies": {"middle": "1.0.0"}},
                "node_modules/middle": {"version": "1.0.0", "dependencies": {"lodash": "4.17.15"}},
                "node_modules/lodash": {"version": "4.17.15"},
            },
        }
        target = await make_target(db, pro_user)
        target.manifest_kind = ManifestKind.PACKAGE_LOCK_JSON
        target.manifest_content = json.dumps(lock)

        outcome = await scan_target(db, target)

        assert outcome.unreached_by_depth == 0
        found = outcome.actionable_count + outcome.suppressed_count
        assert found >= 1, "Pro should reach a finding three levels down"

    async def test_the_route_is_stored_on_the_finding(self, db, pro_user):
        """So it survives the dependency rows being replaced next parse."""
        from sqlalchemy import select

        from app.models import CVEMatch
        from app.services.scan_service import scan_target
        from tests.test_scan_pipeline import LODASH_ADVISORY, make_target, seed_mirror

        await seed_mirror(db, LODASH_ADVISORY)
        lock = {
            "lockfileVersion": 3,
            "packages": {
                "": {"name": "demo", "dependencies": {"top": "^1"}},
                "node_modules/top": {"version": "1.0.0", "dependencies": {"lodash": "4.17.15"}},
                "node_modules/lodash": {"version": "4.17.15"},
            },
        }
        target = await make_target(db, pro_user)
        target.manifest_kind = ManifestKind.PACKAGE_LOCK_JSON
        target.manifest_content = json.dumps(lock)
        await scan_target(db, target)

        match = (
            (await db.execute(select(CVEMatch).where(CVEMatch.package_name == "lodash")))
            .scalars()
            .first()
        )
        assert match is not None
        assert match.via == ["top"]
        assert match.depth == 1
        assert match.chain_label == "top → lodash"
        assert match.is_direct is False
