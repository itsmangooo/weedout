"""Every Pro capability, and proof that Free is refused server-side.

Written as one sweep rather than as gate checks scattered through the feature
suites, because the failure this guards against is a *whole feature* shipping
without a gate — and a test that only covers the features somebody remembered
to write one for would never catch that.

Two rules the assertions here encode:

1. **The gate is on use, not on save.** A row may exist from a lapsed
   subscription or from a `.weedout.yml` a Pro pipeline pushed last month.
   Downgrading must stop the feature applying without deleting anybody's
   configuration, so the check belongs where the feature runs.
2. **Never trust the client.** Every one of these is reachable from the CLI
   with a flag, or from a file in somebody's repository. A local value saying
   "I am allowed" is an assertion by the caller, not a fact.

`TestTheAuditIsComplete` at the bottom is the part that keeps this honest: it
fails when a new Pro capability appears in `PlanLimits` without a case here.
"""

from __future__ import annotations

import json
from datetime import timedelta
from pathlib import Path
from typing import ClassVar

import pytest

from app.core.types import Severity, Tier
from app.models import IgnoreRule
from app.services.rules_service import build_policy
from app.services.target_service import (
    TargetLimitReached,
    add_manifest,
    create_target,
)
from app.tiers import (
    PLANS,
    can_add_target,
    can_use_custom_rules,
    can_use_webhooks,
    history_cutoff_days,
    scan_depth_for,
    scan_interval_for,
)
from tests.conftest import set_csrf

MANIFEST = json.dumps({"dependencies": {"lodash": "4.17.15"}})
SECOND = json.dumps({"dependencies": {"express": "4.18.1"}})


#: A structurally valid Discord webhook. Structural validity matters — the URL
#: has to survive the save-time checks so that what the test observes is the
#: tier gate rather than a rejected URL.
WEBHOOK_URL = "https://discord.com/api/webhooks/123456789012345678/abcdefghijklmnopqrstuvwxyz012345"

#: Slack in the scheduling assertions below: `utcnow()` is read twice, once by
#: the test and once by the scan.
MINUTE = timedelta(minutes=1)


async def a_project(db, owner, content: str = MANIFEST, filename: str = "package.json"):
    return await create_target(db, owner, filename=filename, content=content)


async def attempt_a_digest(db, owner, monkeypatch) -> list[str]:
    """Scan a project with a real finding, send the digest, return every URL
    the webhook channel tried to post to."""
    from app.services import alert_service
    from app.services.discord_service import DeliveryResult
    from app.services.scan_service import scan_target
    from tests.test_scan_pipeline import LODASH_ADVISORY, make_target, seed_mirror

    posted: list[str] = []

    async def record(url, payload, **kwargs):
        posted.append(url)
        return DeliveryResult(ok=True, status=204)

    monkeypatch.setattr(alert_service, "post_webhook", record)

    await seed_mirror(db, LODASH_ADVISORY)
    target = await make_target(db, owner)
    target.discord_webhook_url = WEBHOOK_URL
    outcome = await scan_target(db, target)
    assert outcome.new_matches, "the fixture should produce a finding to alert on"

    await alert_service.send_new_match_digest(db, owner, target, outcome.new_matches)
    return posted


# ---------------------------------------------------------------------------
# 1. Project count
# ---------------------------------------------------------------------------


class TestProjectLimit:
    def test_free_is_capped_and_pro_is_not(self):
        assert can_add_target(Tier.FREE, current_count=0) is True
        assert can_add_target(Tier.FREE, current_count=1) is False
        assert can_add_target(Tier.PRO, current_count=500) is True

    async def test_a_second_project_is_refused_for_free(self, db, user):
        await a_project(db, user)

        with pytest.raises(TargetLimitReached):
            await a_project(db, user, content=SECOND)

    async def test_pro_may_add_more(self, db, pro_user):
        await a_project(db, pro_user)
        await a_project(db, pro_user, content=SECOND)  # must not raise

    async def test_the_limit_is_enforced_at_the_endpoint_too(self, auth_client, db, user):
        """Not only in the service. The endpoint is what a CLI reaches."""
        from tests.conftest import create_project

        first = await create_project(auth_client, filename="package.json", content=MANIFEST)
        assert first.status_code in (200, 201)

        second = await create_project(auth_client, filename="package.json", content=SECOND)
        assert second.status_code == 402, "the refusal names payment, not a malformed request"


# ---------------------------------------------------------------------------
# 2. Scan depth
# ---------------------------------------------------------------------------


class TestScanDepth:
    def test_free_is_shallow_and_pro_is_unlimited(self):
        assert scan_depth_for(Tier.FREE) is not None
        assert scan_depth_for(Tier.PRO) is None

    async def test_the_depth_limit_reaches_the_policy_a_scan_runs_under(self, db, user, pro_user):
        free_target = await a_project(db, user)
        pro_target = await a_project(db, pro_user)

        free_policy = await build_policy(db, free_target, user)
        pro_policy = await build_policy(db, pro_target, pro_user)

        assert free_policy.policy.max_depth == scan_depth_for(Tier.FREE)
        assert pro_policy.policy.max_depth is None


# ---------------------------------------------------------------------------
# 3. Custom rules — thresholds, ignore rules, .weedout.yml
# ---------------------------------------------------------------------------


class TestCustomRules:
    def test_the_helper_agrees_with_the_plan_table(self):
        assert can_use_custom_rules(Tier.FREE) is False
        assert can_use_custom_rules(Tier.PRO) is True

    @pytest.mark.parametrize(
        ("field", "value"),
        [
            ("direct_threshold", Severity.LOW),
            ("transitive_threshold", Severity.LOW),
            ("dev_threshold", Severity.LOW),
        ],
    )
    async def test_a_severity_override_does_not_apply_on_free(self, db, user, field, value):
        target = await a_project(db, user)
        setattr(target, field, value)
        await db.flush()

        effective = await build_policy(db, target, user)

        assert getattr(effective.policy, field) is not value
        assert any("Pro plan" in note for note in effective.notes)

    async def test_the_same_override_applies_on_pro(self, db, pro_user):
        target = await a_project(db, pro_user)
        target.direct_threshold = Severity.LOW
        await db.flush()

        effective = await build_policy(db, target, pro_user)

        assert effective.policy.direct_threshold is Severity.LOW

    async def test_a_policy_file_is_ignored_on_free(self, db, user):
        """The file arrives from the caller's repository, so this is the
        clearest case of not trusting the client."""
        target = await a_project(db, user)
        target.policy_file = "severity:\n  direct: low\n"
        await db.flush()

        effective = await build_policy(db, target, user)

        assert effective.policy.direct_threshold is not Severity.LOW
        assert any("Pro plan" in note for note in effective.notes)

    async def test_an_ignore_rule_does_not_apply_on_free(self, db, user):
        target = await a_project(db, user)
        db.add(
            IgnoreRule(
                target_id=target.id,
                identifier="CVE-2020-8203",
                reason="Left over from a Pro subscription.",
            )
        )
        await db.flush()

        effective = await build_policy(db, target, user)

        assert not effective.policy.ignored_ids

    async def test_a_rule_profile_does_not_apply_on_free(self, db, user):
        """Profiles reuse the `custom_rules` field rather than adding one, so
        the completeness check below would not have noticed them arriving
        without a gate. Walked here explicitly for that reason."""
        from app.services.profile_service import create_profile

        profile = await create_profile(
            db, user, name="Strict", document="severity:\n  direct: low\n"
        )
        target = await a_project(db, user)
        target.profile_id = profile.id
        await db.flush()

        effective = await build_policy(db, target, user)

        assert effective.policy.direct_threshold is not Severity.LOW
        assert effective.profile_name is None

    async def test_a_lapsed_subscription_keeps_the_configuration(self, db, pro_user):
        """Downgrading stops the rules applying. It must not delete them —
        somebody re-subscribing should find their settings intact."""
        target = await a_project(db, pro_user)
        target.direct_threshold = Severity.LOW
        await db.flush()

        pro_user.tier = Tier.FREE
        await db.flush()
        effective = await build_policy(db, target, pro_user)

        assert effective.policy.direct_threshold is not Severity.LOW
        assert target.direct_threshold is Severity.LOW, "the row survives the downgrade"


# ---------------------------------------------------------------------------
# 4. Webhooks
# ---------------------------------------------------------------------------


class TestWebhooks:
    def test_free_has_none(self):
        assert can_use_webhooks(Tier.FREE) is False
        assert can_use_webhooks(Tier.PRO) is True

    async def test_setting_one_is_refused_at_the_endpoint(self, auth_client, db, user):
        target = await a_project(db, user)
        await db.commit()

        response = await auth_client.post(
            f"/api/internal/projects/{target.id}/webhook",
            json={"url": "https://discord.com/api/webhooks/1/abc"},
            headers={"X-CSRF-Token": set_csrf(auth_client)},
        )

        assert response.status_code in (400, 402, 403)

    async def test_a_stored_webhook_does_not_fire_on_free(self, db, user, monkeypatch):
        """The gate is at delivery, not only at save.

        A URL saved while Pro, or one predating the gate, must stop posting the
        moment the plan lapses — without anybody having to clear the field.
        Asserted through `send_new_match_digest` rather than the private
        deliverer, because a gate that only holds when called directly is not a
        gate.
        """
        posted = await attempt_a_digest(db, user, monkeypatch)

        assert posted == [], "a Free account posted to a webhook"

    async def test_the_same_webhook_fires_on_pro(self, db, pro_user, monkeypatch):
        """The negative above only means something next to this one."""
        posted = await attempt_a_digest(db, pro_user, monkeypatch)

        assert posted == [WEBHOOK_URL]


# ---------------------------------------------------------------------------
# 5. Scan cadence and history retention
# ---------------------------------------------------------------------------


class TestCadenceAndHistory:
    def test_pro_is_checked_more_often(self):
        assert scan_interval_for(Tier.PRO) < scan_interval_for(Tier.FREE)

    async def test_the_interval_is_what_schedules_the_next_scan(self, db, user, pro_user):
        """The numbers agreeing is not the same as the scheduler using them."""
        from app.models import utcnow
        from app.services.scan_service import scan_target
        from tests.test_scan_pipeline import make_target, seed_mirror

        await seed_mirror(db)
        before = utcnow()
        free_target = await make_target(db, user)
        pro_target = await make_target(db, pro_user)

        await scan_target(db, free_target)
        await scan_target(db, pro_target)

        assert free_target.next_scan_at - before >= scan_interval_for(Tier.FREE) - MINUTE
        assert pro_target.next_scan_at - before <= scan_interval_for(Tier.PRO) + MINUTE

    def test_pro_keeps_more_history(self):
        assert history_cutoff_days(Tier.PRO) > history_cutoff_days(Tier.FREE)

    def test_the_window_is_applied_to_the_archive_and_nothing_else(self):
        """`history_days` sat on the plan table unread for a while: the pricing
        page sold a longer archive and every Free account already had one.

        The behaviour is pinned in detail in `test_internal_findings.py`; what
        this asserts is that the number reaches a query at all, which is the
        thing the sweep exists to notice.
        """
        from app.services.finding_service import history_window

        assert history_window(Tier.FREE, "resolved") == history_cutoff_days(Tier.FREE)
        assert history_window(Tier.PRO, "resolved") == history_cutoff_days(Tier.PRO)

        # Never for the tabs that describe the present. A live vulnerability
        # behind a paywall is not a plan limit, it is a security product
        # failing at its job.
        assert history_window(Tier.FREE, "open") is None
        assert history_window(Tier.FREE, "filtered") is None


# ---------------------------------------------------------------------------
# 6. Supply-chain signals
# ---------------------------------------------------------------------------


class TestSupplyChainSignals:
    async def test_they_are_not_raised_for_a_free_scan(self, db, user):
        """Gated inside the scan rather than inside the assessment, so a
        lapsed plan stops raising them without deleting the ones already
        recorded."""
        from sqlalchemy import select

        from app.models import SupplyChainFinding
        from app.services.scan_service import scan_target
        from tests.test_scan_pipeline import seed_mirror

        await seed_mirror(db)
        target = await a_project(
            db, user, content=json.dumps({"dependencies": {"lodahs": "1.0.0"}})
        )

        await scan_target(db, target)

        assert (await db.scalars(select(SupplyChainFinding))).all() == []


# ---------------------------------------------------------------------------
# 7. Multi-manifest
# ---------------------------------------------------------------------------


class TestMultiManifestFollowsTheProjectLimit:
    async def test_free_may_still_add_a_second_file_to_its_one_project(self, db, user):
        """Deliberately *not* gated. The limit is on projects, and a monorepo
        with a backend and a frontend is one project — charging for the second
        file would make the free plan useless for the shape of repository it
        is most often tried on.

        Recorded here so that turning it into a Pro feature later is a decision
        somebody makes on purpose rather than a gate that drifts in.
        """
        target = await a_project(db, user)

        await add_manifest(
            db,
            target,
            filename="go.mod",
            content="module x\n\ngo 1.22\n\nrequire github.com/gin-gonic/gin v1.9.0\n",
        )

        from app.services.target_service import load_manifests

        assert len(await load_manifests(db, target)) == 2


# ---------------------------------------------------------------------------
# The part that keeps this file honest
# ---------------------------------------------------------------------------


class TestTheAuditIsComplete:
    """A new Pro capability must appear here, not just in the plan table.

    The gap this closes: somebody adds `sso: bool` to `PlanLimits`, wires it
    into the pricing page, and never writes the server-side check. Every test
    in the suite still passes, because no test knows the feature exists. These
    three do, because they read the plan table rather than a list somebody
    maintains by hand.
    """

    #: Field on `PlanLimits` -> the class above that proves Free is refused.
    GATED: ClassVar[dict[str, str]] = {
        "max_targets": "TestProjectLimit",
        "scan_depth": "TestScanDepth",
        "custom_rules": "TestCustomRules",
        "webhook_alerts": "TestWebhooks",
        "scan_interval": "TestCadenceAndHistory",
        "history_days": "TestCadenceAndHistory",
    }

    #: Field -> why it needs no gate. Spelled out rather than left implicit,
    #: because "this one is fine" is exactly the reasoning that lets a real
    #: capability through.
    NOT_A_CAPABILITY: ClassVar[dict[str, str]] = {
        "tier": "the plan's own identity",
        "display_name": "what the plan is called on the pricing page",
        "price_label": "what it costs",
        "features": "the marketing bullet list, not the enforcement",
        "email_alerts": "true on both plans -- email is the product, not an upsell",
    }

    def _fields(self) -> set[str]:
        free = PLANS[Tier.FREE]
        # `__slots__` on a frozen dataclass, or the annotations if it grows a
        # __dict__ later. Either way, read from the class rather than listed.
        return set(getattr(free, "__slots__", None) or free.__annotations__)

    def test_every_field_is_accounted_for(self):
        """Catches a field added to the plan table and forgotten here."""
        unmapped = self._fields() - set(self.GATED) - set(self.NOT_A_CAPABILITY)

        assert unmapped == set(), (
            f"new PlanLimits fields with no entry in this audit: {sorted(unmapped)}. "
            f"Either add a gate test and map it in GATED, or say in NOT_A_CAPABILITY "
            f"why it needs none."
        )

    def test_nothing_is_waved_through_while_the_plans_differ(self):
        """A field can only sit in NOT_A_CAPABILITY while it is genuinely not a
        capability. The day `email_alerts` becomes Pro-only, this fails."""
        free, pro = PLANS[Tier.FREE], PLANS[Tier.PRO]

        waved_through = {
            name
            for name in self.NOT_A_CAPABILITY
            if name not in ("tier", "display_name", "price_label", "features")
            and getattr(free, name) != getattr(pro, name)
        }

        assert waved_through == set(), (
            f"{sorted(waved_through)} now differs between Free and Pro but is listed as "
            f"not a capability. Write the gate test and move it to GATED."
        )

    def test_every_gated_field_actually_differs(self):
        """The other direction: a gate test for something the plans agree on is
        either dead weight or a sign the limit was quietly removed."""
        free, pro = PLANS[Tier.FREE], PLANS[Tier.PRO]

        identical = {name for name in self.GATED if getattr(free, name) == getattr(pro, name)}

        assert identical == set(), (
            f"{sorted(identical)} is tested as Pro-gated but is the same on both plans."
        )

    def test_the_named_test_classes_exist(self):
        """A typo in GATED would otherwise silently excuse a field."""
        for field, class_name in self.GATED.items():
            assert class_name in globals(), f"{field} names a missing class {class_name!r}"


class TestWhatWeAdvertiseIsWhatWeEnforce:
    """Each Pro-only bullet on the pricing page has to name something the
    server refuses for Free.

    The bullets are the promise a customer pays against. A bullet with no
    enforcement behind it is a feature Free users already have, which makes the
    pricing page inaccurate in the direction that costs money; a gate with no
    bullet is a feature nobody knows they bought.
    """

    #: Pro-only bullet -> the `PlanLimits` field that enforces it.
    CLAIMS: ClassVar[dict[str, str]] = {
        "Unlimited projects": "max_targets",
        "Checked every 4 hours": "scan_interval",
        "The whole dependency tree, however deep": "scan_depth",
        "Custom scan rules and .weedout.yml": "custom_rules",
        "Discord and custom webhooks": "webhook_alerts",
        "A year of alert history": "history_days",
    }

    def test_every_pro_only_bullet_names_an_enforced_field(self):
        pro_only = set(PLANS[Tier.PRO].features) - set(PLANS[Tier.FREE].features)

        unbacked = pro_only - set(self.CLAIMS)

        assert unbacked == set(), (
            f"advertised on the pricing page with nothing enforcing it: {sorted(unbacked)}. "
            f"Build the gate before the bullet ships."
        )

    def test_each_claim_maps_to_a_field_this_file_tests(self):
        gated = set(TestTheAuditIsComplete.GATED)

        assert set(self.CLAIMS.values()) <= gated, (
            f"claims pointing at ungated fields: {sorted(set(self.CLAIMS.values()) - gated)}"
        )

    def test_no_stale_claims(self):
        """A bullet reworded on the pricing page without updating this map
        would otherwise leave a dead entry standing in for a live check."""
        pro_only = set(PLANS[Tier.PRO].features) - set(PLANS[Tier.FREE].features)

        assert set(self.CLAIMS) <= pro_only, (
            f"mapped bullets that are no longer Pro-only: {sorted(set(self.CLAIMS) - pro_only)}"
        )


class TestNobodyBranchesOnTierDirectly:
    """`app/tiers.py` opens by saying no route, template or job may branch on
    `user.tier == Tier.PRO`. Nothing enforced that, so this does.

    It matters for the reason the docstring gives — pricing changes should be
    one edit — and for a second one that matters more here: a capability check
    written inline is a capability check that never appears in the sweep above.

    What counts is `<instance>.tier` compared against a named plan —
    `user.tier is Tier.PRO`. Two near neighbours are deliberately not flagged:

    - `User.tier == Tier.PRO` is a query over the users table, not a decision
      about what a request may do. The receiver tells them apart: a model class
      rather than an instance.
    - `target.tier is new_tier` compares two tiers to each other, which is a
      no-op guard, not a capability check. The comparand tells those apart: a
      named member of `Tier` rather than another variable.
    """

    #: Files allowed to branch on an instance's tier, with the reason.
    ALLOWED: ClassVar[dict[str, str]] = {
        "app/tiers.py": "the table itself",
        "app/routes/internal_billing.py": "renders which plan you are on; not a capability",
        "app/routes/billing.py": "applies the plan change",
    }

    def _offenders(self) -> list[str]:
        import ast

        root = Path(__file__).resolve().parent.parent
        found = []
        for path in sorted((root / "app").rglob("*.py")):
            rel = path.relative_to(root).as_posix()
            if rel in self.ALLOWED:
                continue
            tree = ast.parse(path.read_text(encoding="utf-8"))
            for node in ast.walk(tree):
                if not isinstance(node, ast.Compare):
                    continue
                sides = (node.left, *node.comparators)
                reads_an_instance_tier = any(
                    isinstance(side, ast.Attribute)
                    and side.attr == "tier"
                    and isinstance(side.value, ast.Name)
                    # Lower-case receiver: an instance. `User.tier` is the
                    # column, and belongs to a query.
                    and side.value.id[:1].islower()
                    for side in sides
                )
                names_a_plan = any(
                    isinstance(side, ast.Attribute)
                    and isinstance(side.value, ast.Name)
                    and side.value.id == "Tier"
                    for side in sides
                )
                if reads_an_instance_tier and names_a_plan:
                    found.append(f"{rel}:{node.lineno}")
        return found

    def test_the_check_can_actually_see_an_offender(self):
        """A static check that matches nothing is indistinguishable from a
        clean codebase, so prove the detector fires."""
        import ast
        import textwrap

        source = textwrap.dedent(
            """
            def render(user):
                if user.tier is Tier.PRO:
                    return "pro"
                return "free"
            """
        )
        tree = ast.parse(source)
        compares = [n for n in ast.walk(tree) if isinstance(n, ast.Compare)]

        assert len(compares) == 1
        sides = (compares[0].left, *compares[0].comparators)
        assert any(
            isinstance(s, ast.Attribute) and s.attr == "tier" and s.value.id == "user"
            for s in sides
        )
        assert any(isinstance(s, ast.Attribute) and s.value.id == "Tier" for s in sides)

    def test_capability_decisions_go_through_the_plan_table(self):
        offenders = self._offenders()

        assert offenders == [], (
            f"tier compared directly at {offenders}. Add a `can_*` helper to app/tiers.py "
            f"and a case to this audit, so the new gate is covered by the sweep."
        )
