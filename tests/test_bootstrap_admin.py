"""Creating the first administrator, exactly once.

Two things carry the weight. It must run once and then never again — a deploy
loop that regenerates the owner's password every time it restarts is an outage
with extra steps. And the generated password must never reach a log, which is
why the console email backend is refused rather than accommodated.
"""

from __future__ import annotations

import pytest
from sqlalchemy import func, select

from app.config import get_settings
from app.models import AdminAuditLog, User
from app.security import hash_password, verify_password
from app.services.bootstrap_service import ensure_admin

ADMIN = "founder@weedout.dev"
OPERATOR = "operator@example.com"


@pytest.fixture
def settings(monkeypatch):
    """Production-shaped settings: an admin address, a notify address, real mail.

    `smtp` rather than `console` because the service refuses console outright;
    `send_email` itself is stubbed by `sent` below, so nothing is delivered.
    """
    live = get_settings()
    monkeypatch.setattr(live, "admin_email", ADMIN)
    monkeypatch.setattr(live, "admin_bootstrap_notify_email", OPERATOR)
    monkeypatch.setattr(live, "email_backend", "smtp")
    monkeypatch.setattr(live, "smtp_host", "smtp.example.com")
    return live


@pytest.fixture
def sent(monkeypatch):
    """Capture outgoing mail instead of sending it."""
    messages: list[dict] = []

    async def fake_send(to, subject, text, html=None, settings=None):
        messages.append({"to": to, "subject": subject, "text": text})

    import app.services.bootstrap_service as module

    monkeypatch.setattr(module, "send_email", fake_send)
    return messages


async def admin_count(db) -> int:
    return await db.scalar(select(func.count(User.id)).where(User.is_admin.is_(True)))


class TestFirstRun:
    async def test_it_creates_an_administrator(self, db, settings, sent):
        outcome = await ensure_admin(db, settings)
        await db.flush()

        assert outcome.action == "created"
        assert outcome.email == ADMIN

        user = await db.scalar(select(User).where(User.email == ADMIN))
        assert user is not None
        assert user.is_admin is True
        assert user.password_hash

    async def test_the_password_is_stored_only_as_a_hash(self, db, settings, sent):
        await ensure_admin(db, settings)
        await db.flush()

        password = self._password_from(sent)
        user = await db.scalar(select(User).where(User.email == ADMIN))

        # The hash verifies the mailed password, and is not the password.
        assert verify_password(password, user.password_hash)
        assert password not in user.password_hash
        assert user.password_hash.startswith("$argon2")

    async def test_the_password_goes_to_the_operator_not_the_admin_account(
        self, db, settings, sent
    ):
        """At the moment the account is created nobody can sign in to read mail
        sent to it — and a mistyped ADMIN_EMAIL would deliver the credential to
        whoever owns the typo."""
        await ensure_admin(db, settings)

        assert len(sent) == 1
        assert sent[0]["to"] == OPERATOR
        assert sent[0]["to"] != ADMIN

    async def test_the_email_says_what_to_do_with_it(self, db, settings, sent):
        await ensure_admin(db, settings)
        body = sent[0]["text"]

        assert ADMIN in body
        assert "/login" in body
        assert "/settings" in body
        # Somebody receiving this needs to know it will not be repeated.
        assert "cannot be shown again" in body

    async def test_it_is_recorded_in_the_audit_log(self, db, settings, sent):
        await ensure_admin(db, settings)
        await db.flush()

        entry = await db.scalar(
            select(AdminAuditLog).where(AdminAuditLog.action == "admin.bootstrapped")
        )
        assert entry is not None
        assert entry.target_email == ADMIN

    async def test_the_audit_log_holds_no_part_of_the_credential(self, db, settings, sent):
        await ensure_admin(db, settings)
        await db.flush()

        password = self._password_from(sent)
        entry = await db.scalar(
            select(AdminAuditLog).where(AdminAuditLog.action == "admin.bootstrapped")
        )
        serialised = repr(entry.details)

        assert password not in serialised
        assert "argon2" not in serialised

    def _password_from(self, sent) -> str:
        line = next(line for line in sent[0]["text"].splitlines() if "Password:" in line)
        return line.split("Password:", 1)[1].strip()


class TestIdempotency:
    async def test_a_second_run_does_nothing(self, db, settings, sent):
        first = await ensure_admin(db, settings)
        await db.flush()
        second = await ensure_admin(db, settings)

        assert first.action == "created"
        assert second.action == "noop"
        assert len(sent) == 1, "the password must never be re-sent"
        assert await admin_count(db) == 1

    async def test_repeated_runs_never_change_the_password(self, db, settings, sent):
        """The deploy-loop case. A container that restarts ten times must not
        invalidate the owner's password ten times."""
        await ensure_admin(db, settings)
        await db.flush()

        user = await db.scalar(select(User).where(User.email == ADMIN))
        original_hash = user.password_hash

        for _ in range(5):
            outcome = await ensure_admin(db, settings)
            assert outcome.action == "noop"

        await db.refresh(user)
        assert user.password_hash == original_hash
        assert len(sent) == 1

    async def test_an_unrelated_existing_admin_is_enough(self, db, settings, sent):
        """`ADMIN_EMAIL` is a bootstrap hint, not a requirement. If somebody has
        already been promoted by hand, there is nothing to bootstrap."""
        db.add(
            User(
                email="someone-else@example.com",
                password_hash=hash_password("correct-horse-battery"),
                is_admin=True,
            )
        )
        await db.flush()

        outcome = await ensure_admin(db, settings)

        assert outcome.action == "noop"
        assert sent == []
        assert await db.scalar(select(User).where(User.email == ADMIN)) is None


class TestExistingAccount:
    async def test_a_matching_account_is_promoted_not_replaced(self, db, settings, sent):
        """Somebody already owns this account and knows their password.

        Regenerating it because the deployment wanted an admin would be a
        lockout, not a bootstrap.
        """
        original = hash_password("their-own-chosen-password")
        db.add(User(email=ADMIN, password_hash=original))
        await db.flush()

        outcome = await ensure_admin(db, settings)
        await db.flush()

        assert outcome.action == "promoted"
        user = await db.scalar(select(User).where(User.email == ADMIN))
        assert user.is_admin is True
        assert user.password_hash == original
        assert sent == [], "an existing owner must not be emailed a new password"

    async def test_promotion_is_audited(self, db, settings, sent):
        db.add(User(email=ADMIN, password_hash=hash_password("x" * 12)))
        await db.flush()

        await ensure_admin(db, settings)
        await db.flush()

        entry = await db.scalar(
            select(AdminAuditLog).where(AdminAuditLog.action == "admin.promoted")
        )
        assert entry is not None
        assert entry.details["source"] == "bootstrap"


class TestRefusals:
    async def test_it_skips_when_admin_email_is_unset(self, db, settings, sent, monkeypatch):
        monkeypatch.setattr(settings, "admin_email", None)

        outcome = await ensure_admin(db, settings)

        assert outcome.action == "skipped"
        assert "ADMIN_EMAIL" in outcome.detail
        assert await admin_count(db) == 0

    async def test_it_skips_when_there_is_nowhere_to_send_the_password(
        self, db, settings, sent, monkeypatch
    ):
        """No default recipient. A generated credential mailed to an address
        nobody chose is worse than no bootstrap at all."""
        monkeypatch.setattr(settings, "admin_bootstrap_notify_email", None)

        outcome = await ensure_admin(db, settings)

        assert outcome.action == "skipped"
        assert "ADMIN_BOOTSTRAP_NOTIFY_EMAIL" in outcome.detail
        assert await admin_count(db) == 0

    async def test_the_console_email_backend_is_refused(self, db, settings, sent, monkeypatch):
        """The console backend delivers by logging the message body.

        Using it here would put a live admin password into the log stream, which
        is the one thing this module promises not to do — so it refuses rather
        than accommodating it.
        """
        monkeypatch.setattr(settings, "email_backend", "console")

        outcome = await ensure_admin(db, settings)

        assert outcome.action == "skipped"
        assert "console" in outcome.detail
        assert "promote-admin" in outcome.detail, "the refusal should name the way forward"
        assert await admin_count(db) == 0
        assert sent == []

    async def test_nothing_is_created_when_the_email_cannot_be_delivered(
        self, db, settings, monkeypatch
    ):
        """Committing the account and then failing to send would leave an
        administrator whose password nobody will ever know."""
        import app.services.bootstrap_service as module
        from app.mail import EmailError

        async def explode(**kwargs):
            raise EmailError("mailbox unavailable")

        monkeypatch.setattr(module, "send_email", explode)

        outcome = await ensure_admin(db, settings)

        assert outcome.action == "skipped"
        assert "no account was created" in outcome.detail
        assert await admin_count(db) == 0
        assert await db.scalar(select(User).where(User.email == ADMIN)) is None

    async def test_a_delivery_failure_can_be_retried(self, db, settings, monkeypatch):
        """The next deploy should succeed, not find a half-made account."""
        import app.services.bootstrap_service as module
        from app.mail import EmailError

        async def explode(**kwargs):
            raise EmailError("temporary failure")

        monkeypatch.setattr(module, "send_email", explode)
        assert (await ensure_admin(db, settings)).action == "skipped"

        messages: list[dict] = []

        async def works(to, subject, text, html=None, settings=None):
            messages.append({"to": to})

        monkeypatch.setattr(module, "send_email", works)
        outcome = await ensure_admin(db, settings)

        assert outcome.action == "created"
        assert len(messages) == 1


class TestTheLogNeverSeesThePassword:
    """Captured through structlog, not `caplog`.

    `configure_logging` clears the root logger's handlers, which removes the one
    pytest's logging plugin installed — so `caplog.text` can be empty even while
    lines are being emitted. An assertion that a secret is *absent* from an empty
    string passes for the wrong reason, and this is the one test where a false
    pass would matter most. `structlog.testing.capture_logs` intercepts above the
    stdlib entirely and cannot be defeated that way.
    """

    async def test_no_log_line_contains_it(self, db, settings, sent):
        import structlog

        with structlog.testing.capture_logs() as captured:
            await ensure_admin(db, settings)
            await db.flush()

        password = next(
            line.split("Password:", 1)[1].strip()
            for line in sent[0]["text"].splitlines()
            if "Password:" in line
        )

        assert password
        # Guard against the vacuous version of this test: if nothing was
        # captured, the assertion below proves nothing.
        assert captured, "no log lines were captured; this test would pass vacuously"
        assert password not in repr(captured)

    async def test_the_created_line_is_still_useful(self, db, settings, sent):
        """Silence would be its own problem — an operator needs to see that the
        bootstrap ran, just not what it generated."""
        import structlog

        with structlog.testing.capture_logs() as captured:
            await ensure_admin(db, settings)

        events = [entry.get("event") for entry in captured]
        assert "bootstrap.admin_created" in events

        created = next(e for e in captured if e.get("event") == "bootstrap.admin_created")
        assert created["notified"] == OPERATOR
        # user_id is enough to find the account; nothing else belongs here.
        assert "password" not in created
