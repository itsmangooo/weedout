"""The terms and the privacy policy.

Kept in the repository rather than the database, unlike the documentation
pages. Two reasons, and the second is the one that matters:

1. They change rarely, and when they do the change should go through review
   like any other change to what the product promises.
2. `git log` is the version history. "What did the privacy policy say on the
   day I signed up?" is a question that can be asked in earnest, and an admin
   panel that overwrites in place has no answer to it.

**Every factual claim below was checked against the code**, not written from an
impression of it. Where the policy says a scan reaches no third party, that is
because `scan_service` matches against a local mirror and makes no outbound
call. Where it says there is no analytics, that is because there is no
analytics — no script, no pixel, no identifier. Those are the sentences worth
getting right, because they are the ones somebody may rely on.

Anything requiring a legal or business decision is marked `[[...]]` and must be
replaced before these pages are published. `test_legal_pages.py` fails while
any placeholder remains, so it is not possible to ship them half-finished.
"""

from __future__ import annotations

__all__ = ["PLACEHOLDER_PATTERN", "PRIVACY", "TERMS", "unresolved_placeholders"]

import re

#: The marker for a decision that is not ours to make.
PLACEHOLDER_PATTERN = re.compile(r"\[\[([^\]]+)\]\]")


def unresolved_placeholders(text: str) -> list[str]:
    """Every `[[...]]` still in a document."""
    return PLACEHOLDER_PATTERN.findall(text)


TERMS = """
_Last updated: [[DATE]]_

These terms cover your use of Weedout at weedout.dev, the Weedout API, and the
Weedout command-line tool. Using any of them means agreeing to them.

Weedout is operated by [[LEGAL ENTITY NAME]], [[REGISTERED ADDRESS]],
registered in [[JURISDICTION]] under number [[COMPANY NUMBER]]. "We" and "us"
mean that entity; "you" means the person or organisation using the service.

## What the service does

Weedout watches the dependencies you tell it about and reports vulnerabilities
that are either being exploited in the wild or are severe and reachable in code
that ships. It deliberately does not report everything it finds — that is the
product, not a limitation, and the reasoning is public in our documentation.

## What it is not

**Weedout is not a guarantee that your software is secure.** It is one tool
that reads public advisory data and compares it to a list of dependencies you
provide. It will miss things. Specifically and by design, it will not tell you
about:

- Vulnerabilities that no advisory has been published for.
- Vulnerabilities in code you wrote, in your configuration, or in your
  infrastructure.
- Dependencies you did not tell us about, including anything resolved at
  runtime or vendored without a manifest entry.
- Findings your own rules told it to suppress.
- Anything at all, during a period when an upstream advisory feed is stale or
  our service is unavailable. We publish feed freshness at
  [weedout.dev/status](/status) so you can check this rather than assume it.

Do not use Weedout as your only control, and do not treat a clean scan as
evidence of anything beyond what it says.

## Your account

You need an account, and you are responsible for what happens under it. Keep
your password and your API keys to yourself. Tell us promptly if you think
either has been exposed — you can revoke keys and sign machines out yourself
from your account settings at any time.

One account is one account. It may belong to a company, but it is a single
login and not a multi-user team, and sharing one set of credentials among
several people is your decision and your risk.

You must be old enough to enter a contract where you live, and you must not use
Weedout to scan software you have no right to scan.

## Payment

The free plan costs nothing and needs no card. The Pro plan is billed in
advance through our payment provider, [[PAYMENT PROVIDER]], who handles the
card details — we never see or store them.

- Prices are shown on the [pricing page](/pricing) and may change with
  [[NOTICE PERIOD]] notice. A change never applies to a period you have already
  paid for.
- Cancel at any time from your billing page. Your plan stays active until the
  end of the period you have paid for, and then drops to the free plan. Your
  data is not deleted.
- Refunds: [[REFUND POLICY]].
- Taxes are your responsibility unless we are required to collect them.

## Acceptable use

Do not:

- Attempt to break, overload, or gain unauthorised access to the service.
- Use it to scan or attack systems you do not have permission to.
- Resell access, or run it as a service for third parties. (The source is
  [AGPL-3.0](https://github.com/itsmangooo/weedout) if you want to run your
  own — that licence, not these terms, governs what you may do with the code.)
- Automate the interface in a way that materially degrades it for others. The
  API exists; use it, within its published rate limits.

We may suspend an account that is doing any of the above. Where the situation
allows it, we will tell you first.

## Availability

We try to keep the service running and we do not promise that it always will
be. There is no uptime commitment on any plan. Current state is at
[weedout.dev/status](/status).

## Your content

Manifests, project names, and rules you upload remain yours. You give us
permission to store and process them only so far as running the service
requires. We do not use your dependency data to train anything, sell it, or
share it with anyone — see the [privacy policy](/privacy).

We name a customer on our website only if that customer explicitly asked to be
named, and we remove a name immediately on request.

## Ending it

Delete your account whenever you like, from your settings. That removes your
projects, findings, keys and manifests. Some records — invoices, and audit
entries for administrative actions — are kept where the law requires or where
they are the only record that something happened.

We may close an account that breaks these terms, or with [[NOTICE PERIOD]]
notice for any reason. If we close your account for a reason other than a
breach by you, we will refund the unused part of anything you have paid.

## Liability

To the extent the law allows:

- The service is provided as it is, without warranty of any kind.
- We are not liable for indirect or consequential loss, lost profits, lost
  data, or a security incident that Weedout did not warn you about.
- Our total liability in any twelve-month period is limited to what you paid us
  in that period.

Nothing here limits liability for anything that cannot lawfully be limited,
including fraud and death or personal injury caused by negligence.

## Changes

We may change these terms. Material changes will be announced by email to the
address on your account at least [[NOTICE PERIOD]] before they take effect.
Continuing to use the service after that means accepting them.

## Law

These terms are governed by the law of [[JURISDICTION]], and its courts have
exclusive jurisdiction.

## Contact

[[SUPPORT EMAIL]], or the [contact form](/contact).
"""


PRIVACY = """
_Last updated: [[DATE]]_

This describes what Weedout collects, why, and what happens to it. It is
written from what the software actually does, and the specific claims in it are
checkable against the source, which is public.

The data controller is [[LEGAL ENTITY NAME]], [[REGISTERED ADDRESS]],
[[JURISDICTION]]. Contact: [[PRIVACY CONTACT EMAIL]].

## The short version

- **There is no analytics, no tracking pixel, and no advertising identifier.**
  Not a reduced set — none at all. No Google Analytics, no session recorder, no
  third-party script of any kind runs on these pages.
- **Your dependency list never leaves our servers during a scan.** We mirror
  the public advisory databases and match locally. Scanning does not tell OSV,
  GitHub, or anybody else what you depend on.
- **We do not sell, rent or share your data**, and we do not use it to train
  anything.

## What we collect

### Because you gave it to us

| What | Why |
|---|---|
| Email address | To identify your account and send the alerts you asked for |
| Password | Stored only as an Argon2 hash. We cannot read it |
| Two-factor secret and backup codes, if you enable them | To verify your second factor |
| Company name and website, if you enter them | To address invoices and email correctly |
| Project names, manifests and lockfiles you upload | To scan them, which is the service |
| Scan rules, ignore rules and their reasons | To apply them, and so you can review your own decisions later |
| A webhook URL, if you set one | To deliver alerts to it |
| Messages you send us through the contact form | To reply |

### Because using a website produces it

| What | Why | Kept for |
|---|---|---|
| IP address and browser user-agent, on each session | To show you your own signed-in sessions so you can spot one you do not recognise, and to rate-limit abuse | Until the session expires or you revoke it; expired sessions are purged after 30 days |
| IP address, on sign-in and password-reset attempts | To rate-limit guessing | Short-lived; rate-limit records are purged automatically |
| IP address and machine name, on a `weedout auth` request | So you can tell your own laptop from a request you did not make, on the approval screen | Deleted with the request, within a day of it expiring |
| Server logs | To operate and debug the service | [[LOG RETENTION PERIOD]] |

Our request logs deliberately exclude query strings, because those can contain
password-reset tokens. Access logging from the web server is switched off for
that reason.

### Cookies

Three, all strictly necessary, none for tracking:

| Cookie | Purpose |
|---|---|
| `weedout_session` | Keeps you signed in. Opaque; it is a lookup key, not your data |
| `weedout_csrf` | Prevents another site submitting forms as you |
| `weedout_mfa` | Short-lived, only during two-factor sign-in |

Your theme preference is kept in your browser's local storage and never sent to
us.

Because none of these are used for analytics or advertising, there is no
consent banner. There is nothing to consent to.

## What we do not collect

- Payment card details. Checkout happens at [[PAYMENT PROVIDER]] and we receive
  only a customer reference, the plan, and its status.
- The contents of your source code. We read manifests and lockfiles — names and
  versions of dependencies — not the code itself.
- Anything about who you are beyond your email address and, if you enter it,
  your company name.

## Who else sees it

| Who | What they get | Why |
|---|---|---|
| [[HOSTING PROVIDER]] | Everything, as our infrastructure provider | The service runs there |
| [[EMAIL PROVIDER]] | Your email address, and the content of alerts sent to you | To deliver them |
| [[PAYMENT PROVIDER]] | Your email address and payment details you give them directly | To take payment |
| Discord, or a URL you configure | The alert content you asked to be sent there | Because you asked |

That is the whole list. We do not use advertising networks, data brokers, or
analytics providers, because we do not use analytics.

We fetch advisory data *from* OSV, CISA and others. That is outbound and
anonymous: we download their public catalogues on a schedule. Nothing about you
or your dependencies goes with those requests.

## How long we keep it

- **Your account and its data:** until you delete it.
- **Findings and scan history:** while the project exists. The archive of
  resolved and dismissed findings is limited by plan — 30 days on Free, a year
  on Pro. Open findings are never aged out.
- **Sessions:** until they expire or you revoke them; purged 30 days after.
- **Password reset tokens:** an hour, then purged within 7 days.
- **Invoices and billing records:** as long as tax law requires, which is
  [[FINANCIAL RECORD RETENTION]].
- **Administrative audit entries** (a support action taken on your account):
  kept after account deletion, with your email address, because the record of
  who did what to an account is worthless if it disappears with the account.

## Your rights

Wherever you are, you can:

- **See it.** Everything we hold is visible in the interface or the API.
- **Correct it.** Email and company details are editable in settings.
- **Delete it.** Account deletion is self-service and immediate.
- **Take it with you.** Findings, dependencies and rules are all available as
  JSON from the API.
- **Object to email.** Turn alerts off in settings. We send no marketing email
  you did not ask for.

If you are in the UK or the EU, the legal bases we rely on are: **contract**
for everything needed to run the service you signed up for, **legitimate
interests** for security and abuse prevention, and **legal obligation** for
financial records. You may complain to your local supervisory authority —
[[SUPERVISORY AUTHORITY]] — though we would rather you told us first.

## Where it is processed

[[HOSTING REGION]]. [[INTERNATIONAL TRANSFER BASIS, IF ANY]].

## Security

Passwords are hashed with Argon2. API keys, session tokens and reset tokens are
stored only as SHA-256 hashes — we cannot show you a key twice because we do
not have it. Two-factor authentication is available. Traffic is HTTPS-only, and
cookies are `Secure`, `HttpOnly` and `SameSite`.

None of that makes a breach impossible. If one happens and it affects you, we
will tell you within [[BREACH NOTIFICATION PERIOD]] of finding out, and we will
tell you what we actually know rather than waiting until the picture is
comfortable.

## Changes

Material changes will be announced by email before they take effect. The
history of this page is public in our source repository, so you can see exactly
what changed and when.

## Contact

[[PRIVACY CONTACT EMAIL]], or the [contact form](/contact).
"""
