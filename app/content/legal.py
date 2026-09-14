"""The terms and privacy policy shown by the hosted service.

These documents live in the repository so changes are reviewed and their
history remains available in Git. Factual product claims are covered by the
legal-page tests where the implementation can verify them.
"""

from __future__ import annotations

__all__ = ["PLACEHOLDER_PATTERN", "PRIVACY", "TERMS", "unresolved_placeholders"]

import re

PLACEHOLDER_PATTERN = re.compile(r"\[\[([^\]]+)\]\]")


def unresolved_placeholders(text: str) -> list[str]:
    """Return any unresolved ``[[...]]`` decisions in a document."""
    return PLACEHOLDER_PATTERN.findall(text)


TERMS = r"""
*Last updated: 14 September 2026*

These Terms cover use of Weedout at weedout.dev, the Weedout API, and the
Weedout command-line tool.

By using Weedout, you agree to these Terms.

Weedout is operated from Bosnia and Herzegovina.

Support contact: support@weedout.dev

## What Weedout does

Weedout analyses dependencies you provide and uses vulnerability and project
context to identify security findings that may deserve attention.

Depending on the type of scan, this may include advisory information,
dependency paths, known exploitation information, severity, supported
reachability analysis, fixed versions and other evidence available to Weedout.

Weedout deliberately prioritises findings instead of presenting every possible
advisory as equally important.

## What Weedout does not do

**Weedout does not guarantee that your software is secure.**

It is one security tool and should not be treated as your only security control.

Among other things, Weedout may not identify:

- vulnerabilities for which no usable advisory exists
- vulnerabilities in your own application code
- configuration or infrastructure vulnerabilities
- dependencies that were not included in the information supplied to Weedout
- findings suppressed by rules you configured
- issues outside the ecosystems or analysis methods supported by Weedout
- findings that cannot be identified while an upstream advisory source or the
  Weedout service is unavailable or stale

A clean Weedout scan means only that Weedout did not surface a finding under the
rules and data available to that scan.

Feed and service state may be published at:

https://weedout.dev/status

## Your account

You are responsible for activity performed through your Weedout account and for
keeping your password, API keys and authentication credentials secure.

If you believe a credential has been exposed, revoke it or terminate affected
sessions as soon as possible.

A Weedout account is currently a single account rather than a multi-user team
workspace. If credentials are voluntarily shared with other people, you are
responsible for the risks created by that sharing.

You must have the legal capacity required to agree to these Terms where you
live.

You may only submit software, manifests, source files or other information that
you have the right to analyse and provide to Weedout.

## Price

Weedout currently provides one **Free** plan.

It costs nothing and does not require a payment card.

Features, limits or pricing may change in the future, but a paid service will
not be silently imposed on an existing account without clearly informing the
user first.

Historical billing records from previous payment functionality do not change
access to the current Free plan.

## Acceptable use

You must not:

- attempt to gain unauthorised access to Weedout or another user's account
- intentionally disrupt, overload or damage the service
- use Weedout to analyse systems or software where doing so would violate the
  rights of another person
- use the service as part of unlawful activity
- deliberately circumvent published service limits or security protections
- automate the website in a way that materially disrupts service for others
  when an API or CLI is provided for that purpose

We may restrict or suspend access where reasonably necessary to protect Weedout,
its infrastructure or other users.

Where practical and appropriate, we will explain the reason.

## Open-source software

Open-source components of Weedout are governed by the licence applicable to
that code rather than these Terms.

The Weedout CLI and any other code published in Weedout's repositories remain
subject to the licence included with that repository.

These Terms govern the hosted service at weedout.dev; they do not replace an
open-source licence.

## Availability

We try to keep Weedout operational, but the Free service has no contractual
uptime guarantee or service-level agreement.

The service may occasionally be unavailable because of maintenance, failures,
security incidents, upstream data-source problems or circumstances outside our
control.

Current service information may be published at:

https://weedout.dev/status

## Your content

Project names, manifests, rules and other content that you submit remain yours.

You give Weedout permission to receive, store and process that content only as
needed to:

- provide the service
- perform requested scans and analysis
- retain your findings and settings
- secure and operate the service
- provide features that you explicitly configure

We do not sell your dependency information or use it to train machine-learning
models.

More information is available in the Privacy Policy:

https://weedout.dev/privacy

## Security results

Vulnerability information can be incomplete, incorrect, stale, ambiguous or
affected by upstream data.

Reachability analysis and dependency analysis are technical estimates and may
produce false positives or false negatives.

You remain responsible for deciding whether and how to modify, deploy or secure
your own software.

Recommendations such as upgrading a dependency are informational and should be
reviewed in the context of your project before being applied.

## Ending your use of Weedout

You may stop using Weedout at any time and may delete your account through the
available account controls.

Account deletion removes active account and project information subject to the
retention obligations and backup limitations described in the Privacy Policy.

We may suspend or close an account where necessary because of:

- a material violation of these Terms
- abuse of the service
- a security risk
- a legal obligation

We may also discontinue the Free hosted service.

Where reasonably possible, we will provide at least **30 days' notice** before
a planned discontinuation that is not caused by abuse, an emergency or a legal
requirement.

## No warranty

To the maximum extent permitted by applicable law, Weedout is provided on an
**"as is"** and **"as available"** basis.

We do not promise that:

- Weedout will find every vulnerability
- every finding will be correct
- the service will always be available
- upstream vulnerability information will always be complete or current
- following a Weedout recommendation will make a system secure

Nothing in these Terms excludes rights or warranties that applicable law does
not allow to be excluded.

## Liability

To the extent permitted by applicable law, we are not responsible for indirect,
incidental or consequential losses arising solely from use of or inability to
use the Free service.

Because Weedout is currently provided without charge, no clause in these Terms
is intended to remove or reduce liability that applicable law does not permit
to be limited, including liability arising from fraud or other liability that
cannot legally be excluded.

## Changes to these Terms

We may update these Terms as the service changes.

For a material change, we will provide reasonable advance notice where
practical. We currently aim to provide at least **30 days' notice** for material
changes that are not required immediately for security, abuse prevention or
legal compliance.

Continued use of Weedout after the effective date of updated Terms means the
updated Terms apply to later use, subject to rights that applicable law gives
you.

## Governing law

These Terms are governed by the laws of **Bosnia and Herzegovina**, except where
mandatory consumer or other applicable law requires otherwise.

Disputes are subject to the competent courts determined by applicable law.

## Contact

For support or questions about these Terms:

**support@weedout.dev**

You may also use:

https://weedout.dev/contact
"""


PRIVACY = r"""
*Last updated: 14 September 2026*

This Privacy Policy explains what Weedout collects, why we collect it, how long
we keep it, and who may receive it.

Weedout is operated from Bosnia and Herzegovina.

Privacy contact: privacy@weedout.dev

## The short version

- **There is currently no analytics, tracking pixel, advertising identifier or
  session recorder on Weedout.**
- **Your dependency list is matched against advisory data on Weedout's
  infrastructure.** Scanning does not send your dependency list to OSV, CISA,
  GitHub, or other advisory providers.
- **We do not sell or rent personal data**, and we do not use your data to train
  machine-learning models.
- Weedout is currently a free service and does not require payment details.

## What we collect

### Information you give us

| What | Why |
|---|---|
| Email address | To identify your account and send service or security alerts you request |
| Password | Stored only as a password hash; the original password is not stored |
| Two-factor authentication secret and backup codes, if enabled | To verify your second factor |
| Company name and website, if you provide them | To identify your account or organisation |
| Project names, manifests and lockfiles | To perform dependency vulnerability analysis |
| Supported source files submitted by the CLI for reachability analysis | To determine whether supported vulnerable dependencies appear reachable |
| Scan rules, ignore rules and their reasons | To apply your configuration and retain your previous decisions |
| Webhook URL, if configured | To deliver alerts you requested |
| Messages submitted through the contact form | To respond to you |

### Information produced when you use the service

| What | Why | Retention |
|---|---|---|
| IP address and browser user-agent associated with a session | Session security, showing recognised sessions, and abuse prevention | Until the session expires or is revoked; expired session records are purged after 30 days |
| IP address used for sign-in and password-reset attempts | Rate limiting and abuse prevention | Temporary rate-limit data is removed automatically |
| IP address and machine name supplied during `weedout auth` | So you can identify the device requesting CLI access | Removed with the authentication request after it expires |
| Application and security logs | Operating, securing and debugging Weedout | Kept only for the operational retention configured on the production system |

Application request logging deliberately avoids query strings where they may
contain sensitive tokens.

Web-server access logging is not used as a behavioural analytics system.

## Cookies and local storage

Weedout uses only cookies required for the application to work.

| Cookie | Purpose |
|---|---|
| `weedout_session` | Keeps you signed in. It contains an opaque session identifier |
| `weedout_csrf` | Protects forms against cross-site request forgery |
| `weedout_mfa` | Short-lived state used during two-factor sign-in |

Theme preference may be stored locally in your browser.

These mechanisms are not used for advertising or behavioural tracking.

Because Weedout currently does not use optional analytics or advertising
cookies, no analytics/advertising consent cookie is required.

## Dependency and source-code processing

A browser-based manifest scan submits the dependency information required for
the scan.

The Weedout CLI may additionally submit a bounded set of supported JavaScript
and TypeScript files when reachability analysis is requested.

Those files are analysed for the purpose of producing reachability evidence.
Weedout does not intentionally retain complete raw source files after that
analysis.

Stored analysis results may include:

- reachability state
- relevant evidence snippets
- analysis completeness
- analysis notes
- dependency and finding metadata

Weedout downloads public vulnerability/advisory information independently and
matches project information against that data on Weedout's infrastructure.

Your dependency list is not sent to advisory providers as part of a scan.

## What we do not collect

Weedout does not currently collect payment card information.

Previous versions of the service contained integration support for Dodo
Payments. Historical customer or subscription references may remain where they
were created while that functionality was active, but the current Weedout
product uses a Free plan and does not require a payment card.

We do not intentionally collect demographic profiles, advertising identifiers,
or cross-site browsing histories.

## Service providers and external recipients

Some data may be processed by infrastructure providers that are necessary to
operate Weedout.

These may include:

- the infrastructure provider hosting the Weedout server and database
- the email delivery infrastructure used to send account and alert emails
- a notification destination such as Discord or a webhook URL that **you**
  configure
- Dodo Payments only in relation to historical payment/subscription records
  created when payment functionality was active

We do not provide personal data to advertising networks or data brokers.

The production deployment includes its own mail relay. Depending on the
deployment configuration, outbound mail may be delivered directly or through a
configured SMTP/email provider.

Weedout retrieves public advisory information from sources such as OSV and
CISA. Those catalogue downloads do not include your account or dependency
information.

## How long we keep information

- **Account and project data:** until you delete the account or project, except
  where another retention rule below applies.
- **Open findings:** retained while their project exists.
- **Resolved or dismissed finding history:** may be retained for up to one year
  so previous security decisions remain reviewable.
- **Sessions:** until expiry or revocation, with expired session records purged
  after 30 days.
- **Password-reset tokens:** valid for approximately one hour and subsequently
  purged by maintenance processes.
- **CLI authentication requests:** removed after expiry.
- **Historical billing records:** retained only for as long as required by
  applicable accounting, tax, or legal obligations.
- **Administrative audit records:** may be retained after account deletion where
  necessary to preserve the security and accountability record of an
  administrative action.
- **Backups:** may temporarily contain information deleted from the live
  database until the relevant backup expires under the configured backup
  retention schedule.

## Your rights

Subject to applicable law, you may:

- access personal data associated with your account
- correct account information
- delete your account and projects
- obtain available project, dependency, finding and rule data through Weedout's
  interface or API
- disable optional alerts and notifications
- object to or request restriction of certain processing where the law provides
  that right

Weedout does not send unrelated advertising email as part of the service.

For processing necessary to provide Weedout, the legal basis may be performance
of the service requested by you. Security, fraud prevention and service
protection may rely on legitimate interests. Information that must be kept by
law is processed to comply with the relevant legal obligation.

If you are in Bosnia and Herzegovina, the competent supervisory authority is:

**Personal Data Protection Agency in Bosnia and Herzegovina\
Dubrovačka 6\
71000 Sarajevo\
Bosnia and Herzegovina**

You may also contact the relevant supervisory authority where applicable to
you.

## International processing

Weedout is operated from Bosnia and Herzegovina.

Infrastructure or email providers may process data in another country depending
on the provider configured for the production deployment. Where applicable,
international transfers must use a transfer mechanism permitted by applicable
data-protection law.

## Security

Weedout uses security controls including password hashing, hashed authentication
tokens, two-factor authentication support, secure cookies and HTTPS in
production.

API keys, session tokens and password-reset tokens are designed to be stored in
a form that does not permit the original secret to be recovered from the stored
value.

No security measure makes a breach impossible.

If a personal-data breach occurs, Weedout will notify the competent supervisory
authority within the period required by applicable law where notification is
required. Under the Bosnia and Herzegovina Personal Data Protection Law, this
may require notification to the Agency without undue delay and, where
applicable, within 72 hours after becoming aware of the breach.

Where a breach is likely to result in a high risk to affected individuals, we
will notify affected users without undue delay as required by applicable law.

## Analytics

Weedout currently runs without website analytics.

If analytics or another non-essential tracking technology is introduced later,
this Privacy Policy will be updated before or when that processing begins and
any legally required consent mechanism will be implemented.

## Changes

We may update this Privacy Policy when Weedout, its infrastructure or applicable
law changes.

Material changes that significantly affect how personal data is processed will
be communicated through the service or by email where appropriate.

## Contact

For privacy questions or requests:

**privacy@weedout.dev**

You may also use the contact form:

https://weedout.dev/contact
"""
