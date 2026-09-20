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
DubrovaÄka 6\
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