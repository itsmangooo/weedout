# Remaining Python inventory

Audit date: 2026-09-20  
Tracked Python files: **196**

## Conclusion

No tracked Python file is currently safe to delete while preserving working behavior. The migration is not complete: `web/` owns health, readiness, and the read-only session bootstrap, while the fallback still delegates the rest of the product to FastAPI. Detection is configured only as `off` or `shadow`, so Python remains authoritative. Alembic is still the sole schema writer, and Python workers still synchronize advisories and run scheduled jobs.

Deleting `app/`, `tests/`, `migrations/`, `pyproject.toml`, `requirements.txt`, or the Python Docker stages now would break production behavior, local development, CI, or recovery. No `.gitattributes` language override is present or proposed.

## Verified blockers

- `next.config.ts` still contains the catch-all legacy rewrite.
- `DETECTION_ENGINE_MODE` accepts only `off` and `shadow`; Go is not authoritative.
- Next.js currently owns only `/healthz`, `/readyz`, and `/api/internal/auth/me`.
- FastAPI still owns authentication mutations, projects, findings, profiles, rules, admin, billing, docs, notifications, CLI/account APIs, and events.
- Python jobs still own OSV mirror synchronization, KEV/EPSS refresh, rescans, cleanup, backups, and notification scheduling.
- Alembic still owns the production schema and its full migration history.
- The default and production Docker/Compose definitions still start the Python web and worker runtimes.

## Python runtime references outside `.py` files

| File | Current dependency |
|---|---|
| `pyproject.toml` | Defines the FastAPI application, worker entrypoint, Python dependencies, linting, and test configuration. |
| `requirements.txt` | Pins the Python production and development environment. |
| `alembic.ini` | Configures the active Alembic schema migration system. |
| `Dockerfile` | Builds and starts the Python web runtime. |
| `docker-compose.yml` | Starts Alembic, `python -m app`, and the Python worker. |
| `docker-compose.prod.yml` | Production still starts the Python web and worker services. |
| `docker-compose.migration.yml` | Next.js still proxies unmigrated routes to the Python `legacy` service and runs the Python worker. |
| `.github/workflows/ci.yml` | Installs Python, applies Alembic migrations, runs parity, and runs the legacy test suite. |
| `scripts/ship.sh` | Treats Python linting, Alembic, parity, and pytest as required shipping gates. |
| `scripts/backup.sh` | Calls the Python S3 upload helper. |
| `scripts/deploy.ps1` | Runs Python formatting, linting, and tests before deployment. |
| `.github/action.yml` | Installs the separately published Python CLI; this can only disappear when that action is retired or replaced. |

## File-by-file inventory

| File | Why it remains |
|---|---|
| `app/__init__.py` | Legacy application runtime/infrastructure (  init  ); required by remaining FastAPI routes, persistence, auth, or workers. |
| `app/__main__.py` | Legacy application runtime/infrastructure (  main  ); required by remaining FastAPI routes, persistence, auth, or workers. |
| `app/assets.py` | Legacy application runtime/infrastructure (assets); required by remaining FastAPI routes, persistence, auth, or workers. |
| `app/config.py` | Legacy application runtime/infrastructure (config); required by remaining FastAPI routes, persistence, auth, or workers. |
| `app/content/__init__.py` | Legacy content source (  init  ); public/legal page ownership has not moved to Next.js. |
| `app/content/legal.py` | Legacy content source (legal); public/legal page ownership has not moved to Next.js. |
| `app/core/__init__.py` | Authoritative Python domain code (  init  ); production scan mode is still off/shadow, so Go has not cut over. |
| `app/core/cvss.py` | Authoritative Python domain code (cvss); production scan mode is still off/shadow, so Go has not cut over. |
| `app/core/discord.py` | Authoritative Python domain code (discord); production scan mode is still off/shadow, so Go has not cut over. |
| `app/core/epss.py` | Authoritative Python domain code (epss); production scan mode is still off/shadow, so Go has not cut over. |
| `app/core/explain.py` | Authoritative Python domain code (explain); production scan mode is still off/shadow, so Go has not cut over. |
| `app/core/manifests.py` | Authoritative Python domain code (manifests); production scan mode is still off/shadow, so Go has not cut over. |
| `app/core/matching.py` | Authoritative Python domain code (matching); production scan mode is still off/shadow, so Go has not cut over. |
| `app/core/osv.py` | Authoritative Python domain code (osv); production scan mode is still off/shadow, so Go has not cut over. |
| `app/core/policy.py` | Authoritative Python domain code (policy); production scan mode is still off/shadow, so Go has not cut over. |
| `app/core/reachability.py` | Authoritative Python domain code (reachability); production scan mode is still off/shadow, so Go has not cut over. |
| `app/core/supply_chain.py` | Authoritative Python domain code (supply chain); production scan mode is still off/shadow, so Go has not cut over. |
| `app/core/totp.py` | Authoritative Python domain code (totp); production scan mode is still off/shadow, so Go has not cut over. |
| `app/core/types.py` | Authoritative Python domain code (types); production scan mode is still off/shadow, so Go has not cut over. |
| `app/core/versions.py` | Authoritative Python domain code (versions); production scan mode is still off/shadow, so Go has not cut over. |
| `app/core/webhooks.py` | Authoritative Python domain code (webhooks); production scan mode is still off/shadow, so Go has not cut over. |
| `app/db.py` | Legacy application runtime/infrastructure (db); required by remaining FastAPI routes, persistence, auth, or workers. |
| `app/deps.py` | Legacy application runtime/infrastructure (deps); required by remaining FastAPI routes, persistence, auth, or workers. |
| `app/feeds/__init__.py` | Production feed/worker code (  init  ); advisory synchronization and scheduled work have not moved from Python. |
| `app/feeds/epss.py` | Production feed/worker code (epss); advisory synchronization and scheduled work have not moved from Python. |
| `app/feeds/kev.py` | Production feed/worker code (kev); advisory synchronization and scheduled work have not moved from Python. |
| `app/feeds/osv.py` | Production feed/worker code (osv); advisory synchronization and scheduled work have not moved from Python. |
| `app/feeds/registry.py` | Production feed/worker code (registry); advisory synchronization and scheduled work have not moved from Python. |
| `app/jobs/__init__.py` | Production feed/worker code (  init  ); advisory synchronization and scheduled work have not moved from Python. |
| `app/jobs/runner.py` | Production feed/worker code (runner); advisory synchronization and scheduled work have not moved from Python. |
| `app/jobs/scheduler.py` | Production feed/worker code (scheduler); advisory synchronization and scheduled work have not moved from Python. |
| `app/jobs/tasks.py` | Production feed/worker code (tasks); advisory synchronization and scheduled work have not moved from Python. |
| `app/logging_config.py` | Legacy application runtime/infrastructure (logging config); required by remaining FastAPI routes, persistence, auth, or workers. |
| `app/mail.py` | Legacy application runtime/infrastructure (mail); required by remaining FastAPI routes, persistence, auth, or workers. |
| `app/main.py` | Legacy application runtime/infrastructure (main); required by remaining FastAPI routes, persistence, auth, or workers. |
| `app/manage.py` | Legacy application runtime/infrastructure (manage); required by remaining FastAPI routes, persistence, auth, or workers. |
| `app/markdown.py` | Legacy application runtime/infrastructure (markdown); required by remaining FastAPI routes, persistence, auth, or workers. |
| `app/models.py` | Legacy application runtime/infrastructure (models); required by remaining FastAPI routes, persistence, auth, or workers. |
| `app/routes/__init__.py` | FastAPI route module (  init  ); still reachable through the Next.js fallback or standalone legacy deployment. |
| `app/routes/api.py` | FastAPI route module (api); still reachable through the Next.js fallback or standalone legacy deployment. |
| `app/routes/api_account.py` | FastAPI route module (api account); still reachable through the Next.js fallback or standalone legacy deployment. |
| `app/routes/billing.py` | FastAPI route module (billing); still reachable through the Next.js fallback or standalone legacy deployment. |
| `app/routes/cli_auth.py` | FastAPI route module (cli auth); still reachable through the Next.js fallback or standalone legacy deployment. |
| `app/routes/events.py` | FastAPI route module (events); still reachable through the Next.js fallback or standalone legacy deployment. |
| `app/routes/frontend.py` | FastAPI route module (frontend); still reachable through the Next.js fallback or standalone legacy deployment. |
| `app/routes/health.py` | FastAPI route module (health); still reachable through the Next.js fallback or standalone legacy deployment. |
| `app/routes/internal_admin.py` | FastAPI route module (internal admin); still reachable through the Next.js fallback or standalone legacy deployment. |
| `app/routes/internal_alerts.py` | FastAPI route module (internal alerts); still reachable through the Next.js fallback or standalone legacy deployment. |
| `app/routes/internal_auth.py` | FastAPI route module (internal auth); still reachable through the Next.js fallback or standalone legacy deployment. |
| `app/routes/internal_auth_actions.py` | FastAPI route module (internal auth actions); still reachable through the Next.js fallback or standalone legacy deployment. |
| `app/routes/internal_cli_auth.py` | FastAPI route module (internal cli auth); still reachable through the Next.js fallback or standalone legacy deployment. |
| `app/routes/internal_dashboard.py` | FastAPI route module (internal dashboard); still reachable through the Next.js fallback or standalone legacy deployment. |
| `app/routes/internal_findings.py` | FastAPI route module (internal findings); still reachable through the Next.js fallback or standalone legacy deployment. |
| `app/routes/internal_marketing.py` | FastAPI route module (internal marketing); still reachable through the Next.js fallback or standalone legacy deployment. |
| `app/routes/internal_profiles.py` | FastAPI route module (internal profiles); still reachable through the Next.js fallback or standalone legacy deployment. |
| `app/routes/internal_projects.py` | FastAPI route module (internal projects); still reachable through the Next.js fallback or standalone legacy deployment. |
| `app/routes/internal_public.py` | FastAPI route module (internal public); still reachable through the Next.js fallback or standalone legacy deployment. |
| `app/routes/internal_settings.py` | FastAPI route module (internal settings); still reachable through the Next.js fallback or standalone legacy deployment. |
| `app/routes/pages.py` | FastAPI route module (pages); still reachable through the Next.js fallback or standalone legacy deployment. |
| `app/routes/targets.py` | FastAPI route module (targets); still reachable through the Next.js fallback or standalone legacy deployment. |
| `app/schemas.py` | Legacy application runtime/infrastructure (schemas); required by remaining FastAPI routes, persistence, auth, or workers. |
| `app/security.py` | Legacy application runtime/infrastructure (security); required by remaining FastAPI routes, persistence, auth, or workers. |
| `app/services/__init__.py` | Legacy product service (  init  ); Next.js has no equivalent implementation yet. |
| `app/services/admin_service.py` | Legacy product service (admin service); Next.js has no equivalent implementation yet. |
| `app/services/alert_service.py` | Legacy product service (alert service); Next.js has no equivalent implementation yet. |
| `app/services/api_key_service.py` | Legacy product service (api key service); Next.js has no equivalent implementation yet. |
| `app/services/auth_service.py` | Legacy product service (auth service); Next.js has no equivalent implementation yet. |
| `app/services/backup_service.py` | Legacy product service (backup service); Next.js has no equivalent implementation yet. |
| `app/services/bootstrap_service.py` | Legacy product service (bootstrap service); Next.js has no equivalent implementation yet. |
| `app/services/challenge_service.py` | Legacy product service (challenge service); Next.js has no equivalent implementation yet. |
| `app/services/cli_auth_service.py` | Legacy product service (cli auth service); Next.js has no equivalent implementation yet. |
| `app/services/cli_release_service.py` | Legacy product service (cli release service); Next.js has no equivalent implementation yet. |
| `app/services/contact_service.py` | Legacy product service (contact service); Next.js has no equivalent implementation yet. |
| `app/services/discord_service.py` | Legacy product service (discord service); Next.js has no equivalent implementation yet. |
| `app/services/docs_service.py` | Legacy product service (docs service); Next.js has no equivalent implementation yet. |
| `app/services/email_service.py` | Legacy product service (email service); Next.js has no equivalent implementation yet. |
| `app/services/engine_client.py` | Legacy product service (engine client); Next.js has no equivalent implementation yet. |
| `app/services/feed_service.py` | Legacy product service (feed service); Next.js has no equivalent implementation yet. |
| `app/services/finding_service.py` | Legacy product service (finding service); Next.js has no equivalent implementation yet. |
| `app/services/login_flow.py` | Legacy product service (login flow); Next.js has no equivalent implementation yet. |
| `app/services/mirror_service.py` | Legacy product service (mirror service); Next.js has no equivalent implementation yet. |
| `app/services/organisation_service.py` | Legacy product service (organisation service); Next.js has no equivalent implementation yet. |
| `app/services/package_metadata_service.py` | Legacy product service (package metadata service); Next.js has no equivalent implementation yet. |
| `app/services/password_reset_service.py` | Legacy product service (password reset service); Next.js has no equivalent implementation yet. |
| `app/services/plan_service.py` | Legacy product service (plan service); Next.js has no equivalent implementation yet. |
| `app/services/profile_service.py` | Legacy product service (profile service); Next.js has no equivalent implementation yet. |
| `app/services/public_service.py` | Legacy product service (public service); Next.js has no equivalent implementation yet. |
| `app/services/rate_limit_service.py` | Legacy product service (rate limit service); Next.js has no equivalent implementation yet. |
| `app/services/rules_service.py` | Legacy product service (rules service); Next.js has no equivalent implementation yet. |
| `app/services/scan_service.py` | Legacy product service (scan service); Next.js has no equivalent implementation yet. |
| `app/services/status_service.py` | Legacy product service (status service); Next.js has no equivalent implementation yet. |
| `app/services/supply_chain_service.py` | Legacy product service (supply chain service); Next.js has no equivalent implementation yet. |
| `app/services/target_service.py` | Legacy product service (target service); Next.js has no equivalent implementation yet. |
| `app/services/twofactor_service.py` | Legacy product service (twofactor service); Next.js has no equivalent implementation yet. |
| `app/templating.py` | Legacy application runtime/infrastructure (templating); required by remaining FastAPI routes, persistence, auth, or workers. |
| `app/tiers.py` | Legacy application runtime/infrastructure (tiers); required by remaining FastAPI routes, persistence, auth, or workers. |
| `engine/parity/python_reference.py` | Cross-language oracle for the Python-to-Go parity gate; removable only after the legacy detector is retired. |
| `migrations/env.py` | Alembic runtime; still owns schema migration execution. |
| `migrations/versions/018ca2ca7edd_an_account_can_say_it_is_a_company.py` | Alembic production schema history; still authoritative because no Next.js migration baseline exists. |
| `migrations/versions/05b0a721210d_retire_the_per_scan_osv_feed_row.py` | Alembic production schema history; still authoritative because no Next.js migration baseline exists. |
| `migrations/versions/32f55890a455_cli_tokens_and_browser_auth_requests.py` | Alembic production schema history; still authoritative because no Next.js migration baseline exists. |
| `migrations/versions/333b8ef89e52_supply_chain_findings.py` | Alembic production schema history; still authoritative because no Next.js migration baseline exists. |
| `migrations/versions/3e9a08c91352_ignore_rules_may_name_a_package_glob.py` | Alembic production schema history; still authoritative because no Next.js migration baseline exists. |
| `migrations/versions/532470ebf4cf_epss_threshold_per_project.py` | Alembic production schema history; still authoritative because no Next.js migration baseline exists. |
| `migrations/versions/5ae6a2cbd2e4_admin_panel_roles_suspension_audit_log_.py` | Alembic production schema history; still authoritative because no Next.js migration baseline exists. |
| `migrations/versions/5b6abb9b9d05_password_reset_tokens.py` | Alembic production schema history; still authoritative because no Next.js migration baseline exists. |
| `migrations/versions/612f3ce3d895_epss_scores.py` | Alembic production schema history; still authoritative because no Next.js migration baseline exists. |
| `migrations/versions/873af9624f02_custom_scan_rules.py` | Alembic production schema history; still authoritative because no Next.js migration baseline exists. |
| `migrations/versions/879cd92fe4fc_discord_webhook_per_project.py` | Alembic production schema history; still authoritative because no Next.js migration baseline exists. |
| `migrations/versions/8bd959484f85_unreached_by_depth_on_target.py` | Alembic production schema history; still authoritative because no Next.js migration baseline exists. |
| `migrations/versions/98c5f99708ab_initial_schema.py` | Alembic production schema history; still authoritative because no Next.js migration baseline exists. |
| `migrations/versions/a1c4f7e2d9b3_manifests_as_rows.py` | Alembic production schema history; still authoritative because no Next.js migration baseline exists. |
| `migrations/versions/a2bfb3b26c6f_local_advisory_mirror_index_cwe_ids_api_.py` | Alembic production schema history; still authoritative because no Next.js migration baseline exists. |
| `migrations/versions/a4d72e18b3c9_two_factor_and_api_key_usage.py` | Alembic production schema history; still authoritative because no Next.js migration baseline exists. |
| `migrations/versions/b0684ece8758_package_metadata_cache.py` | Alembic production schema history; still authoritative because no Next.js migration baseline exists. |
| `migrations/versions/b152c68c5330_named_rule_profiles.py` | Alembic production schema history; still authoritative because no Next.js migration baseline exists. |
| `migrations/versions/b24fbb9a6b66_doc_pages.py` | Alembic production schema history; still authoritative because no Next.js migration baseline exists. |
| `migrations/versions/b7d3e91a4c62_dev_severity_floor.py` | Alembic production schema history; still authoritative because no Next.js migration baseline exists. |
| `migrations/versions/c16703f455a3_migrate_billing_from_paddle_to_dodo.py` | Alembic production schema history; still authoritative because no Next.js migration baseline exists. |
| `migrations/versions/c4a9b8d7e6f5_automated_reachability_and_filtered_status.py` | Alembic production schema history; still authoritative because no Next.js migration baseline exists. |
| `migrations/versions/d3c81f0a94e2_rate_limit_hits.py` | Alembic production schema history; still authoritative because no Next.js migration baseline exists. |
| `migrations/versions/e48a017523ca_api_key_scopes.py` | Alembic production schema history; still authoritative because no Next.js migration baseline exists. |
| `migrations/versions/e618eaa6adf2_dependency_depth_and_chain.py` | Alembic production schema history; still authoritative because no Next.js migration baseline exists. |
| `migrations/versions/e7a4c9b21d05_drop_github_oauth_column.py` | Alembic production schema history; still authoritative because no Next.js migration baseline exists. |
| `migrations/versions/ea9a156007b5_webhook_kind.py` | Alembic production schema history; still authoritative because no Next.js migration baseline exists. |
| `migrations/versions/f1058721df2f_contact_messages_and_email_log.py` | Alembic production schema history; still authoritative because no Next.js migration baseline exists. |
| `migrations/versions/f1e6b90c4a72_projects_without_a_manifest.py` | Alembic production schema history; still authoritative because no Next.js migration baseline exists. |
| `scripts/s3_upload.py` | Backup upload helper called by scripts/backup.sh; no non-Python replacement exists. |
| `scripts/sync_cli.py` | CLI source synchronization helper; no non-Python replacement exists. |
| `tests/__init__.py` | Legacy regression coverage (  init  ); required while the corresponding Python route/service or compatibility deployment remains. |
| `tests/conftest.py` | Legacy regression coverage (conftest); required while the corresponding Python route/service or compatibility deployment remains. |
| `tests/factories.py` | Legacy regression coverage (factories); required while the corresponding Python route/service or compatibility deployment remains. |
| `tests/test_account_api.py` | Legacy regression coverage (test account api); required while the corresponding Python route/service or compatibility deployment remains. |
| `tests/test_admin_access.py` | Legacy regression coverage (test admin access); required while the corresponding Python route/service or compatibility deployment remains. |
| `tests/test_admin_actions.py` | Legacy regression coverage (test admin actions); required while the corresponding Python route/service or compatibility deployment remains. |
| `tests/test_admin_api.py` | Legacy regression coverage (test admin api); required while the corresponding Python route/service or compatibility deployment remains. |
| `tests/test_admin_delete.py` | Legacy regression coverage (test admin delete); required while the corresponding Python route/service or compatibility deployment remains. |
| `tests/test_admin_email.py` | Legacy regression coverage (test admin email); required while the corresponding Python route/service or compatibility deployment remains. |
| `tests/test_admin_inputs.py` | Legacy regression coverage (test admin inputs); required while the corresponding Python route/service or compatibility deployment remains. |
| `tests/test_api.py` | Legacy regression coverage (test api); required while the corresponding Python route/service or compatibility deployment remains. |
| `tests/test_auth.py` | Legacy regression coverage (test auth); required while the corresponding Python route/service or compatibility deployment remains. |
| `tests/test_backup.py` | Legacy regression coverage (test backup); required while the corresponding Python route/service or compatibility deployment remains. |
| `tests/test_billing.py` | Legacy regression coverage (test billing); required while the corresponding Python route/service or compatibility deployment remains. |
| `tests/test_bootstrap_admin.py` | Legacy regression coverage (test bootstrap admin); required while the corresponding Python route/service or compatibility deployment remains. |
| `tests/test_cli_auth.py` | Legacy regression coverage (test cli auth); required while the corresponding Python route/service or compatibility deployment remains. |
| `tests/test_cli_page.py` | Legacy regression coverage (test cli page); required while the corresponding Python route/service or compatibility deployment remains. |
| `tests/test_contact.py` | Legacy regression coverage (test contact); required while the corresponding Python route/service or compatibility deployment remains. |
| `tests/test_cvss.py` | Legacy regression coverage (test cvss); required while the corresponding Python route/service or compatibility deployment remains. |
| `tests/test_design_system.py` | Legacy regression coverage (test design system); required while the corresponding Python route/service or compatibility deployment remains. |
| `tests/test_dev_threshold.py` | Legacy regression coverage (test dev threshold); required while the corresponding Python route/service or compatibility deployment remains. |
| `tests/test_discord.py` | Legacy regression coverage (test discord); required while the corresponding Python route/service or compatibility deployment remains. |
| `tests/test_docs.py` | Legacy regression coverage (test docs); required while the corresponding Python route/service or compatibility deployment remains. |
| `tests/test_engine_client.py` | Legacy regression coverage (test engine client); required while the corresponding Python route/service or compatibility deployment remains. |
| `tests/test_epss.py` | Legacy regression coverage (test epss); required while the corresponding Python route/service or compatibility deployment remains. |
| `tests/test_feeds.py` | Legacy regression coverage (test feeds); required while the corresponding Python route/service or compatibility deployment remains. |
| `tests/test_frontend_production.py` | Legacy regression coverage (test frontend production); required while the corresponding Python route/service or compatibility deployment remains. |
| `tests/test_ignore_patterns.py` | Legacy regression coverage (test ignore patterns); required while the corresponding Python route/service or compatibility deployment remains. |
| `tests/test_internal_alerts.py` | Legacy regression coverage (test internal alerts); required while the corresponding Python route/service or compatibility deployment remains. |
| `tests/test_internal_auth.py` | Legacy regression coverage (test internal auth); required while the corresponding Python route/service or compatibility deployment remains. |
| `tests/test_internal_auth_actions.py` | Legacy regression coverage (test internal auth actions); required while the corresponding Python route/service or compatibility deployment remains. |
| `tests/test_internal_dashboard.py` | Legacy regression coverage (test internal dashboard); required while the corresponding Python route/service or compatibility deployment remains. |
| `tests/test_internal_findings.py` | Legacy regression coverage (test internal findings); required while the corresponding Python route/service or compatibility deployment remains. |
| `tests/test_internal_projects.py` | Legacy regression coverage (test internal projects); required while the corresponding Python route/service or compatibility deployment remains. |
| `tests/test_internal_settings.py` | Legacy regression coverage (test internal settings); required while the corresponding Python route/service or compatibility deployment remains. |
| `tests/test_landing.py` | Legacy regression coverage (test landing); required while the corresponding Python route/service or compatibility deployment remains. |
| `tests/test_legal_pages.py` | Legacy regression coverage (test legal pages); required while the corresponding Python route/service or compatibility deployment remains. |
| `tests/test_logging_hygiene.py` | Legacy regression coverage (test logging hygiene); required while the corresponding Python route/service or compatibility deployment remains. |
| `tests/test_malicious_packages.py` | Legacy regression coverage (test malicious packages); required while the corresponding Python route/service or compatibility deployment remains. |
| `tests/test_manifests.py` | Legacy regression coverage (test manifests); required while the corresponding Python route/service or compatibility deployment remains. |
| `tests/test_manifests_rust_jvm.py` | Legacy regression coverage (test manifests rust jvm); required while the corresponding Python route/service or compatibility deployment remains. |
| `tests/test_matching.py` | Legacy regression coverage (test matching); required while the corresponding Python route/service or compatibility deployment remains. |
| `tests/test_mirror.py` | Legacy regression coverage (test mirror); required while the corresponding Python route/service or compatibility deployment remains. |
| `tests/test_multi_manifest.py` | Legacy regression coverage (test multi manifest); required while the corresponding Python route/service or compatibility deployment remains. |
| `tests/test_organisation_accounts.py` | Legacy regression coverage (test organisation accounts); required while the corresponding Python route/service or compatibility deployment remains. |
| `tests/test_osv_normalize.py` | Legacy regression coverage (test osv normalize); required while the corresponding Python route/service or compatibility deployment remains. |
| `tests/test_package_metadata.py` | Legacy regression coverage (test package metadata); required while the corresponding Python route/service or compatibility deployment remains. |
| `tests/test_password_reset.py` | Legacy regression coverage (test password reset); required while the corresponding Python route/service or compatibility deployment remains. |
| `tests/test_plan_changes_take_effect.py` | Legacy regression coverage (test plan changes take effect); required while the corresponding Python route/service or compatibility deployment remains. |
| `tests/test_production_config.py` | Legacy regression coverage (test production config); required while the corresponding Python route/service or compatibility deployment remains. |
| `tests/test_rate_limiting.py` | Legacy regression coverage (test rate limiting); required while the corresponding Python route/service or compatibility deployment remains. |
| `tests/test_reachability.py` | Legacy regression coverage (test reachability); required while the corresponding Python route/service or compatibility deployment remains. |
| `tests/test_route_authorization.py` | Legacy regression coverage (test route authorization); required while the corresponding Python route/service or compatibility deployment remains. |
| `tests/test_routes.py` | Legacy regression coverage (test routes); required while the corresponding Python route/service or compatibility deployment remains. |
| `tests/test_rule_profiles.py` | Legacy regression coverage (test rule profiles); required while the corresponding Python route/service or compatibility deployment remains. |
| `tests/test_scan_depth.py` | Legacy regression coverage (test scan depth); required while the corresponding Python route/service or compatibility deployment remains. |
| `tests/test_scan_pipeline.py` | Legacy regression coverage (test scan pipeline); required while the corresponding Python route/service or compatibility deployment remains. |
| `tests/test_scan_rules.py` | Legacy regression coverage (test scan rules); required while the corresponding Python route/service or compatibility deployment remains. |
| `tests/test_sessions_and_theme.py` | Legacy regression coverage (test sessions and theme); required while the corresponding Python route/service or compatibility deployment remains. |
| `tests/test_status_page.py` | Legacy regression coverage (test status page); required while the corresponding Python route/service or compatibility deployment remains. |
| `tests/test_theme_scope.py` | Legacy regression coverage (test theme scope); required while the corresponding Python route/service or compatibility deployment remains. |
| `tests/test_tier_gating_audit.py` | Legacy regression coverage (test tier gating audit); required while the corresponding Python route/service or compatibility deployment remains. |
| `tests/test_tiers.py` | Legacy regression coverage (test tiers); required while the corresponding Python route/service or compatibility deployment remains. |
| `tests/test_two_factor.py` | Legacy regression coverage (test two factor); required while the corresponding Python route/service or compatibility deployment remains. |
| `tests/test_typosquat.py` | Legacy regression coverage (test typosquat); required while the corresponding Python route/service or compatibility deployment remains. |
| `tests/test_versions.py` | Legacy regression coverage (test versions); required while the corresponding Python route/service or compatibility deployment remains. |
| `tests/test_worker_resilience.py` | Legacy regression coverage (test worker resilience); required while the corresponding Python route/service or compatibility deployment remains. |

## Required removal order

1. Move every route and product service into Next.js with compatibility tests.
2. Move advisory synchronization and scheduled jobs to non-Python services.
3. Make Go authoritative for scans and reconcile findings/history through Next.js.
4. Establish and verify a non-Alembic migration baseline against production-shaped data.
5. Remove the fallback rewrite and Python services from every Docker/Compose deployment.
6. Delete Python runtime code, tests, migrations, packaging, dependencies, and CI steps in one reviewed cutover.
7. Assert that `git ls-files "*.py"` returns no files and that all web, engine, integration, deployment, and data-migration tests pass.
