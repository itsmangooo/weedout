"""Upstream feed clients: CISA KEV and OSV.dev."""

from __future__ import annotations

import httpx
import pytest
import respx

from app.feeds.kev import KevClient, KevFeedError, parse_kev_payload
from app.feeds.osv import OSVClient, OSVError
from tests.factories import dep

KEV_URL = "https://www.cisa.gov/kev.json"
OSV_BASE = "https://api.osv.dev"

KEV_PAYLOAD = {
    "title": "CISA Catalog of Known Exploited Vulnerabilities",
    "catalogVersion": "2024.01.15",
    "count": 2,
    "vulnerabilities": [
        {
            "cveID": "CVE-2021-44228",
            "vendorProject": "Apache",
            "product": "Log4j2",
            "vulnerabilityName": "Apache Log4j2 Remote Code Execution Vulnerability",
            "dateAdded": "2021-12-10",
            "shortDescription": "Apache Log4j2 contains a vulnerability...",
            "requiredAction": "Apply updates per vendor instructions.",
            "dueDate": "2021-12-24",
            "knownRansomwareCampaignUse": "Known",
        },
        {
            "cveID": "cve-2020-8203",
            "vendorProject": "Lodash",
            "product": "lodash",
            "vulnerabilityName": "Prototype pollution",
            "dateAdded": "2022-05-03",
            "shortDescription": "Prototype pollution.",
            "requiredAction": "Apply updates.",
            "dueDate": "2022-05-24",
            "knownRansomwareCampaignUse": "Unknown",
        },
    ],
}


class TestParseKevPayload:
    def test_parses_entries(self):
        catalog = parse_kev_payload(KEV_PAYLOAD)
        assert len(catalog) == 2
        assert catalog.catalog_version == "2024.01.15"

    def test_cve_ids_are_uppercased(self):
        catalog = parse_kev_payload(KEV_PAYLOAD)
        assert "CVE-2020-8203" in catalog.cve_ids

    def test_ransomware_flag_is_derived_from_the_known_string(self):
        entries = {e.cve_id: e for e in parse_kev_payload(KEV_PAYLOAD).entries}
        assert entries["CVE-2021-44228"].known_ransomware_use is True
        assert entries["CVE-2020-8203"].known_ransomware_use is False

    def test_dates_are_parsed(self):
        entries = {e.cve_id: e for e in parse_kev_payload(KEV_PAYLOAD).entries}
        assert entries["CVE-2021-44228"].date_added.isoformat() == "2021-12-10"
        assert entries["CVE-2021-44228"].due_date.isoformat() == "2021-12-24"

    def test_rows_without_a_cve_id_are_skipped(self):
        payload = {
            "vulnerabilities": [
                {"vendorProject": "x"},  # no cveID — nothing to join on
                {"cveID": "CVE-2000-0001"},
            ]
        }
        assert len(parse_kev_payload(payload)) == 1

    def test_malformed_dates_do_not_raise(self):
        payload = {"vulnerabilities": [{"cveID": "CVE-2000-0001", "dateAdded": "not-a-date"}]}
        assert parse_kev_payload(payload).entries[0].date_added is None

    def test_missing_vulnerabilities_array_raises(self):
        with pytest.raises(KevFeedError):
            parse_kev_payload({"title": "x"})

    def test_empty_catalog_raises_rather_than_wiping_the_signal(self):
        # An empty KEV set would silently demote every exploited finding to
        # ordinary severity triage, so it must be treated as a fetch failure.
        with pytest.raises(KevFeedError):
            parse_kev_payload({"vulnerabilities": []})


class TestKevClient:
    @respx.mock
    async def test_fetches_and_parses(self):
        respx.get(KEV_URL).mock(return_value=httpx.Response(200, json=KEV_PAYLOAD))
        async with KevClient(feed_url=KEV_URL) as client:
            catalog = await client.fetch()
        assert len(catalog) == 2

    @respx.mock
    async def test_http_error_raises_kev_feed_error(self):
        respx.get(KEV_URL).mock(return_value=httpx.Response(503))
        async with KevClient(feed_url=KEV_URL) as client:
            with pytest.raises(KevFeedError, match="503"):
                await client.fetch()

    @respx.mock
    async def test_invalid_json_raises_kev_feed_error(self):
        respx.get(KEV_URL).mock(return_value=httpx.Response(200, text="<html>nope</html>"))
        async with KevClient(feed_url=KEV_URL) as client:
            with pytest.raises(KevFeedError):
                await client.fetch()

    @respx.mock
    async def test_connection_error_raises_kev_feed_error(self):
        respx.get(KEV_URL).mock(side_effect=httpx.ConnectError("no route"))
        async with KevClient(feed_url=KEV_URL) as client:
            with pytest.raises(KevFeedError):
                await client.fetch()

    async def test_must_be_used_as_a_context_manager(self):
        with pytest.raises(RuntimeError):
            await KevClient(feed_url=KEV_URL).fetch()


class TestOSVClient:
    @respx.mock
    async def test_query_batch_associates_results_with_packages(self):
        deps = [dep(name="a", version="1.0.0"), dep(name="b", version="2.0.0")]
        respx.post(f"{OSV_BASE}/v1/querybatch").mock(
            return_value=httpx.Response(
                200,
                json={"results": [{"vulns": [{"id": "GHSA-a"}]}, {}]},
            )
        )
        async with OSVClient(api_url=OSV_BASE) as client:
            results = await client.query_batch(deps)

        assert results == {deps[0].key: ["GHSA-a"]}

    @respx.mock
    async def test_mismatched_result_count_is_rejected(self):
        # Results are positional. Pairing a package with another package's
        # advisories would be worse than failing.
        deps = [dep(name="a"), dep(name="b")]
        respx.post(f"{OSV_BASE}/v1/querybatch").mock(
            return_value=httpx.Response(200, json={"results": [{"vulns": []}]})
        )
        async with OSVClient(api_url=OSV_BASE) as client:
            with pytest.raises(OSVError, match="cannot safely associate"):
                await client.query_batch(deps)

    @respx.mock
    async def test_missing_results_key_is_rejected(self):
        respx.post(f"{OSV_BASE}/v1/querybatch").mock(
            return_value=httpx.Response(200, json={"unexpected": []})
        )
        async with OSVClient(api_url=OSV_BASE) as client:
            with pytest.raises(OSVError):
                await client.query_batch([dep()])

    async def test_empty_dependency_list_makes_no_request(self):
        async with OSVClient(api_url=OSV_BASE) as client:
            assert await client.query_batch([]) == {}

    @respx.mock
    async def test_large_dependency_lists_are_chunked(self):
        from app.feeds.osv import BATCH_SIZE

        deps = [dep(name=f"pkg-{i}", version="1.0.0") for i in range(BATCH_SIZE + 5)]

        def respond(request: httpx.Request) -> httpx.Response:
            import json

            count = len(json.loads(request.content)["queries"])
            return httpx.Response(200, json={"results": [{} for _ in range(count)]})

        route = respx.post(f"{OSV_BASE}/v1/querybatch").mock(side_effect=respond)
        async with OSVClient(api_url=OSV_BASE) as client:
            await client.query_batch(deps)

        assert route.call_count == 2

    @respx.mock
    async def test_get_vulnerability_normalises_the_record(self):
        respx.get(f"{OSV_BASE}/v1/vulns/GHSA-x").mock(
            return_value=httpx.Response(
                200,
                json={
                    "id": "GHSA-x",
                    "aliases": ["CVE-2020-1111"],
                    "affected": [
                        {
                            "package": {"ecosystem": "npm", "name": "x"},
                            "ranges": [
                                {
                                    "type": "SEMVER",
                                    "events": [{"introduced": "0"}, {"fixed": "2.0.0"}],
                                }
                            ],
                        }
                    ],
                },
            )
        )
        async with OSVClient(api_url=OSV_BASE) as client:
            vuln = await client.get_vulnerability("GHSA-x")

        assert vuln.id == "GHSA-x"
        assert vuln.cve_ids == ("CVE-2020-1111",)

    @respx.mock
    async def test_unknown_advisory_returns_none_rather_than_failing_the_scan(self):
        respx.get(f"{OSV_BASE}/v1/vulns/GHSA-gone").mock(return_value=httpx.Response(404))
        async with OSVClient(api_url=OSV_BASE) as client:
            assert await client.get_vulnerability("GHSA-gone") is None

    @respx.mock
    async def test_one_failing_detail_does_not_lose_the_others(self):
        respx.get(f"{OSV_BASE}/v1/vulns/GHSA-ok").mock(
            return_value=httpx.Response(
                200,
                json={
                    "id": "GHSA-ok",
                    "affected": [
                        {
                            "package": {"ecosystem": "npm", "name": "x"},
                            "ranges": [{"type": "SEMVER", "events": [{"introduced": "0"}]}],
                        }
                    ],
                },
            )
        )
        respx.get(f"{OSV_BASE}/v1/vulns/GHSA-bad").mock(return_value=httpx.Response(404))

        async with OSVClient(api_url=OSV_BASE) as client:
            fetched = await client.get_vulnerabilities(["GHSA-ok", "GHSA-bad"])

        assert set(fetched) == {"GHSA-ok"}

    @respx.mock
    async def test_server_errors_are_retried(self):
        route = respx.post(f"{OSV_BASE}/v1/querybatch").mock(
            side_effect=[
                httpx.Response(500),
                httpx.Response(200, json={"results": [{"vulns": [{"id": "GHSA-a"}]}]}),
            ]
        )
        async with OSVClient(api_url=OSV_BASE) as client:
            results = await client.query_batch([dep(name="a")])

        assert route.call_count == 2
        assert results

    @respx.mock
    async def test_client_errors_are_not_retried(self):
        # A 400 will not become correct by being repeated.
        route = respx.post(f"{OSV_BASE}/v1/querybatch").mock(return_value=httpx.Response(400))
        async with OSVClient(api_url=OSV_BASE) as client:
            with pytest.raises(OSVError):
                await client.query_batch([dep(name="a")])

        assert route.call_count == 1

    async def test_must_be_used_as_a_context_manager(self):
        with pytest.raises(RuntimeError):
            await OSVClient(api_url=OSV_BASE).query_batch([dep()])
