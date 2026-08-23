"""Rust and JVM manifest parsing.

The two properties worth guarding, in order of how badly they fail:

1. A version the scanner cannot compare is reported as *not affected* — so a
   version scheme it does not understand makes vulnerable projects look clean.
   Maven's scheme is not semver and this is where that is pinned.
2. A dependency skipped for a good reason must say so. These parsers refuse to
   guess at Maven ranges and unresolved properties, and a silent skip would
   turn "we could not check this" into "this is fine".
"""

from __future__ import annotations

import pytest

from app.core.manifests import ManifestParseError, detect_manifest_kind, parse_manifest
from app.core.types import AffectedPackage, AffectedRange, Ecosystem, ManifestKind, Reachability
from app.core.versions import compare, version_matches

CARGO_LOCK = """\
version = 3

[[package]]
name = "my-app"
version = "0.1.0"
dependencies = ["serde", "tokio"]

[[package]]
name = "serde"
version = "1.0.100"
source = "registry+https://github.com/rust-lang/crates.io-index"

[[package]]
name = "tokio"
version = "1.20.0"
source = "registry+https://github.com/rust-lang/crates.io-index"
dependencies = ["mio 0.8.0"]

[[package]]
name = "mio"
version = "0.8.0"
source = "registry+https://github.com/rust-lang/crates.io-index"
"""

POM = """<?xml version="1.0" encoding="UTF-8"?>
<project xmlns="http://maven.apache.org/POM/4.0.0">
  <groupId>com.example</groupId>
  <artifactId>store-api</artifactId>
  <version>1.0.0</version>
  <properties>
    <spring.version>5.3.20</spring.version>
  </properties>
  <dependencyManagement>
    <dependencies>
      <dependency>
        <groupId>com.google.guava</groupId>
        <artifactId>guava</artifactId>
        <version>31.1-jre</version>
      </dependency>
    </dependencies>
  </dependencyManagement>
  <dependencies>
    <dependency>
      <groupId>org.springframework</groupId>
      <artifactId>spring-core</artifactId>
      <version>${spring.version}</version>
    </dependency>
    <dependency>
      <groupId>com.google.guava</groupId>
      <artifactId>guava</artifactId>
    </dependency>
    <dependency>
      <groupId>junit</groupId>
      <artifactId>junit</artifactId>
      <version>4.13.2</version>
      <scope>test</scope>
    </dependency>
    <dependency>
      <groupId>jakarta.servlet</groupId>
      <artifactId>jakarta.servlet-api</artifactId>
      <version>5.0.0</version>
      <scope>provided</scope>
    </dependency>
  </dependencies>
</project>
"""

GRADLE = """\
# This is a Gradle generated file for dependency locking.
# Manual edits can break the build and are not advised.
com.fasterxml.jackson.core:jackson-databind:2.13.0=compileClasspath,runtimeClasspath
org.junit.jupiter:junit-jupiter:5.8.2=testCompileClasspath,testRuntimeClasspath
com.puppycrawl.tools:checkstyle:9.3=checkstyle
empty=annotationProcessor
"""

SBT_LOCK = """\
{
  "lockVersion": 1,
  "dependencies": [
    {"org": "org.typelevel", "name": "cats-core_2.13", "version": "2.7.0",
     "configurations": ["compile"]},
    {"org": "org.scalatest", "name": "scalatest_2.13", "version": "3.2.11",
     "configurations": ["test"]}
  ]
}
"""


class TestDetection:
    @pytest.mark.parametrize(
        ("filename", "content", "expected"),
        [
            ("Cargo.lock", CARGO_LOCK, ManifestKind.CARGO_LOCK),
            ("pom.xml", POM, ManifestKind.POM_XML),
            ("gradle.lockfile", GRADLE, ManifestKind.GRADLE_LOCKFILE),
            ("settings-gradle.lockfile", GRADLE, ManifestKind.GRADLE_LOCKFILE),
            ("build.sbt.lock", SBT_LOCK, ManifestKind.SBT_LOCK),
            ("backend/Cargo.lock", CARGO_LOCK, ManifestKind.CARGO_LOCK),
        ],
    )
    def test_by_name(self, filename, content, expected):
        assert detect_manifest_kind(filename, content) is expected

    def test_cargo_is_recognised_from_content_when_renamed(self):
        assert detect_manifest_kind("locked.txt.bak", CARGO_LOCK) is ManifestKind.CARGO_LOCK

    def test_a_pom_is_recognised_from_its_xml(self):
        assert detect_manifest_kind("unknown", POM) is ManifestKind.POM_XML

    def test_unrelated_xml_is_not_taken_for_a_pom(self):
        assert detect_manifest_kind("data.xml", "<?xml version='1.0'?><catalog/>") is None


class TestCargoLock:
    def test_the_workspace_crate_is_not_reported_as_its_own_dependency(self):
        parsed = parse_manifest(ManifestKind.CARGO_LOCK, CARGO_LOCK)

        assert parsed.project_name == "my-app"
        assert "my-app" not in {d.name for d in parsed.dependencies}

    def test_direct_and_transitive_are_told_apart(self):
        parsed = parse_manifest(ManifestKind.CARGO_LOCK, CARGO_LOCK)
        by_name = {d.name: d for d in parsed.dependencies}

        assert by_name["serde"].reachability is Reachability.RUNTIME_DIRECT
        assert by_name["tokio"].reachability is Reachability.RUNTIME_DIRECT
        # Pulled in by tokio, not asked for by the project.
        assert by_name["mio"].reachability is Reachability.RUNTIME_TRANSITIVE

    def test_versions_are_exact(self):
        parsed = parse_manifest(ManifestKind.CARGO_LOCK, CARGO_LOCK)

        assert all(d.version_exact for d in parsed.dependencies)
        assert all(d.ecosystem is Ecosystem.CRATES_IO for d in parsed.dependencies)

    def test_malformed_toml_is_refused_rather_than_half_read(self):
        with pytest.raises(ManifestParseError, match="valid TOML"):
            parse_manifest(ManifestKind.CARGO_LOCK, "[[package]\nname =")


class TestPom:
    def test_a_property_version_is_resolved(self):
        parsed = parse_manifest(ManifestKind.POM_XML, POM)
        by_name = {d.name: d for d in parsed.dependencies}

        assert by_name["org.springframework:spring-core"].version == "5.3.20"

    def test_a_version_from_dependency_management_is_applied(self):
        parsed = parse_manifest(ManifestKind.POM_XML, POM)
        by_name = {d.name: d for d in parsed.dependencies}

        assert by_name["com.google.guava:guava"].version == "31.1-jre"

    def test_test_and_provided_scopes_do_not_ship(self):
        parsed = parse_manifest(ManifestKind.POM_XML, POM)
        by_name = {d.name: d for d in parsed.dependencies}

        assert by_name["junit:junit"].reachability is Reachability.DEV_ONLY
        assert by_name["jakarta.servlet:jakarta.servlet-api"].reachability is Reachability.DEV_ONLY

    def test_names_use_the_coordinate_osv_files_advisories_under(self):
        parsed = parse_manifest(ManifestKind.POM_XML, POM)

        assert all(":" in d.name for d in parsed.dependencies)

    @pytest.mark.parametrize(
        ("version", "expected_warning"),
        [
            ("", "parent or BOM"),
            ("${nowhere.version}", "not defined here"),
            ("[1.0,2.0)", "resolve at build time"),
        ],
    )
    def test_an_unresolvable_version_is_named_rather_than_guessed(self, version, expected_warning):
        """The dangerous alternative is inventing one. A made-up version
        checked against advisory ranges gives a confident wrong answer."""
        element = f"<version>{version}</version>" if version else ""
        pom = f"""<project xmlns="http://maven.apache.org/POM/4.0.0">
          <artifactId>x</artifactId>
          <dependencies><dependency>
            <groupId>org.example</groupId><artifactId>thing</artifactId>{element}
          </dependency></dependencies>
        </project>"""

        parsed = parse_manifest(ManifestKind.POM_XML, pom)

        assert parsed.dependencies == []
        assert any(expected_warning in w for w in parsed.warnings)

    def test_a_pom_is_not_treated_as_a_lockfile(self):
        """It states what was asked for, not what was installed."""
        assert ManifestKind.POM_XML.is_lockfile is False
        assert ManifestKind.GRADLE_LOCKFILE.is_lockfile is True

    def test_xml_that_is_not_a_pom_is_refused(self):
        with pytest.raises(ManifestParseError, match="not a Maven POM"):
            parse_manifest(ManifestKind.POM_XML, "<catalog><book/></catalog>")


class TestGradleLockfile:
    def test_coordinates_are_read_with_their_versions(self):
        parsed = parse_manifest(ManifestKind.GRADLE_LOCKFILE, GRADLE)
        by_name = {d.name: d for d in parsed.dependencies}

        assert by_name["com.fasterxml.jackson.core:jackson-databind"].version == "2.13.0"

    def test_a_test_only_classpath_is_dev_only(self):
        parsed = parse_manifest(ManifestKind.GRADLE_LOCKFILE, GRADLE)
        by_name = {d.name: d for d in parsed.dependencies}

        assert by_name["org.junit.jupiter:junit-jupiter"].reachability is Reachability.DEV_ONLY
        assert by_name["com.puppycrawl.tools:checkstyle"].reachability is Reachability.DEV_ONLY

    def test_appearing_on_any_runtime_classpath_means_it_ships(self):
        """Jackson is on a test classpath too. One runtime use is enough."""
        parsed = parse_manifest(ManifestKind.GRADLE_LOCKFILE, GRADLE)
        by_name = {d.name: d for d in parsed.dependencies}

        assert by_name["com.fasterxml.jackson.core:jackson-databind"].reachability is not (
            Reachability.DEV_ONLY
        )

    def test_the_empty_line_is_not_a_dependency(self):
        parsed = parse_manifest(ManifestKind.GRADLE_LOCKFILE, GRADLE)

        assert "empty" not in {d.name for d in parsed.dependencies}

    def test_a_file_with_no_coordinates_is_refused(self):
        with pytest.raises(ManifestParseError, match="Gradle lockfile"):
            parse_manifest(ManifestKind.GRADLE_LOCKFILE, "# nothing here\nempty=\n")


class TestSbtLock:
    def test_dependencies_are_read_as_maven_coordinates(self):
        parsed = parse_manifest(ManifestKind.SBT_LOCK, SBT_LOCK)
        by_name = {d.name: d for d in parsed.dependencies}

        assert "org.typelevel:cats-core_2.13" in by_name
        assert by_name["org.typelevel:cats-core_2.13"].ecosystem is Ecosystem.MAVEN

    def test_a_test_configuration_is_dev_only(self):
        parsed = parse_manifest(ManifestKind.SBT_LOCK, SBT_LOCK)
        by_name = {d.name: d for d in parsed.dependencies}

        assert by_name["org.scalatest:scalatest_2.13"].reachability is Reachability.DEV_ONLY

    def test_json_that_is_not_a_lock_is_refused(self):
        with pytest.raises(ManifestParseError, match="dependencies"):
            parse_manifest(ManifestKind.SBT_LOCK, '{"lockVersion": 1}')


class TestMavenVersionOrdering:
    """Maven's scheme is not semver, and getting it wrong hides findings.

    `version_matches()` answers False for a version it cannot parse, so before this
    ordering existed a Spring project pinned to `5.3.20.RELEASE` reported
    clean against a real advisory.
    """

    @pytest.mark.parametrize(
        ("lower", "higher"),
        [
            ("1.0.0.RELEASE", "1.0.1.RELEASE"),
            ("1.0-SNAPSHOT", "1.0"),
            ("1.0-alpha1", "1.0-beta1"),
            ("1.0-beta1", "1.0-rc1"),
            ("1.0-rc1", "1.0"),
            ("1.0", "1.0-sp1"),
            ("1.0-milestone2", "1.0-rc1"),
            ("1.2", "1.10"),
            ("2.13.0", "2.13.4.2"),
            ("31.1-jre", "32.0.0-jre"),
        ],
    )
    def test_ordering(self, lower, higher):
        assert compare(Ecosystem.MAVEN, lower, higher) == -1
        assert compare(Ecosystem.MAVEN, higher, lower) == 1

    @pytest.mark.parametrize(
        ("left", "right"),
        [
            ("1.0", "1.0.0"),
            ("1.0", "1"),
            ("5.3.20.RELEASE", "5.3.20"),
            ("1.0.0.Final", "1.0.0"),
        ],
    )
    def test_trailing_nulls_are_the_same_version(self, left, right):
        assert compare(Ecosystem.MAVEN, left, right) == 0

    def test_a_release_qualifier_still_matches_an_advisory_range(self):
        """The regression this whole comparator exists for."""
        advisory = AffectedPackage(
            ecosystem=Ecosystem.MAVEN,
            name="org.springframework:spring-core",
            ranges=(AffectedRange(introduced="5.0.0", fixed="5.3.21"),),
        )

        assert version_matches(Ecosystem.MAVEN, "5.3.20.RELEASE", advisory) is True
        assert version_matches(Ecosystem.MAVEN, "5.3.21", advisory) is False

    def test_a_crates_io_version_matches_a_range(self):
        advisory = AffectedPackage(
            ecosystem=Ecosystem.CRATES_IO,
            name="tokio",
            ranges=(AffectedRange(introduced="1.0.0", fixed="1.20.1"),),
        )

        assert version_matches(Ecosystem.CRATES_IO, "1.20.0", advisory) is True
        assert version_matches(Ecosystem.CRATES_IO, "1.20.1", advisory) is False


class TestPomIsNotAnAttackSurface:
    """An uploaded POM is untrusted XML from a stranger.

    Checked rather than assumed: `xml.etree` already refuses *external*
    entities — an XXE payload raises "undefined entity" — but it expands
    internal ones, so a billion-laughs document parsed and grew until it
    exhausted memory. No POM needs a DTD, so one is refused outright.
    """

    BILLION_LAUGHS = """<?xml version="1.0"?>
    <!DOCTYPE lolz [
     <!ENTITY lol "lol">
     <!ENTITY lol2 "&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;">
     <!ENTITY lol3 "&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;">
    ]>
    <project><artifactId>&lol3;</artifactId></project>"""

    XXE = """<?xml version="1.0"?>
    <!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>
    <project><artifactId>&xxe;</artifactId></project>"""

    def test_entity_expansion_is_refused(self):
        with pytest.raises(ManifestParseError, match="document type"):
            parse_manifest(ManifestKind.POM_XML, self.BILLION_LAUGHS)

    def test_an_external_entity_is_refused(self):
        with pytest.raises(ManifestParseError, match="document type"):
            parse_manifest(ManifestKind.POM_XML, self.XXE)

    def test_an_ordinary_pom_still_parses(self):
        """The guard must not cost the legitimate case."""
        assert parse_manifest(ManifestKind.POM_XML, POM).dependencies
