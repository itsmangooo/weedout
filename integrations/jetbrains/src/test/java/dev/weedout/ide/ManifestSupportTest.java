package dev.weedout.ide;

import org.junit.jupiter.api.Test;

import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

final class ManifestSupportTest {
    @Test void supportsEveryBackendManifestFamily() {
        for (String name : List.of("package.json", "package-lock.json", "requirements-dev.txt", "go.mod", "Cargo.lock", "pom.xml", "gradle.lockfile", "dependencies.lock", "build.sbt.lock")) {
            assertTrue(ManifestSupport.supported(name), name);
        }
    }

    @Test void prefersResolvedDependencyFiles() {
        assertTrue(ManifestSupport.rank("package-lock.json") < ManifestSupport.rank("package.json"));
        assertTrue(ManifestSupport.rank("Cargo.lock") < ManifestSupport.rank("pom.xml"));
    }

    @Test void locatesDependenciesForEditorAnnotations() {
        assertEquals(List.of("lodash"), ManifestSupport.occurrences("{\n  \"dependencies\": {\n    \"lodash\": \"4.17.20\"\n  }\n}", "package.json").stream().map(Occurrence::packageName).toList());
        assertEquals(List.of("Django", "requests"), ManifestSupport.occurrences("Django==4.2.0\nrequests>=2.0", "requirements.txt").stream().map(Occurrence::packageName).toList());
        assertEquals(List.of("lodash"), ManifestSupport.occurrences("\"node_modules/lodash\": {", "package-lock.json").stream().map(Occurrence::packageName).toList());
        assertEquals(List.of("org.slf4j:slf4j-api"), ManifestSupport.occurrences("<dependency><groupId>org.slf4j</groupId><artifactId>slf4j-api</artifactId><version>2.0.0</version></dependency>", "pom.xml").stream().map(Occurrence::packageName).toList());
    }

    @Test void inlineHintsHaveAtMostEightWords() {
        Finding finding = new Finding("lodash", "1.0", "CVE-2025-1", "high", false, "2.0", "", List.of(), "", List.of(), "");
        assertTrue(finding.hint().split("\\s+").length <= 8);
    }
}
