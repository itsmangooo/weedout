package dev.weedout.ide;

import java.util.ArrayList;
import java.util.List;
import java.util.Set;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

final class ManifestSupport {
    private static final Set<String> EXACT = Set.of(
        "package.json", "package-lock.json", "go.mod", "Cargo.lock", "pom.xml",
        "gradle.lockfile", "dependencies.lock", "build.sbt.lock"
    );

    private ManifestSupport() {}

    static boolean supported(String name) {
        return EXACT.contains(name) || name.matches("(?i)requirements.*\\.txt") || name.endsWith(".gradle.lockfile");
    }

    static int rank(String name) {
        return switch (name) {
            case "package-lock.json" -> 0;
            case "Cargo.lock" -> 1;
            case "gradle.lockfile", "dependencies.lock", "build.sbt.lock" -> 2;
            case "package.json" -> 3;
            case "go.mod" -> 5;
            case "pom.xml" -> 6;
            default -> name.matches("(?i)requirements.*\\.txt") ? 4 : name.endsWith(".gradle.lockfile") ? 2 : 99;
        };
    }

    static String key(String value) {
        return value.trim().toLowerCase().replaceAll("[._-]+", "-");
    }

    static List<Occurrence> occurrences(String text, String filename) {
        List<Occurrence> result = new ArrayList<>();
        if (filename.equals("pom.xml")) {
            Matcher dependencies = Pattern.compile("<dependency>[\\s\\S]*?<groupId>\\s*([^<]+)\\s*</groupId>[\\s\\S]*?<artifactId>\\s*([^<]+)\\s*</artifactId>[\\s\\S]*?</dependency>").matcher(text);
            while (dependencies.find()) {
                int start = dependencies.start() + dependencies.group().indexOf(dependencies.group(2));
                result.add(new Occurrence(dependencies.group(1).trim() + ":" + dependencies.group(2).trim(), start, start + dependencies.group(2).trim().length()));
            }
            return result;
        }
        int offset = 0;
        for (String line : text.split("\\R", -1)) {
            Pattern pattern;
            if (filename.equals("package.json") || filename.equals("package-lock.json")) {
                pattern = Pattern.compile("^\\s*\"([@a-zA-Z0-9_.\\/-]+)\"\\s*:\\s*(?:\"[^\"]+\"|\\{)");
            } else if (filename.matches("(?i)requirements.*\\.txt")) {
                pattern = Pattern.compile("^\\s*([A-Za-z0-9_.-]+)(?:\\[[^]]+])?\\s*(?:===|==|~=|>=|<=|>|<|!=)");
            } else if (filename.equals("go.mod")) {
                pattern = Pattern.compile("^\\s*([^\\s/][^\\s]*)\\s+v?\\d");
            } else if (filename.equals("Cargo.lock")) {
                pattern = Pattern.compile("^name\\s*=\\s*\"([^\"]+)\"");
            } else {
                pattern = Pattern.compile("^\\s*([^\\s:#]+:[^\\s:#]+):([^\\s=]+)");
            }
            Matcher matcher = pattern.matcher(line);
            if (matcher.find()) {
                String packageName = matcher.group(1).trim().replaceFirst("^.*node_modules/", "");
                if (!Set.of("dependencies", "devDependencies", "packages", "module", "go", "toolchain", "replace", "exclude").contains(packageName)) {
                    int start = offset + matcher.start(1);
                    result.add(new Occurrence(packageName, start, start + matcher.group(1).length()));
                }
            }
            offset += line.length() + 1;
        }
        return result;
    }
}
