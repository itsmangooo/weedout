package dev.weedout.ide;

import java.util.List;

record Finding(
    String packageName,
    String version,
    String cve,
    String severity,
    boolean exploited,
    String fixedIn,
    String summary,
    List<String> via,
    String reachability,
    List<String> evidence,
    String reason
) {
    String identity() { return cve + ":" + packageName + ":" + version; }
    String hint() { return fixedIn == null || fixedIn.isBlank() ? "Review " + cve : "Update to " + fixedIn; }
}

record Occurrence(String packageName, int start, int end) {}

record ProjectBinding(int id, String name) {}
