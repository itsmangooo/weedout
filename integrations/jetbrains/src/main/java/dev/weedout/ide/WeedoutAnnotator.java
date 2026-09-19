package dev.weedout.ide;

import com.intellij.lang.annotation.AnnotationHolder;
import com.intellij.lang.annotation.Annotator;
import com.intellij.lang.annotation.HighlightSeverity;
import com.intellij.openapi.util.TextRange;
import com.intellij.psi.PsiElement;
import com.intellij.psi.PsiFile;
import org.jetbrains.annotations.NotNull;

import java.util.HashMap;
import java.util.Map;

public final class WeedoutAnnotator implements Annotator {
    @Override public void annotate(@NotNull PsiElement element, @NotNull AnnotationHolder holder) {
        if (!(element instanceof PsiFile file) || file.getVirtualFile() == null || !ManifestSupport.supported(file.getName())) return;
        Map<String, Finding> findings = new HashMap<>();
        file.getProject().getService(WeedoutProjectService.class).findings().forEach(finding -> findings.put(ManifestSupport.key(finding.packageName()), finding));
        for (Occurrence occurrence : ManifestSupport.occurrences(file.getText(), file.getName())) {
            Finding finding = findings.get(ManifestSupport.key(occurrence.packageName()));
            if (finding == null || occurrence.end() > file.getTextLength()) continue;
            HighlightSeverity severity = finding.exploited() || finding.severity().equals("critical") ? HighlightSeverity.ERROR : HighlightSeverity.WARNING;
            holder.newAnnotation(severity, finding.cve() + " · " + finding.severity())
                .range(new TextRange(occurrence.start(), occurrence.end()))
                .tooltip(tooltip(finding))
                .create();
        }
    }

    private static String tooltip(Finding finding) {
        StringBuilder value = new StringBuilder("<html><b>").append(escape(finding.cve())).append(" · ").append(escape(finding.packageName())).append(" ").append(escape(finding.version())).append("</b><br>")
            .append("Severity: <b>").append(escape(finding.severity())).append("</b><br>")
            .append("Known exploitation: <b>").append(finding.exploited() ? "yes" : "no").append("</b><br>")
            .append("Fixed version: <b>").append(escape(finding.fixedIn() == null ? "not published" : finding.fixedIn())).append("</b>");
        if (!finding.via().isEmpty()) value.append("<br>Dependency path: ").append(escape(String.join(" → ", finding.via())));
        if (!finding.summary().isBlank()) value.append("<br><br>").append(escape(finding.summary()));
        if (!finding.reason().isBlank()) value.append("<br>Why surfaced: ").append(escape(finding.reason()));
        if (!finding.evidence().isEmpty()) value.append("<br>Evidence: ").append(escape(String.join("; ", finding.evidence())));
        return value.append("</html>").toString();
    }

    private static String escape(String value) {
        return value.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;").replace("\"", "&quot;");
    }
}
