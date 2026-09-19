package dev.weedout.ide;

import com.intellij.openapi.Disposable;
import com.intellij.openapi.project.Project;
import com.intellij.openapi.ui.SimpleToolWindowPanel;
import com.intellij.openapi.wm.ToolWindow;
import com.intellij.openapi.wm.ToolWindowFactory;
import com.intellij.ui.CollectionListModel;
import com.intellij.ui.SimpleListCellRenderer;
import com.intellij.ui.components.JBList;
import com.intellij.ui.content.ContentFactory;
import org.jetbrains.annotations.NotNull;

import javax.swing.JList;

public final class WeedoutToolWindowFactory implements ToolWindowFactory {
    @Override public void createToolWindowContent(@NotNull Project project, @NotNull ToolWindow toolWindow) {
        WeedoutProjectService service = project.getService(WeedoutProjectService.class);
        CollectionListModel<Finding> model = new CollectionListModel<>(service.findings());
        JBList<Finding> list = new JBList<>(model);
        list.setEmptyText("No findings that need attention");
        list.setCellRenderer(SimpleListCellRenderer.create((label, finding, index) -> {
            label.setText(finding.cve() + " · " + finding.packageName() + " " + finding.version());
            label.setToolTipText(finding.severity() + (finding.exploited() ? " · known exploitation" : "") + (finding.fixedIn() == null ? "" : " · fix " + finding.fixedIn()));
        }));
        SimpleToolWindowPanel panel = new SimpleToolWindowPanel(true, true);
        panel.setContent(list);
        var content = ContentFactory.getInstance().createContent(panel, "", false);
        toolWindow.getContentManager().addContent(content);
        service.addListener(() -> model.replaceAll(service.findings()), content);
    }
}
