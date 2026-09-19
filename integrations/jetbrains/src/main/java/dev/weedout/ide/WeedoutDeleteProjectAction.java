package dev.weedout.ide;

import com.intellij.openapi.actionSystem.AnAction;
import com.intellij.openapi.actionSystem.AnActionEvent;
import com.intellij.openapi.ui.Messages;
import org.jetbrains.annotations.NotNull;

public final class WeedoutDeleteProjectAction extends AnAction {
    @Override public void actionPerformed(@NotNull AnActionEvent event) {
        if (event.getProject() == null) return;
        WeedoutProjectService service = event.getProject().getService(WeedoutProjectService.class);
        ProjectBinding binding = service.binding();
        if (binding == null) { Messages.showInfoMessage(event.getProject(), "This project is not connected to Weedout.", "Weedout"); return; }
        int answer = Messages.showYesNoDialog(event.getProject(), "Delete Weedout project “" + binding.name() + "”? This removes its findings and keys.", "Delete Weedout Project", "Delete", "Cancel", Messages.getWarningIcon());
        if (answer == Messages.YES) service.deleteProject();
    }
}
