package dev.weedout.ide;

import com.intellij.openapi.actionSystem.AnAction;
import com.intellij.openapi.actionSystem.AnActionEvent;
import com.intellij.openapi.ui.Messages;
import org.jetbrains.annotations.NotNull;

public final class WeedoutCreateProjectAction extends AnAction {
    @Override public void actionPerformed(@NotNull AnActionEvent event) {
        if (event.getProject() == null) return;
        String suggested = event.getProject().getName();
        String name = Messages.showInputDialog(event.getProject(), "Project name", "Create Weedout Project", Messages.getQuestionIcon(), suggested, null);
        if (name != null && !name.isBlank()) event.getProject().getService(WeedoutProjectService.class).createProject(name.trim());
    }
}
