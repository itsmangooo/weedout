package dev.weedout.ide;

import com.intellij.openapi.actionSystem.AnAction;
import com.intellij.openapi.actionSystem.AnActionEvent;
import org.jetbrains.annotations.NotNull;

public final class WeedoutAuthAction extends AnAction {
    @Override public void actionPerformed(@NotNull AnActionEvent event) {
        if (event.getProject() != null) event.getProject().getService(WeedoutProjectService.class).authenticate();
    }
}
