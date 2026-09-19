package dev.weedout.ide;

import com.intellij.openapi.project.Project;
import com.intellij.openapi.startup.StartupActivity;
import org.jetbrains.annotations.NotNull;

public final class WeedoutStartupActivity implements StartupActivity.DumbAware {
    @Override public void runActivity(@NotNull Project project) {
        project.getService(WeedoutProjectService.class).start();
    }
}
