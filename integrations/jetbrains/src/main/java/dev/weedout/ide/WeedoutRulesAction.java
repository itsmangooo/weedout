package dev.weedout.ide;

import com.intellij.openapi.actionSystem.AnAction;
import com.intellij.openapi.actionSystem.AnActionEvent;
import com.intellij.openapi.fileEditor.FileEditorManager;
import com.intellij.openapi.ui.Messages;
import com.intellij.openapi.vfs.LocalFileSystem;
import org.jetbrains.annotations.NotNull;

import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;

public final class WeedoutRulesAction extends AnAction {
    @Override public void actionPerformed(@NotNull AnActionEvent event) {
        if (event.getProject() == null || event.getProject().getBasePath() == null) return;
        try {
            Path path = Path.of(event.getProject().getBasePath(), ".weedout.yml");
            if (!Files.exists(path)) Files.writeString(path, "# Weedout project rules\n", StandardCharsets.UTF_8);
            var file = LocalFileSystem.getInstance().refreshAndFindFileByNioFile(path);
            if (file != null) FileEditorManager.getInstance(event.getProject()).openFile(file, true);
        } catch (Exception error) {
            Messages.showErrorDialog(event.getProject(), error.getMessage(), "Weedout Rules");
        }
    }
}
