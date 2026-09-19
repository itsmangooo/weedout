package dev.weedout.ide;

import com.google.gson.JsonObject;
import com.intellij.credentialStore.CredentialAttributes;
import com.intellij.credentialStore.Credentials;
import com.intellij.ide.BrowserUtil;
import com.intellij.ide.passwordSafe.PasswordSafe;
import com.intellij.notification.NotificationGroupManager;
import com.intellij.notification.NotificationType;
import com.intellij.openapi.Disposable;
import com.intellij.openapi.application.ApplicationManager;
import com.intellij.openapi.editor.Editor;
import com.intellij.openapi.editor.EditorFactory;
import com.intellij.openapi.editor.Inlay;
import com.intellij.openapi.fileEditor.FileDocumentManager;
import com.intellij.openapi.project.Project;
import com.intellij.openapi.roots.ProjectFileIndex;
import com.intellij.openapi.util.Disposer;
import com.intellij.openapi.util.io.FileUtil;
import com.intellij.openapi.vfs.VfsUtilCore;
import com.intellij.openapi.vfs.VirtualFile;
import com.intellij.openapi.vfs.VirtualFileManager;
import com.intellij.openapi.vfs.newvfs.BulkFileListener;
import com.intellij.openapi.vfs.newvfs.events.VFileEvent;
import com.intellij.psi.PsiManager;
import com.intellij.codeInsight.daemon.DaemonCodeAnalyzer;
import com.intellij.util.Alarm;
import com.intellij.ide.util.PropertiesComponent;
import org.jetbrains.annotations.NotNull;

import java.net.InetAddress;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.CopyOnWriteArrayList;

public final class WeedoutProjectService implements Disposable {
    private static final String PROJECT_ID = "weedout.projectId";
    private static final String PROJECT_NAME = "weedout.projectName";
    private static final CredentialAttributes MACHINE = new CredentialAttributes("Weedout IDE", "machine");

    private final Project project;
    private final WeedoutApi api;
    private final Alarm debounce = new Alarm(Alarm.ThreadToUse.POOLED_THREAD, this);
    private final List<Runnable> listeners = new CopyOnWriteArrayList<>();
    private final Map<Editor, List<Inlay<?>>> inlays = new HashMap<>();
    private volatile List<Finding> findings = List.of();
    private volatile Set<String> baseline = Set.of();
    private volatile boolean baselineInitialized;

    public WeedoutProjectService(Project project) {
        this.project = project;
        String configured = System.getProperty("weedout.serverUrl", "https://weedout.dev");
        this.api = new WeedoutApi(configured);
        project.getMessageBus().connect(this).subscribe(VirtualFileManager.VFS_CHANGES, new BulkFileListener() {
            @Override public void after(@NotNull List<? extends VFileEvent> events) {
                if (events.stream().map(VFileEvent::getPath).anyMatch(WeedoutProjectService::watchedPath)) schedule(false);
            }
        });
    }

    public List<Finding> findings() { return findings; }
    public void addListener(Runnable listener, Disposable parent) { listeners.add(listener); Disposer.register(parent, () -> listeners.remove(listener)); }
    public boolean hasBinding() { return PropertiesComponent.getInstance(project).getValue(PROJECT_ID) != null; }

    public void start() { schedule(true); }

    public void schedule(boolean startup) {
        debounce.cancelAllRequests();
        debounce.addRequest(() -> scan(startup), startup ? 100 : 800);
    }

    private void scan(boolean startup) {
        ProjectBinding binding = binding();
        String key = binding == null ? null : password(projectCredentials());
        VirtualFile manifest = bestManifest();
        if (binding == null || key == null || manifest == null) {
            if (manifest == null) update(List.of(), startup);
            return;
        }
        try {
            byte[] policy = policyBytes();
            List<Finding> next = api.scan(key, manifest.getName(), VfsUtilCore.loadBytes(manifest), policy);
            update(next, startup);
        } catch (Exception error) {
            if (!startup) notifyUser("Automatic analysis failed: " + error.getMessage(), NotificationType.ERROR);
        }
    }

    private void update(List<Finding> next, boolean startup) {
        Set<String> identities = new HashSet<>();
        next.forEach(finding -> identities.add(finding.identity()));
        long added = identities.stream().filter(value -> !baseline.contains(value)).count();
        boolean hadBaseline = baselineInitialized;
        findings = List.copyOf(next);
        baseline = Set.copyOf(identities);
        baselineInitialized = true;
        ApplicationManager.getApplication().invokeLater(() -> {
            if (project.isDisposed()) return;
            DaemonCodeAnalyzer.getInstance(project).restart();
            refreshInlays();
            listeners.forEach(Runnable::run);
            if (!startup && hadBaseline && added > 0) notifyUser("Weedout found " + added + " new " + (added == 1 ? "finding." : "findings."), NotificationType.WARNING);
        });
    }

    public void authenticate() {
        ApplicationManager.getApplication().executeOnPooledThread(() -> {
            try {
                String host = InetAddress.getLocalHost().getHostName();
                JsonObject started = api.startAuth("JetBrains IDE on " + host);
                String code = started.get("user_code").getAsString();
                String url = started.get("verification_url").getAsString();
                ApplicationManager.getApplication().invokeLater(() -> {
                    BrowserUtil.browse(url);
                    notifyUser("Confirm code " + code + " in your browser.", NotificationType.INFORMATION);
                });
                long deadline = System.currentTimeMillis() + started.get("expires_in").getAsLong() * 1000;
                long interval = started.get("interval").getAsLong() * 1000;
                while (!project.isDisposed() && System.currentTimeMillis() < deadline) {
                    Thread.sleep(interval);
                    JsonObject polled = api.pollAuth(started.get("device_code").getAsString());
                    String state = polled.get("state").getAsString();
                    if (state.equals("approved")) {
                        PasswordSafe.getInstance().set(MACHINE, new Credentials("machine", polled.get("token").getAsString()));
                        notifyUser("Authenticated as " + polled.get("email").getAsString() + ".", NotificationType.INFORMATION);
                        return;
                    }
                    if (state.equals("denied") || state.equals("expired")) throw new IllegalStateException("Authentication " + state + ".");
                }
            } catch (Exception error) { notifyUser("Authentication failed: " + error.getMessage(), NotificationType.ERROR); }
        });
    }

    public void createProject(String name) {
        String machine = password(MACHINE);
        if (machine == null) { notifyUser("Run Weedout: Auth first.", NotificationType.WARNING); return; }
        VirtualFile manifest = bestManifest();
        if (manifest == null) { notifyUser("No supported dependency file was found.", NotificationType.WARNING); return; }
        ApplicationManager.getApplication().executeOnPooledThread(() -> {
            try {
                JsonObject result = api.createProject(machine, name, manifest.getName(), VfsUtilCore.loadText(manifest));
                JsonObject created = result.getAsJsonObject("project");
                PropertiesComponent properties = PropertiesComponent.getInstance(project);
                properties.setValue(PROJECT_ID, created.get("id").getAsString());
                properties.setValue(PROJECT_NAME, created.get("name").getAsString());
                PasswordSafe.getInstance().set(projectCredentials(), new Credentials(project.getLocationHash(), result.get("key").getAsString()));
                notifyUser("Weedout project “" + created.get("name").getAsString() + "” is active.", NotificationType.INFORMATION);
                schedule(false);
            } catch (Exception error) { notifyUser("Project creation failed: " + error.getMessage(), NotificationType.ERROR); }
        });
    }

    public void deleteProject() {
        ProjectBinding binding = binding();
        String machine = password(MACHINE);
        if (binding == null) { notifyUser("This project is not connected to Weedout.", NotificationType.WARNING); return; }
        if (machine == null) { notifyUser("Run Weedout: Auth first.", NotificationType.WARNING); return; }
        ApplicationManager.getApplication().executeOnPooledThread(() -> {
            try {
                api.deleteProject(machine, binding.id());
                PasswordSafe.getInstance().set(projectCredentials(), null);
                PropertiesComponent properties = PropertiesComponent.getInstance(project);
                properties.unsetValue(PROJECT_ID);
                properties.unsetValue(PROJECT_NAME);
                update(List.of(), false);
                notifyUser("Deleted Weedout project “" + binding.name() + "”.", NotificationType.INFORMATION);
            } catch (Exception error) { notifyUser("Project deletion failed: " + error.getMessage(), NotificationType.ERROR); }
        });
    }

    ProjectBinding binding() {
        PropertiesComponent properties = PropertiesComponent.getInstance(project);
        String raw = properties.getValue(PROJECT_ID);
        if (raw == null) return null;
        try { return new ProjectBinding(Integer.parseInt(raw), properties.getValue(PROJECT_NAME, "Weedout project")); }
        catch (NumberFormatException ignored) { return null; }
    }

    private VirtualFile bestManifest() {
        VirtualFile root = project.getBaseDir();
        if (root == null) return null;
        List<VirtualFile> files = new ArrayList<>();
        VfsUtilCore.iterateChildrenRecursively(root,
            file -> !file.getName().equals(".git") && !file.getName().equals("node_modules") && !file.getName().equals("build") && !ProjectFileIndex.getInstance(project).isExcluded(file),
            file -> { if (!file.isDirectory() && ManifestSupport.supported(file.getName())) files.add(file); return true; });
        return files.stream().min(Comparator.comparingInt((VirtualFile file) -> ManifestSupport.rank(file.getName())).thenComparingInt(file -> file.getPath().length())).orElse(null);
    }

    private byte[] policyBytes() throws Exception {
        VirtualFile root = project.getBaseDir();
        VirtualFile policy = root == null ? null : root.findChild(".weedout.yml");
        return policy == null ? null : VfsUtilCore.loadBytes(policy);
    }

    private void refreshInlays() {
        for (List<Inlay<?>> values : inlays.values()) values.forEach(Inlay::dispose);
        inlays.clear();
        Map<String, Finding> byPackage = new HashMap<>();
        findings.forEach(finding -> byPackage.put(ManifestSupport.key(finding.packageName()), finding));
        for (Editor editor : EditorFactory.getInstance().getAllEditors()) {
            if (editor.getProject() != project) continue;
            VirtualFile file = FileDocumentManager.getInstance().getFile(editor.getDocument());
            if (file == null || !ManifestSupport.supported(file.getName())) continue;
            List<Inlay<?>> added = new ArrayList<>();
            for (Occurrence occurrence : ManifestSupport.occurrences(editor.getDocument().getText(), file.getName())) {
                Finding finding = byPackage.get(ManifestSupport.key(occurrence.packageName()));
                if (finding == null) continue;
                Inlay<?> inlay = editor.getInlayModel().addInlineElement(occurrence.end(), true, new WeedoutInlayRenderer(finding.hint()));
                if (inlay != null) added.add(inlay);
            }
            inlays.put(editor, added);
        }
    }

    private CredentialAttributes projectCredentials() { return new CredentialAttributes("Weedout project", project.getLocationHash()); }
    private static String password(CredentialAttributes attributes) {
        Credentials credentials = PasswordSafe.getInstance().get(attributes);
        return credentials == null ? null : credentials.getPasswordAsString();
    }
    private static boolean watchedPath(String path) {
        String name = FileUtil.toSystemIndependentName(path);
        int slash = name.lastIndexOf('/');
        String filename = slash < 0 ? name : name.substring(slash + 1);
        return filename.equals(".weedout.yml") || ManifestSupport.supported(filename);
    }
    private void notifyUser(String content, NotificationType type) {
        ApplicationManager.getApplication().invokeLater(() -> NotificationGroupManager.getInstance().getNotificationGroup("Weedout").createNotification(content, type).notify(project));
    }

    @Override public void dispose() {
        for (List<Inlay<?>> values : inlays.values()) values.forEach(Inlay::dispose);
        inlays.clear();
    }
}
