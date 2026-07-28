package com.localmask

import com.intellij.openapi.application.ApplicationManager
import com.intellij.openapi.progress.ProgressIndicator
import com.intellij.openapi.progress.ProgressManager
import com.intellij.openapi.progress.Task
import com.intellij.openapi.project.Project
import com.intellij.openapi.ui.Messages
import com.intellij.openapi.ui.popup.JBPopupFactory

/** The shield menu — mirrors the VS Code QuickPick, zero AI tokens. */
object ActionMenu {

    fun show(project: Project, onDone: () -> Unit) {
        if (!LocalMask.installed()) {
            Messages.showInfoMessage(project,
                "LocalMask CLI not found at ~/.localmask.\n" +
                "Install: curl -sL https://localmaskpro.com/install-mcp.sh | bash",
                "LocalMask")
            return
        }
        val items = listOf(
            "🔄 Scan / sync now",
            "✅ Approve all detections",
            "🚀 Publish masked mirror",
            "📋 Review findings (terminal)",
            "🔗 Install commit hook",
        )
        JBPopupFactory.getInstance()
            .createPopupChooserBuilder(items)
            .setTitle("🛡 LocalMask (100% local)")
            .setItemChosenCallback { chosen ->
                when (items.indexOf(chosen)) {
                    0 -> cliTask(project, "scanning / syncing…", onDone) { root, scan ->
                        if (scan.isEmpty()) LocalMask.run(listOf("scan", ".", "--sensitivity", "strict"), root, 600)
                        else LocalMask.run(listOf("sync", scan), root, 600)
                    }
                    1 -> cliTask(project, "approving all…", onDone) { root, scan ->
                        LocalMask.run(listOf("approve-all", scan), root)
                    }
                    2 -> publish(project, onDone)
                    3 -> Messages.showInfoMessage(project,
                        "Run in a terminal (real values stay on your screen):\n\n" +
                        "  ~/.localmask/localmask review ${LocalMask.scanId(project)}",
                        "LocalMask Review")
                    4 -> cliTask(project, "installing commit hook…", onDone) { root, scan ->
                        LocalMask.run(listOf("hook", scan), root)
                    }
                }
            }
            .createPopup()
            .showInFocusCenter()
    }

    private fun publish(project: Project, onDone: () -> Unit) {
        val root = project.basePath ?: return
        val suggested = "$root-masked.git"
        val target = Messages.showInputDialog(project,
            "Masked mirror: local path or git URL (tokens only — no secrets)",
            "LocalMask Publish", null, suggested, null) ?: return
        cliTask(project, "publishing masked mirror…", onDone) { r, scan ->
            LocalMask.run(listOf("publish", scan, target), r, 600)
        }
    }

    private fun cliTask(
        project: Project, title: String, onDone: () -> Unit,
        body: (root: String, scanId: String) -> String,
    ) {
        val root = project.basePath ?: return
        ProgressManager.getInstance().run(object :
            Task.Backgroundable(project, "🛡 LocalMask — $title", false) {
            override fun run(indicator: ProgressIndicator) {
                val scan = LocalMask.scanId(project)
                val out = body(root, scan)
                ApplicationManager.getApplication().invokeLater {
                    val tail = out.trim().lines().lastOrNull { it.isNotBlank() } ?: "done"
                    com.intellij.notification.NotificationGroupManager.getInstance()
                        .getNotificationGroup("LocalMask")
                        .createNotification("🛡 LocalMask", tail,
                            com.intellij.notification.NotificationType.INFORMATION)
                        .notify(project)
                    onDone()
                }
            }
        })
    }
}
