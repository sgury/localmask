package com.localmask

import com.intellij.openapi.project.Project
import com.intellij.openapi.wm.StatusBar
import com.intellij.openapi.wm.StatusBarWidget
import com.intellij.openapi.wm.StatusBarWidgetFactory
import com.intellij.util.Consumer
import java.awt.event.MouseEvent

/** 🛡 status-bar widget: findings · stage. Click = action menu. */
class ShieldWidgetFactory : StatusBarWidgetFactory {
    override fun getId() = "LocalMaskShield"
    override fun getDisplayName() = "LocalMask"
    override fun isAvailable(project: Project) = true
    override fun createWidget(project: Project): StatusBarWidget = ShieldWidget(project)
    override fun disposeWidget(widget: StatusBarWidget) {}
    override fun canBeEnabledOn(statusBar: StatusBar) = true
}

class ShieldWidget(private val project: Project) :
    StatusBarWidget, StatusBarWidget.TextPresentation {

    private var text = "🛡 LocalMask"
    private var statusBar: StatusBar? = null

    override fun ID() = "LocalMaskShield"
    override fun getPresentation(): StatusBarWidget.WidgetPresentation = this

    override fun install(statusBar: StatusBar) {
        this.statusBar = statusBar
        refresh()
    }

    fun refresh() {
        com.intellij.openapi.application.ApplicationManager.getApplication()
            .executeOnPooledThread {
                val scan = try { LocalMask.scan(project) } catch (e: Exception) { null }
                text = when {
                    scan == null -> "🛡 LocalMask"
                    scan.pending > 0 ->
                        "🛡 ${scan.detections.size} findings · ⏳ ${scan.pending} to review"
                    else -> "🛡 ${scan.detections.size} findings · ✓"
                }
                statusBar?.updateWidget(ID())
            }
    }

    override fun getText() = text
    override fun getAlignment() = 0f
    override fun getTooltipText(): String {
        val v = try { LocalMask.cliVersion() } catch (e: Exception) { "" }
        return "LocalMask — click for actions (scan, review, publish). " +
            "100% local." + (if (v.isNotEmpty()) " CLI $v" else "")
    }

    override fun getClickConsumer(): Consumer<MouseEvent> =
        Consumer { ActionMenu.show(project) { refresh() } }

    override fun dispose() { statusBar = null }
}
