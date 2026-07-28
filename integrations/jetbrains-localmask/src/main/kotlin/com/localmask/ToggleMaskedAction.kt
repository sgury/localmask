package com.localmask

import com.intellij.openapi.actionSystem.AnAction
import com.intellij.openapi.actionSystem.AnActionEvent
import com.intellij.openapi.actionSystem.CommonDataKeys
import com.intellij.openapi.application.ApplicationManager
import com.intellij.openapi.fileEditor.FileEditorManager
import com.intellij.openapi.progress.ProgressIndicator
import com.intellij.openapi.progress.ProgressManager
import com.intellij.openapi.progress.Task
import com.intellij.testFramework.LightVirtualFile

/**
 * 🔑 Toggle: open a read-only MASKED view of the current file — exactly what
 * the AI sees (`localmask mask-text`). 100% local.
 */
class ToggleMaskedAction : AnAction() {

    override fun actionPerformed(e: AnActionEvent) {
        val project = e.project ?: return
        val vf = e.getData(CommonDataKeys.VIRTUAL_FILE) ?: return
        if (vf is LightVirtualFile) return   // already a masked view
        val path = vf.path

        ProgressManager.getInstance().run(object :
            Task.Backgroundable(project, "🔒 LocalMask — masking locally…", false) {
            override fun run(indicator: ProgressIndicator) {
                val scan = LocalMask.scanId(project)
                val masked = if (scan.isEmpty())
                    "// LocalMask: no scan yet — click the 🛡 shield in the status bar first.\n"
                else LocalMask.run(listOf("mask-text", scan, path), project.basePath)
                ApplicationManager.getApplication().invokeLater {
                    val view = LightVirtualFile(
                        "${vf.name} (masked — what the AI sees)",
                        vf.fileType, masked)
                    view.isWritable = false
                    FileEditorManager.getInstance(project).openFile(view, true)
                }
            }
        })
    }

    override fun update(e: AnActionEvent) {
        e.presentation.isEnabledAndVisible =
            e.project != null && e.getData(CommonDataKeys.VIRTUAL_FILE) != null
    }
}
