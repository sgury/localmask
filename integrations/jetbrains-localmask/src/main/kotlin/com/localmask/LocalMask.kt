package com.localmask

import com.google.gson.JsonParser
import com.intellij.openapi.diagnostic.Logger
import com.intellij.openapi.project.Project
import java.io.File
import java.util.concurrent.TimeUnit

/**
 * Shared helpers: CLI location, scan-id resolution, scan JSON model.
 * Mirrors the VS Code extension (extension.js) — same CLI, same scans JSON.
 * Everything is defensive: any failure returns empty/null and logs quietly;
 * the plugin must never break the IDE.
 */
object LocalMask {
    private val LOG = Logger.getInstance(LocalMask::class.java)

    val home: File get() = File(System.getProperty("user.home"), ".localmask")
    val cli: File get() = File(home, "localmask")

    fun installed(): Boolean = cli.canExecute()

    /** "<version> <edition>" from `localmask --version`, or "" (old CLI).
     *  The plugin only uses commands every CLI version has, so this is
     *  informational (shield tooltip), not a gate. */
    fun cliVersion(): String = run(listOf("--version"), null, 5).trim()

    /** Latest scan id for the project root: git hook comment, then `scan-id`. */
    fun scanId(project: Project): String {
        val root = project.basePath ?: return ""
        try {
            for (hook in listOf("post-commit", "pre-push")) {
                val f = File(root, ".git/hooks/$hook")
                if (f.isFile) {
                    Regex("# Scan ID: (\\S+)").find(f.readText())
                        ?.let { return it.groupValues[1] }
                }
            }
        } catch (e: Exception) { LOG.debug(e) }
        return run(listOf("scan-id", root), root, 10).trim().lineSequence()
            .lastOrNull { it.startsWith("scan_") } ?: ""
    }

    data class Detection(
        val detId: String, val file: String, val line: Int,
        val type: String, val token: String, val value: String,
        val decision: String,
    )

    data class Scan(val id: String, val detections: List<Detection>) {
        val pending get() = detections.count { it.decision == "pending" }
    }

    fun scan(project: Project): Scan? {
        val id = scanId(project)
        if (id.isEmpty()) return null
        return try {
            val f = File(home, "scans/$id.json")
            val root = JsonParser.parseString(f.readText()).asJsonObject
            val dets = (root.getAsJsonArray("detections") ?: return Scan(id, emptyList()))
                .mapNotNull { el ->
                    try {
                        val o = el.asJsonObject
                        Detection(
                            detId = o.get("det_id")?.asString ?: "",
                            file = o.get("file")?.asString ?: "",
                            line = o.get("line")?.asInt ?: 1,
                            type = o.get("type")?.asString ?: "secret",
                            token = o.get("token")?.asString ?: "~[…]~",
                            value = o.get("value")?.asString ?: "",
                            decision = o.get("decision")?.let {
                                if (it.isJsonNull) "pending" else it.asString
                            } ?: "pending",
                        )
                    } catch (e: Exception) { null }
                }
            Scan(id, dets)
        } catch (e: Exception) { LOG.debug(e); null }
    }

    /** Run the CLI, return stdout+stderr (ANSI stripped). Never throws. */
    fun run(args: List<String>, cwd: String?, timeoutSec: Long = 120): String {
        if (!installed()) return ""
        return try {
            val pb = ProcessBuilder(listOf(cli.absolutePath) + args)
            if (cwd != null) pb.directory(File(cwd))
            pb.redirectErrorStream(true)
            val p = pb.start()
            val out = p.inputStream.bufferedReader().readText()
            p.waitFor(timeoutSec, TimeUnit.SECONDS)
            out.replace(Regex("\u001b\\[[0-9;]*m"), "")
        } catch (e: Exception) { LOG.debug(e); "" }
    }
}
