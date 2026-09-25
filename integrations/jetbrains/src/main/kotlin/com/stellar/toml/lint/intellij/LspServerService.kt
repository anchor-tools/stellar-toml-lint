package com.stellar.toml.lint.intellij

import com.intellij.openapi.project.Project
import com.intellij.openapi.vfs.VirtualFile

@ProjectService
class LspServerService(private val project: Project) {

    private var process: Process? = null
    private var outputThread: Thread? = null

    fun startLspServer() {
        val processBuilder = ProcessBuilder("stellar-toml-lint", "--lsp")
        processBuilder.directory(project.baseDir)
        processBuilder.redirectErrorStream(true)

        process = processBuilder.start()
        startOutputReader()
    }

    private fun startOutputReader() {
        outputThread = Thread {
            val reader = java.io.BufferedReader(java.io.InputStreamReader(process?.inputStream ?: return@Thread))
            var line: String?
            while (reader.readLine().also { line = it } != null) {
                handleLspMessage(line ?: "")
            }
        }
        outputThread?.start()
    }

    private fun handleLspMessage(message: String) {
        // Parse and dispatch LSP JSON-RPC messages to IntelliJ inspection system
    }

    fun sendMessage(message: String) {
        val outputStream: java.io.OutputStream? = process?.outputStream
        outputStream?.write(message.toByteArray())
        outputStream?.flush()
    }

    fun stopLspServer() {
        process?.destroy()
        outputThread?.interrupt()
    }

    fun isRunning(): Boolean = process?.isAlive == true

    companion object {
        fun getInstance(project: Project): LspServerService = project.getService(LspServerService::class.java)
    }
}
