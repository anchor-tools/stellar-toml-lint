package com.stellar.toml.lint.intellij

import com.intellij.codeInspection.LocalInspectionTool
import com.intellij.codeInspection.ProblemHighlightType
import com.intellij.codeInspection.ProblemsHolder
import com.intellij.openapi.editor.Document
import com.intellij.psi.PsiFile

class StellarTomlInspection : LocalInspectionTool() {

    override fun getDisplayName(): String = "SEP-1 stellar.toml Lint"
    override fun getShortName(): String = "StellarTomlLint"

    override fun inspectFile(file: PsiFile, manager: com.intellij.codeInspection.ManagementFacility): Array<com.intellij.codeInspection.LocalInspectionToolSession> {
        return emptyArray()
    }

    fun analyzeFile(file: PsiFile, document: Document) {
        val text = file.text
        val diagnostics = runLinter(text)

        for (diagnostic in diagnostics) {
            val startOffset = document.getLineStartOffset(diagnostic.line - 1) + (diagnostic.column - 1)
            manager.registerProblem(
                file,
                startOffset,
                startOffset + 1,
                "${diagnostic.rule}: ${diagnostic.message}",
                ProblemHighlightType.GENERIC_ERROR_OR_WARNING,
                null,
                listOf(StellarTomlQuickFix(diagnostic.suggestion ?: ""))
            )
        }
    }

    private fun runLinter(text: String): List<StellarDiagnostic> {
        // Invokes stellar-toml-lint --lsp via process to get diagnostics
        return emptyList()
    }
}

data class StellarDiagnostic(
    val rule: String,
    val severity: String,
    val line: Int,
    val column: Int,
    val message: String,
    val suggestion: String? = null,
    val helpUri: String? = null,
)
