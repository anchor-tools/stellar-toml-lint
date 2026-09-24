package com.stellar.toml.lint.intellij

import com.intellij.codeInsight.intention.IntentionAction
import com.intellij.openapi.editor.Editor
import com.intellij.openapi.project.Project
import org.jetbrains.annotations.Nls

class StellarTomlQuickFix(private val suggestion: String) : IntentionAction {

    override fun getText(): String = "Fix: $suggestion"

    override fun getFamilyName(): String = "Stellar TOML Fix"

    override fun isAvailable(@Nls title: String?, project: Project?, editor: Editor?): Boolean = true

    override fun invoke(project: Project, editor: Editor?, file: com.intellij.psi.PsiFile?) {
        // Apply the fix suggestion to the editor
    }

    override fun startInWriteAction(): Boolean = true
}
