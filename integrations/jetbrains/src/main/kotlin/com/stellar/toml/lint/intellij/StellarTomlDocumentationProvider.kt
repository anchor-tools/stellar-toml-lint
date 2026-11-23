package com.stellar.toml.lint.intellij

import com.intellij.lang.documentation.DocumentationProvider
import com.intellij.openapi.editor.Editor
import com.intellij.psi.PsiElement
import com.intellij.psi.PsiFile

class StellarTomlDocumentationProvider : DocumentationProvider {

    override fun generateDoc(element: PsiElement, originalElement: PsiElement?): String? {
        return when (element.text) {
            "NETWORK_PASSPHRASE" -> "**NETWORK_PASSPHRASE**\n\nThe network passphrase for the Stellar network. See [SEP-1](https://github.com/stellar/stellar-protocol/blob/master/ecosystem/sep-0001.md)."
            "SIGNING_KEY" -> "**SIGNING_KEY**\n\nThe Stellar signing key (G-address). See [SEP-1](https://github.com/stellar/stellar-protocol/blob/master/ecosystem/sep-0001.md)."
            "CURRENCIES" -> "**CURRENCIES**\n\nArray of supported currencies. See [SEP-1](https://github.com/stellar/stellar-protocol/blob/master/ecosystem/sep-0001.md)."
            "VALIDATORS" -> "**VALIDATORS**\n\nArray of trusted validators. See [SEP-1](https://github.com/stellar/stellar-protocol/blob/master/ecosystem/sep-0001.md)."
            "WEB_AUTH_ENDPOINT" -> "**WEB_AUTH_ENDPOINT**\n\nWeb authentication endpoint for SEP-10. See [SEP-10](https://github.com/stellar/stellar-protocol/blob/master/ecosystem/sep-0010.md)."
            "HORIZON_URL" -> "**HORIZON_URL**\n\nThe Horizon server URL. See [SEP-1](https://github.com/stellar/stellar-protocol/blob/master/ecosystem/sep-0001.md)."
            else -> "**SEP-1 stellar.toml**\n\nSee the [SEP-1 specification](https://github.com/stellar/stellar-protocol/blob/master/ecosystem/sep-0001.md) for details on all fields."
        }
    }

    override fun fetchQuickDoc(element: PsiElement?, editor: Editor?): String? {
        return generateDoc(element ?: return null, null)
    }

    override fun generateDoc(element: PsiElement, originalElement: PsiElement?): String? = null
}
