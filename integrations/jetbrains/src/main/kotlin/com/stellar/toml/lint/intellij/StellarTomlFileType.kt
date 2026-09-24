package com.stellar.toml.lint.intellij

import com.intellij.openapi.fileTypes.FileType
import com.intellij.openapi.fileTypes.FileTypeFactory
import com.intellij.openapi.fileTypes.FileTypeProvider
import com.intellij.openapi.fileTypes.language.FileTypeLanguage
import javax.swing.Icon

class StellarTomlFileType : FileType {
    override fun getName(): String = "Stellar TOML"
    override fun getDescription(): String = "Stellar TOML configuration file"
    override fun getDefaultExtension(): String = "toml"
    override fun getIcon(): Icon? = null
    override fun isBinary(): Boolean = false
    override fun isReadOnly(): Boolean = true
    override fun getCharset(): String? = null
    override fun getLanguage(): FileTypeLanguage = StellarTomlLanguage.INSTANCE
}

class StellarTomlFileTypeFactory : FileTypeFactory() {
    override fun createFileTypes(): Array<FileType> {
        return arrayOf(StellarTomlFileType())
    }
}

object StellarTomlLanguage : FileTypeLanguage("Stellar TOML", "stellar.toml", StellarTomlFileType.INSTANCE) {
    companion object {
        val INSTANCE = StellarTomlLanguage()
    }
}

object StellarTomlFileTypeProvider : FileTypeProvider {
    fun getInstance(): StellarTomlFileTypeProvider = StellarTomlFileTypeProvider()
}

object StellarTomlFileTypes {
    val INSTANCE = StellarTomlFileType()
}
