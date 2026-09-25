plugins {
    id 'org.jetbrains.intellij' version '1.16.1'
    id 'org.jetbrains.kotlin.jvm' version '1.9.22'
}

group = 'com.stellar.toml.lint'
version = '1.0.0'

intellij {
    type = 'IC'
    version = '2024.1'
    pluginName = 'stellar-toml-lint'
    updateSinceUntilBuild = false
    instrumentCode = true
    jvmArgs = ['-Xmx2g']
}

repositories {
    mavenCentral()
}

dependencies {
    implementation 'org.jetbrains.kotlin:kotlin-stdlib:1.9.22'
    implementation 'org.jetbrains.intellij.plugins:gradle-intellij-plugin:1.16.1'
    implementation 'com.jetbrains:php:233.14015.108'
    implementation 'org.jetbrains:annotations:24.1.0'
}

tasks {
    patchPluginXml {
        changeNotes = """
            <p>Official JetBrains IDE plugin for IntelliJ and WebStorm with real-time SEP-1 linting.</p>
            <ul>
                <li>Real-time diagnostics for stellar.toml files</li>
                <li>Quick-fix intentions via Alt+Enter</li>
                <li>Hover documentation with SEP-1 spec links</li>
                <li>File type association for stellar.toml and .well-known/stellar.toml</li>
            </ul>
        """
    }
    signPlugin {
        certificateChain = System.getenv('CERTIFICATE_CHAIN') ?: ''
        privateKey = System.getenv('PRIVATE_KEY') ?: ''
        password = System.getenv('PRIVATE_KEY_PASSWORD') ?: ''
    }
}

sourceSets {
    main {
        kotlin {
            srcDirs = ['src/main/kotlin']
        }
        resources {
            srcDirs = ['src/main/resources']
        }
    }
}

compileKotlin {
    kotlinOptions {
        jvmTarget = '17'
    }
}
