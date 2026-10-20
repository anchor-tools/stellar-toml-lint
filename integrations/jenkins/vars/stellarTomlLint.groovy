import groovy.json.JsonSlurperClassic

/** Lint a stellar.toml in the published container and publish Jenkins reports. */
def call(Map config = [:]) {
    String file = (config.file ?: 'stellar.toml').toString()
    String image = (config.image ?: 'ghcr.io/anchor-tools/stellar-toml-lint:latest').toString()
    int maxErrors = (config.maxErrors == null ? 0 : config.maxErrors.toString().toInteger())
    int maxWarnings = (config.maxWarnings == null ? -1 : config.maxWarnings.toString().toInteger())

    if (maxErrors < 0 || maxWarnings < -1) {
        error('maxErrors must be >= 0 and maxWarnings must be >= -1')
    }

    String target = "'${file.replace("'", "'\\''")}'"
    String json
    docker.image(image).inside {
        sh "stellar-toml-lint --format checkstyle ${target} > stellar-toml-lint-checkstyle.xml || true"
        sh "stellar-toml-lint --format junit ${target} > stellar-toml-lint-junit.xml || true"
        json = sh(
            script: "stellar-toml-lint --format json ${target} || true",
            returnStdout: true
        ).trim()
    }

    recordIssues tools: [checkStyle(pattern: 'stellar-toml-lint-checkstyle.xml')]
    junit testResults: 'stellar-toml-lint-junit.xml', allowEmptyResults: true

    def report = new JsonSlurperClassic().parseText(json)
    int errors = report.counts.error as int
    int warnings = report.counts.warning as int
    if (errors > maxErrors || (maxWarnings >= 0 && warnings > maxWarnings)) {
        error("stellar-toml-lint quality gate failed: ${errors} errors, ${warnings} warnings")
    }

    return report
}