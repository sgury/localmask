// LocalMask JetBrains plugin — MVP
// Build: ./gradlew buildPlugin   ·   Test-drive: ./gradlew runIde
plugins {
    id("java")
    id("org.jetbrains.kotlin.jvm") version "1.9.24"
    id("org.jetbrains.intellij") version "1.17.4"
}

group = "com.localmask"
version = "0.1.0"

repositories { mavenCentral() }

intellij {
    // Build against IntelliJ Community — the plugin uses only platform APIs,
    // so it runs in PyCharm, IDEA, DataGrip, GoLand, WebStorm, …
    version.set("2023.3")
    type.set("IC")
}

kotlin { jvmToolchain(17) }

tasks {
    patchPluginXml {
        sinceBuild.set("233")
        untilBuild.set("299.*")
    }
    buildSearchableOptions { enabled = false }
}
