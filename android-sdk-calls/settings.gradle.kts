// Optional WebRTC media module of the NEXUS-SIGN Android SDK (ADR 0017).
// The core SDK is built from ../android-sdk, so this module always matches
// the SDK source in this repository.
pluginManagement {
    repositories {
        google()
        mavenCentral()
        gradlePluginPortal()
    }
}

dependencyResolutionManagement {
    repositoriesMode.set(RepositoriesMode.FAIL_ON_PROJECT_REPOS)
    repositories {
        google()
        mavenCentral()
    }
}

rootProject.name = "nexus-sign-android-calls"

includeBuild("../android-sdk") {
    dependencySubstitution {
        substitute(module("com.nexis:nexus-sign-android")).using(project(":"))
    }
}
