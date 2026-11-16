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

// -Pnexus.coreSdkFromMavenLocal takes the core SDK from Maven Local (published
// first with publishReleasePublicationToMavenLocal) instead of the included
// build. Only for Android Lint: AGP 8.5 cannot build the lint model of a module
// whose dependency comes from an included build.
val coreSdkFromMavenLocal = providers.gradleProperty("nexus.coreSdkFromMavenLocal").isPresent

dependencyResolutionManagement {
    repositoriesMode.set(RepositoriesMode.FAIL_ON_PROJECT_REPOS)
    repositories {
        if (coreSdkFromMavenLocal) {
            mavenLocal { content { includeModule("com.nexis", "nexus-sign-android") } }
        }
        google()
        mavenCentral()
    }
}

rootProject.name = "nexus-sign-android-calls"

if (!coreSdkFromMavenLocal) {
    includeBuild("../android-sdk") {
        dependencySubstitution {
            substitute(module("com.nexis:nexus-sign-android")).using(project(":"))
        }
    }
}
