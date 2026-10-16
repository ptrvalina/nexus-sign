// Demo host app for the NEXUS-SIGN Android SDK. The SDK is built from
// ../../android-sdk through a composite build, so the demo always uses the
// SDK source in this repository.
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

rootProject.name = "nexus-sign-android-demo"
include(":app")

includeBuild("../../android-sdk") {
    dependencySubstitution {
        substitute(module("com.nexis:nexus-sign-android")).using(project(":"))
    }
}
