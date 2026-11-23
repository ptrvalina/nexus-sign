// VoxTel Demo Bank for Android: the sandbox bank's app. The NEXUS-SIGN SDK is
// built from ../../../android-sdk (unchanged) through a composite build.
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

rootProject.name = "voxtel-sandbox-bank"
include(":app")

includeBuild("../../../android-sdk") {
    dependencySubstitution {
        substitute(module("com.nexis:nexus-sign-android")).using(project(":"))
    }
}
