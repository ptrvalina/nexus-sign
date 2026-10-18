plugins {
    id("com.android.library") version "8.5.2"
    kotlin("android") version "1.9.24"
    `maven-publish`
}

group = "com.nexis"
version = rootDir.resolve("../VERSION").readText().trim()

android {
    namespace = "com.nexis.nexussign.calls"
    compileSdk = 34

    defaultConfig {
        minSdk = 28
        consumerProguardFiles("consumer-rules.pro")
    }

    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_17
        targetCompatibility = JavaVersion.VERSION_17
    }

    kotlinOptions {
        jvmTarget = "17"
    }

    publishing {
        singleVariant("release") {
            withSourcesJar()
        }
    }
}

afterEvaluate {
    publishing {
        publications {
            create<MavenPublication>("release") {
                from(components["release"])
                artifactId = "nexus-sign-android-calls"
            }
        }
    }
}

dependencies {
    api("com.nexis:nexus-sign-android")
    // libwebrtc for Android, prebuilt by the webrtc-sdk project (Maven Central,
    // io.github.webrtc-sdk:android). Exact version; DEVELOPMENT APPROVAL ONLY:
    // provenance, checksum and licence review are open release blockers, see
    // docs/engineering/DECISION_LOG.md D-015 and THIRD_PARTY_MEDIA.md.
    implementation("io.github.webrtc-sdk:android:150.7871.01")
    implementation("androidx.lifecycle:lifecycle-runtime-ktx:2.7.0")
    implementation("org.jetbrains.kotlinx:kotlinx-coroutines-android:1.8.1")
}
