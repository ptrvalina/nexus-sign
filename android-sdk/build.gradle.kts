plugins {
    id("com.android.library") version "8.5.2"
    kotlin("android") version "2.4.20"
    kotlin("plugin.serialization") version "1.9.24"
    `maven-publish`
}

group = "com.nexis"
version = rootDir.resolve("../VERSION").readText().trim()

android {
    namespace = "com.nexis.nexussign"
    compileSdk = 34

    defaultConfig {
        minSdk = 28 // StrongBox requires API 28; KeyManager falls back to a TEE-backed key
        consumerProguardFiles("consumer-rules.pro")
    }

    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_17
        targetCompatibility = JavaVersion.VERSION_17
    }

    kotlinOptions {
        jvmTarget = "17"
    }

    buildFeatures {
        buildConfig = false
    }

    // The shared protocol vectors are read where Auth Core generates them.
    sourceSets {
        getByName("test") {
            resources.srcDir("../auth-core/test-vectors")
        }
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
                artifactId = "nexus-sign-android"
            }
        }
    }
}

dependencies {
    implementation("androidx.biometric:biometric:1.1.0")
    implementation("com.squareup.okhttp3:okhttp:4.12.0")
    implementation("org.jetbrains.kotlinx:kotlinx-serialization-json:1.6.3")
    implementation("org.jetbrains.kotlinx:kotlinx-coroutines-android:1.8.1")
    implementation("com.google.android.play:integrity:1.4.0")

    testImplementation("junit:junit:4.13.2")
}
