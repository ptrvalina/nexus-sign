plugins {
    id("com.android.application")
    kotlin("android")
}

// Release builds (.github/workflows/sandbox-apps.yml) pass the public sandbox
// address and the signing key; a local debug build keeps the defaults.
val defaultServer = (findProperty("sandboxServer") as String?) ?: "http://127.0.0.1:8191"
val releaseKeystore = System.getenv("VOXTEL_KEYSTORE_FILE")

android {
    namespace = "com.nexis.voxtel.sandbox"
    compileSdk = 34

    defaultConfig {
        applicationId = "com.nexis.voxtel.sandbox.bank"
        minSdk = 28
        targetSdk = 34
        versionCode = ((findProperty("versionCode") as String?) ?: "1").toInt()
        versionName = (findProperty("versionName") as String?) ?: "1.0"
        buildConfigField("String", "DEFAULT_SERVER", "\"$defaultServer\"")
    }

    buildFeatures {
        buildConfig = true
    }

    signingConfigs {
        if (releaseKeystore != null) {
            create("release") {
                storeFile = file(releaseKeystore)
                storePassword = System.getenv("VOXTEL_KEYSTORE_PASSWORD")
                keyAlias = System.getenv("VOXTEL_KEY_ALIAS")
                keyPassword = System.getenv("VOXTEL_KEY_PASSWORD")
            }
        }
    }

    buildTypes {
        release {
            isMinifyEnabled = false
            signingConfig = signingConfigs.findByName("release")
        }
    }

    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_17
        targetCompatibility = JavaVersion.VERSION_17
    }

    kotlinOptions {
        jvmTarget = "17"
    }
}

dependencies {
    implementation("com.nexis:nexus-sign-android")
    implementation("androidx.appcompat:appcompat:1.6.1")
    implementation("androidx.lifecycle:lifecycle-runtime-ktx:2.7.0")
    implementation("org.jetbrains.kotlinx:kotlinx-coroutines-android:1.8.1")
}
