plugins {
    id("com.android.application")
    kotlin("android")
}

android {
    namespace = "com.nexis.nexussign.demo"
    compileSdk = 34

    defaultConfig {
        applicationId = "com.nexis.nexussign.demo"
        minSdk = 28
        targetSdk = 34
        versionCode = 1
        versionName = "1.0"
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
    implementation("com.nexis:nexus-sign-android-calls")
    implementation("androidx.appcompat:appcompat:1.6.1")
    implementation("androidx.lifecycle:lifecycle-runtime-ktx:2.7.0")
    implementation("org.jetbrains.kotlinx:kotlinx-coroutines-android:1.8.1")
    implementation("org.jetbrains.kotlinx:kotlinx-serialization-json:1.6.3")
}
