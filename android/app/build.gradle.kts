plugins {
    id("com.android.application")
}

android {
    namespace = "com.soyunomas.taltun.android"
    compileSdk = 36

    defaultConfig {
        applicationId = "com.soyunomas.taltun.android"
        minSdk = 33
        targetSdk = 36
        versionCode = 7
        versionName = "0.2.1"
        testInstrumentationRunner = "android.app.Instrumentation"
    }

    buildTypes {
        release {
            isMinifyEnabled = false
        }
    }

    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_17
        targetCompatibility = JavaVersion.VERSION_17
    }

    testOptions {
        unitTests.isReturnDefaultValues = true
    }
}

dependencies {
    testImplementation("junit:junit:4.13.2")
}
