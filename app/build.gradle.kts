import java.io.File

plugins {
    id("com.android.application")
    id("org.jetbrains.kotlin.android")
}

android {
    namespace = "com.detect.integrity"
    compileSdk = 34

    defaultConfig {
        applicationId = "com.detect.integrity"
        minSdk = 23
        targetSdk = 34
        versionCode = 1
        versionName = "1.0.0"

        // 发布前建议填入你自己 release 签名的 SHA-256（小写十六进制，无冒号），用于"应用防篡改"检测
        buildConfigField("String", "EXPECTED_SIGNATURE_SHA256", "\"\"")
        // Play Integrity 需要的 Google Cloud 项目号（在 Play 管理中心 > 应用完整性 中绑定）
        buildConfigField("long", "PLAY_CLOUD_PROJECT_NUMBER", "0L")
        // 用于解密 Play Integrity 令牌的自己的服务端地址，留空则只取令牌不解密
        buildConfigField("String", "INTEGRITY_DECRYPT_ENDPOINT", "\"\"")
    }

    // CI 签名配置：仅在环境变量 KEYSTORE_FILE / KEY_ALIAS 存在时生效（见 .github/workflows/android.yml）
    signingConfigs {
        create("ci") {
            val ks = System.getenv("KEYSTORE_FILE").orEmpty()
            if (ks.isNotBlank() && File(ks).exists()) {
                storeFile = file(ks)
                storePassword = System.getenv("KEYSTORE_PASSWORD")
                keyAlias = System.getenv("KEY_ALIAS")
                keyPassword = System.getenv("KEY_PASSWORD")
            }
        }
    }

    buildTypes {
        release {
            val ci = signingConfigs.getByName("ci")
            // 未配置密钥时退回 debug 签名，保证 CI 一定能产出可安装的 APK
            signingConfig = if (ci.storeFile != null) ci else signingConfigs.getByName("debug")
            isMinifyEnabled = false
            proguardFiles(
                getDefaultProguardFile("proguard-android-optimize.txt"),
                "proguard-rules.pro"
            )
        }
    }

    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_17
        targetCompatibility = JavaVersion.VERSION_17
    }

    kotlinOptions {
        jvmTarget = "17"
    }

    buildFeatures {
        viewBinding = true
        buildConfig = true
    }

    packaging {
        resources {
            excludes += "/META-INF/{AL2.0,LGPL2.1}"
        }
    }
}

dependencies {
    implementation("androidx.core:core-ktx:1.13.1")
    implementation("androidx.appcompat:appcompat:1.7.0")
    implementation("com.google.android.material:material:1.12.0")
    implementation("androidx.constraintlayout:constraintlayout:2.1.4")
    implementation("androidx.recyclerview:recyclerview:1.3.2")
    implementation("androidx.preference:preference-ktx:1.2.1")
    implementation("androidx.lifecycle:lifecycle-runtime-ktx:2.8.4")
    implementation("androidx.lifecycle:lifecycle-viewmodel-ktx:2.8.4")
    implementation("org.jetbrains.kotlinx:kotlinx-coroutines-android:1.8.1")

    // Google Play Integrity（设备/应用完整性认证）
    implementation("com.google.android.gms:play-integrity:1.4.0")
    implementation("com.google.android.gms:play-services-base:18.5.0")
}
