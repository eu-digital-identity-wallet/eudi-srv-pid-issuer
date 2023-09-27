import org.springframework.boot.gradle.tasks.bundling.BootBuildImage

plugins {
    id("org.jetbrains.dokka") version "1.8.20"
    id("org.springframework.boot") version "3.1.4"
    id("io.spring.dependency-management") version "1.1.3"
    kotlin("jvm") version "1.9.0"
    kotlin("plugin.spring") version "1.9.0"
    kotlin("plugin.serialization") version "1.9.0"
    id("com.diffplug.spotless") version "6.20.0"
}

group = "eu.europa.ec.eudi"
version = "0.0.1-SNAPSHOT"

repositories {
    mavenCentral()
}

dependencies {
    implementation("org.springframework.boot:spring-boot-starter-oauth2-resource-server")
    implementation("org.springframework.boot:spring-boot-starter-webflux")
    implementation("com.fasterxml.jackson.module:jackson-module-kotlin")
    implementation("io.projectreactor.kotlin:reactor-kotlin-extensions")
    implementation("org.jetbrains.kotlin:kotlin-reflect")
    implementation("org.jetbrains.kotlinx:kotlinx-coroutines-reactor")
    testImplementation("org.springframework.boot:spring-boot-starter-test")
    testImplementation("io.projectreactor:reactor-test")
}

java {
    sourceCompatibility = JavaVersion.VERSION_17
}

kotlin {
    jvmToolchain(17)
}

testing {
    suites {
        val test by getting(JvmTestSuite::class) {
            useJUnitJupiter()
        }
    }
}

tasks.named<BootBuildImage>("bootBuildImage") {
    imageName.set("$group/${project.name}")
}

val ktlintVersion = "0.50.0"
spotless {
    kotlin {
        ktlint(ktlintVersion)
        licenseHeaderFile("FileHeader.txt")
    }
    kotlinGradle {
        ktlint(ktlintVersion)
    }
}

// tasks.withType<KotlinCompile> {
// 	kotlinOptions {
// 		freeCompilerArgs += "-Xjsr305=strict"
// 		jvmTarget = "17"
// 	}
// }

// tasks.withType<Test> {
// 	useJUnitPlatform()
// }
