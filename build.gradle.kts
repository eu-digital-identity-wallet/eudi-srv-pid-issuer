import org.jetbrains.kotlin.gradle.tasks.KotlinCompile
import org.springframework.boot.gradle.tasks.bundling.BootBuildImage
import java.net.URI
import kotlin.jvm.optionals.getOrNull

plugins {
    base
    alias(libs.plugins.dokka)
    alias(libs.plugins.spring.boot)
    alias(libs.plugins.spring.dependency.management)
    alias(libs.plugins.kotlin.jvm)
    alias(libs.plugins.kotlin.plugin.spring)
    alias(libs.plugins.kotlin.plugin.serialization)
    alias(libs.plugins.spotless)
}

group = "eu.europa.ec.eudi"
version = "0.0.1-SNAPSHOT"

repositories {
    mavenCentral()
    maven {
        url = URI.create("https://s01.oss.sonatype.org/content/repositories/snapshots/")
        this.mavenContent {
            snapshotsOnly()
        }
    }
}

dependencies {
    implementation("org.springframework.boot:spring-boot-starter-oauth2-resource-server") {
        because("PID Issuer acts like a OAUTH2 resource server")
    }
    implementation("org.springframework.boot:spring-boot-starter-webflux")
    implementation("com.fasterxml.jackson.module:jackson-module-kotlin")
    implementation("io.projectreactor.kotlin:reactor-kotlin-extensions")
    implementation("org.jetbrains.kotlin:kotlin-reflect")
    implementation("org.jetbrains.kotlinx:kotlinx-coroutines-reactor")
    implementation(libs.kotlinx.serialization.json)
    implementation(libs.kotlinx.serialization.cbor) {
        because("To serialize PID in CBOR. Experimental")
    }
    implementation(libs.arrow.core) {
        because("Functional programming support")
    }
    implementation(libs.arrow.fx.coroutines)
    implementation(libs.nimbus.jose.jwt)
    implementation(libs.eudi.sdjwt) {
        because("To Support issuance in SD-JWT-VC format")
    }
    implementation(libs.bouncy.castle) {
        because("To support X509 certificates parsing")
    }
    testImplementation(kotlin("test"))
    testImplementation(libs.kotlinx.coroutines.test)
    testImplementation("org.springframework.boot:spring-boot-starter-test")
    testImplementation("org.springframework.security:spring-security-test")
    testImplementation("io.projectreactor:reactor-test")
    testImplementation(libs.nimbus.oauth2)
}

java {
    val javaVersion = getVersionFromCatalog("java")
    sourceCompatibility = JavaVersion.toVersion(javaVersion)
}

kotlin {

    jvmToolchain {
        val javaVersion = getVersionFromCatalog("java")
        languageVersion.set(JavaLanguageVersion.of(javaVersion))
    }
}
fun getVersionFromCatalog(lookup: String): String {
    val versionCatalog: VersionCatalog = extensions.getByType<VersionCatalogsExtension>().named("libs")
    return versionCatalog
        .findVersion(lookup)
        .getOrNull()
        ?.requiredVersion
        ?: throw GradleException("Version '$lookup' is not specified in the version catalog")
}

tasks.withType<KotlinCompile>().configureEach {
    kotlinOptions {
        freeCompilerArgs += "-Xcontext-receivers"
        freeCompilerArgs += "-Xjsr305=strict"
    }
}
testing {
    suites {
        val test by getting(JvmTestSuite::class) {
            useJUnitJupiter()
        }
    }
}

springBoot {
    buildInfo()
}
tasks.named<BootBuildImage>("bootBuildImage") {
    imageName.set("$group/${project.name}")
    publish.set(false)
    environment.set(System.getenv())
    val env = environment.get()
    docker {
        publishRegistry {
            env["REGISTRY_URL"]?.let { url = it }
            env["REGISTRY_USERNAME"]?.let { username = it }
            env["REGISTRY_PASSWORD"]?.let { password = it }
        }
        env["DOCKER_METADATA_OUTPUT_TAGS"]?.let { tagStr ->
            tags = tagStr.split(" ")
        }
    }
}

spotless {
    val ktlintVersion = getVersionFromCatalog("ktlintVersion")
    kotlin {
        ktlint(ktlintVersion)
        licenseHeaderFile("FileHeader.txt")
    }
    kotlinGradle {
        ktlint(ktlintVersion)
    }
}

// tasks.withType<Test> {
// 	useJUnitPlatform()
// }
