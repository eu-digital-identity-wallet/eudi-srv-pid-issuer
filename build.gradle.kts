import org.jetbrains.kotlin.gradle.tasks.KotlinCompile
import org.owasp.dependencycheck.gradle.extension.DependencyCheckExtension
import org.springframework.boot.gradle.tasks.bundling.BootBuildImage
import java.net.URI

plugins {
    base
    alias(libs.plugins.dokka)
    alias(libs.plugins.spring.boot)
    alias(libs.plugins.spring.dependency.management)
    alias(libs.plugins.kotlin.jvm)
    alias(libs.plugins.kotlin.plugin.spring)
    alias(libs.plugins.kotlin.plugin.serialization)
    alias(libs.plugins.spotless)
    alias(libs.plugins.dependency.check)
    alias(libs.plugins.sonarqube)
    jacoco
}

group = "eu.europa.ec.eudi"
version = "0.2.0-SNAPSHOT"

repositories {
    mavenCentral()
    maven {
        url = URI.create("https://s01.oss.sonatype.org/content/repositories/snapshots/")
        this.mavenContent {
            snapshotsOnly()
        }
    }
    maven {
        url = URI.create("https://jitpack.io")
    }
}

dependencies {
    implementation("org.springframework.boot:spring-boot-starter-oauth2-resource-server") {
        because("PID Issuer acts like a OAUTH2 resource server")
    }
    implementation("org.springframework.boot:spring-boot-starter-webflux")
    implementation("org.springframework.boot:spring-boot-starter-thymeleaf") {
        because("For HTML templates")
    }
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
    implementation("org.webjars:webjars-locator-core") {
        because("To support resolution of Webjars static resources")
    }
    implementation(libs.bootstrap) {
        because("For inclusion in HTML templates")
    }
    implementation(libs.qrgen) {
        because("To generate a QR Code for Credentials Offer URI")
    }
    testImplementation(kotlin("test"))
    testImplementation(libs.kotlinx.coroutines.test)
    testImplementation("org.springframework.boot:spring-boot-starter-test")
    testImplementation("org.springframework.security:spring-security-test")
    testImplementation("io.projectreactor:reactor-test")
    testImplementation(libs.nimbus.oauth2)
}

java {
    val javaVersion = libs.versions.java.get()
    sourceCompatibility = JavaVersion.toVersion(javaVersion)
}

kotlin {
    jvmToolchain {
        val javaVersion = libs.versions.java.get()
        languageVersion.set(JavaLanguageVersion.of(javaVersion))
    }
}

tasks.withType<KotlinCompile>().configureEach {
    kotlinOptions {
        freeCompilerArgs += "-Xcontext-receivers"
        freeCompilerArgs += "-Xjsr305=strict"
    }
}

tasks.test {
    finalizedBy(tasks.jacocoTestReport)
}

tasks.jacocoTestReport {
    dependsOn(tasks.test)

    reports {
        xml.required = true
        csv.required = true
        html.required = true
    }
}

testing {
    suites {
        val test by getting(JvmTestSuite::class) {
            useJUnitJupiter()
        }
    }
}

jacoco {
    toolVersion = libs.versions.jacoco.get()
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
            tags = tagStr.split(delimiters = arrayOf("\n", " ")).onEach { println("Tag: $it") }
        }
    }
}

spotless {
    val ktlintVersion = libs.versions.ktlint.get()
    kotlin {
        ktlint(ktlintVersion)
        licenseHeaderFile("FileHeader.txt")
    }
    kotlinGradle {
        ktlint(ktlintVersion)
    }
}

val nvdApiKey: String? = System.getenv("NVD_API_KEY") ?: properties["nvdApiKey"]?.toString()
val dependencyCheckExtension = extensions.findByType(DependencyCheckExtension::class.java)
dependencyCheckExtension?.apply {
    formats = mutableListOf("XML", "HTML")
    nvd.apiKey = nvdApiKey ?: ""
}
