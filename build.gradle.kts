import org.jetbrains.kotlin.gradle.dsl.KotlinVersion
import org.owasp.dependencycheck.gradle.extension.DependencyCheckExtension
import org.springframework.boot.gradle.tasks.bundling.BootBuildImage

plugins {
    base
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

repositories {
    mavenCentral()
    maven {
        url = uri("https://maven.waltid.dev/releases")
        mavenContent {
        }
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
    implementation(libs.zxing) {
        because("To generate a QR Code for Credentials Offer URI")
    }
    implementation(libs.multiformat) {
        because("To support resolution of did:key")
    }
    implementation(libs.result.monad) {
        because("Optional dependency from org.erwinkok.multiformat:multiformat that we require")
    }
    implementation(libs.nimbus.oauth2) {
        because("To support DPoP")
    }
    implementation(libs.keycloak.admin.client) {
        because("To be able to fetch user attributes")
    }
    implementation(libs.waltid.mdoc.credentials) {
        because("To sign CBOR credentials")
    }
    implementation("org.jetbrains.kotlinx:kotlinx-datetime:0.6.2") {
        because("required by walt.id")
    }
    implementation("com.augustcellars.cose:cose-java:1.1.0") {
        because("required by walt.id")
    }
    implementation(libs.uri.kmp) {
        because("To generate Credentials Offer URIs using custom URIs")
    }
    implementation(libs.tink) {
        because("To support CNonce encryption using XC20P")
    }

    testImplementation(kotlin("test"))
    testImplementation(libs.kotlinx.coroutines.test)
    testImplementation("org.springframework.boot:spring-boot-starter-test")
    testImplementation("org.springframework.security:spring-security-test")
    testImplementation("io.projectreactor:reactor-test")
}

java {
    sourceCompatibility = JavaVersion.toVersion(libs.versions.java.get())
}

kotlin {
    jvmToolchain {
        languageVersion = JavaLanguageVersion.of(libs.versions.java.get())
    }

    compilerOptions {
        apiVersion = KotlinVersion.KOTLIN_2_0
        freeCompilerArgs.addAll(
            "-Xjsr305=strict",
            "-Xconsistent-data-class-copy-visibility",
        )
        optIn = listOf(
            "kotlinx.serialization.ExperimentalSerializationApi",
            "kotlin.io.encoding.ExperimentalEncodingApi",
            "kotlin.contracts.ExperimentalContracts",
        )
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
