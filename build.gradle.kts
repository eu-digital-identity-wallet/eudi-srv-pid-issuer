import org.jetbrains.kotlin.gradle.dsl.JvmDefaultMode
import org.jetbrains.kotlin.gradle.dsl.JvmTarget
import org.jetbrains.kotlin.gradle.dsl.KotlinVersion
import org.springframework.boot.gradle.plugin.SpringBootPlugin

plugins {
    alias(libs.plugins.kotlin.jvm)
    alias(libs.plugins.kotlin.plugin.serialization)
    alias(libs.plugins.spring.boot)
    alias(libs.plugins.kotlin.plugin.spring)
    alias(libs.plugins.spotless)
    alias(libs.plugins.kover)
    alias(libs.plugins.dependency.check)
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
    implementation(platform(libs.kotlin.bom))
    implementation(platform(libs.kotlinx.coroutines.bom))
    implementation(platform(libs.kotlinx.serialization.bom))
    implementation(platform(libs.arrow.stack))
    implementation(platform(SpringBootPlugin.BOM_COORDINATES))

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
    implementation(libs.arrow.core.serialization)
    implementation(libs.arrow.fx.coroutines)
    implementation(libs.nimbus.jose.jwt)
    implementation(libs.eudi.sdjwt) {
        because("To Support issuance in SD-JWT-VC format")
    }
    implementation(libs.statium)
    implementation(libs.ktor.client.java)
    implementation(libs.bouncy.castle) {
        because("To support X509 certificates parsing")
    }
    implementation("org.webjars:webjars-locator-lite") {
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
    implementation(libs.waltid.mdoc.credentials) {
        because("To sign CBOR credentials")
    }
    implementation(libs.kotlinx.datetime) {
        because("required by walt.id")
    }
    implementation(libs.cose.java) {
        because("required by walt.id")
    }
    implementation(libs.uri.kmp) {
        because("To generate Credentials Offer URIs using custom URIs")
    }
    implementation(libs.tink) {
        because("To support CNonce encryption using XC20P")
    }

    implementation("org.springframework.boot:spring-boot-starter-data-r2dbc") {
        because("Reactive database access for PostgreSQL persistence adapter")
    }
    runtimeOnly("org.postgresql:r2dbc-postgresql") {
        because("R2DBC driver for PostgreSQL")
    }

    testImplementation(kotlin("test"))
    testImplementation(libs.kotlinx.coroutines.test)
    testImplementation("org.springframework.boot:spring-boot-starter-test")
    testImplementation("org.springframework.security:spring-security-test")
    testImplementation("io.projectreactor:reactor-test")
    testImplementation("org.springframework.boot:spring-boot-webtestclient")
    testRuntimeOnly("io.r2dbc:r2dbc-h2") {
        because("R2DBC driver for H2")
    }
    testRuntimeOnly("com.h2database:h2") {
        because("H2 in-memory database")
    }
}

kotlin {
    jvmToolchain {
        languageVersion = JavaLanguageVersion.of(libs.versions.java.get())
        vendor = JvmVendorSpec.ADOPTIUM
        implementation = JvmImplementation.VENDOR_SPECIFIC
    }

    target {
        compilerOptions {
            javaParameters = true
            jvmDefault = JvmDefaultMode.ENABLE
            jvmTarget = JvmTarget.fromTarget(libs.versions.java.get())
            apiVersion = KotlinVersion.DEFAULT
            languageVersion = KotlinVersion.DEFAULT
            optIn =
                listOf(
                    "kotlinx.serialization.ExperimentalSerializationApi",
                    "kotlin.io.encoding.ExperimentalEncodingApi",
                    "kotlin.contracts.ExperimentalContracts",
                    "kotlin.time.ExperimentalTime",
                    "kotlin.uuid.ExperimentalUuidApi",
                )
            freeCompilerArgs.addAll(
                "-Xjsr305=strict",
                "-Xconsistent-data-class-copy-visibility",
                "-Xcontext-parameters",
            )
        }
    }
}

tasks.test {
    useJUnitPlatform()
}

springBoot {
    buildInfo()
}

tasks.bootBuildImage {
    imageName = "$group/${project.name}"
    publish = false
    environment = System.getenv()

    docker {
        val environment = environment.get()
        publishRegistry {
            environment["REGISTRY_URL"]?.let { url = it }
            environment["REGISTRY_USERNAME"]?.let { username = it }
            environment["REGISTRY_PASSWORD"]?.let { password = it }
        }
        environment["DOCKER_METADATA_OUTPUT_TAGS"]?.let {
            tags = it.split(delimiters = arrayOf("\n", " ")).onEach { tag -> println("Tag: $tag") }
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

dependencyCheck {
    formats = mutableListOf("XML", "HTML")

    nvd {
        apiKey = System.getenv("NVD_API_KEY") ?: properties["nvdApiKey"]?.toString() ?: ""
        delay = 10000
        maxRetryCount = 2
    }
}
