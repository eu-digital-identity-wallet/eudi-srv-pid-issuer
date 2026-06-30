/*
 * Copyright (c) 2023-2026 European Commission
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
@file:Suppress("ktlint:standard:max-line-length")

package eu.europa.ec.eudi.pidissuer

import kotlinx.datetime.TimeZone
import org.springframework.boot.test.context.SpringBootTest
import org.springframework.context.ApplicationContextInitializer
import org.springframework.context.annotation.Configuration
import org.springframework.context.annotation.Primary
import org.springframework.context.support.GenericApplicationContext
import org.springframework.core.annotation.AliasFor
import org.springframework.test.context.ContextConfiguration
import kotlin.reflect.KClass
import kotlin.time.Clock

/**
 * Meta annotation to be used with integration tests of [PidIssuerApplication].
 */
@Target(AnnotationTarget.CLASS)
@Retention(AnnotationRetention.RUNTIME)
@SpringBootTest(
    classes = [PidIssuerApplication::class],
    webEnvironment = SpringBootTest.WebEnvironment.MOCK,
    properties = [
        "spring.r2dbc.url=r2dbc:h2:mem:///pid_issuer;DB_CLOSE_DELAY=-1;DATABASE_TO_UPPER=FALSE",
        "spring.r2dbc.username=sa",
        "spring.r2dbc.password=",
        "spring.sql.init.schema-locations=file:docker-compose/postgresql/schema/V1.sql",
        "spring.sql.init.mode=embedded",
    ],
)
@ContextConfiguration
internal annotation class PidIssuerApplicationTest(
    /**
     * [Configuration] classes that contain extra bean definitions.
     * Useful for bean overriding using [Primary] annotation.
     */
    @get:AliasFor(annotation = ContextConfiguration::class)
    val classes: Array<KClass<*>> = [],
    /**
     * Custom [ApplicationContextInitializer] classes.
     * Defaults to [BeansDslApplicationContextInitializer] for production beans.
     * When overriding, the custom initializer MUST invoke [BeansDslApplicationContextInitializer]
     * internally (e.g. test mocks).
     */
    @get:AliasFor(annotation = ContextConfiguration::class)
    val initializers: Array<KClass<out ApplicationContextInitializer<*>>> =
        [BeansDslApplicationContextInitializer::class],
)

/**
 * [ApplicationContextInitializer] for use with [SpringBootTest]/[ContextConfiguration]
 */
internal class BeansDslApplicationContextInitializer : ApplicationContextInitializer<GenericApplicationContext> {
    override fun initialize(applicationContext: GenericApplicationContext) {
        applicationContext.register(beans(Clock.System, TimeZone.currentSystemDefault()))
    }
}
