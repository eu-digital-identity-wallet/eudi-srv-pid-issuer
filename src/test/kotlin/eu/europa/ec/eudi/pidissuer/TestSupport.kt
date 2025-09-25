/*
 * Copyright (c) 2023 European Commission
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
package eu.europa.ec.eudi.pidissuer

import eu.europa.ec.eudi.pidissuer.domain.Clock
import org.springframework.boot.test.context.SpringBootTest
import org.springframework.context.ApplicationContextInitializer
import org.springframework.context.annotation.Configuration
import org.springframework.context.annotation.Primary
import org.springframework.context.support.GenericApplicationContext
import org.springframework.core.annotation.AliasFor
import org.springframework.test.context.ContextConfiguration
import kotlin.reflect.KClass

/**
 * Meta annotation to be used with integration tests of [PidIssuerApplication].
 */
@Target(AnnotationTarget.CLASS)
@Retention(AnnotationRetention.RUNTIME)
@SpringBootTest(
    classes = [PidIssuerApplication::class],
    webEnvironment = SpringBootTest.WebEnvironment.MOCK,
)
@ContextConfiguration(initializers = [BeansDslApplicationContextInitializer::class])
internal annotation class PidIssuerApplicationTest(

    /**
     * [Configuration] classes that contain extra bean definitions.
     * Useful for bean overriding using [Primary] annotation.
     */
    @get:AliasFor(annotation = ContextConfiguration::class)
    val classes: Array<KClass<*>> = [],

)

/**
 * [ApplicationContextInitializer] for use with [SpringBootTest]/[ContextConfiguration]
 */
internal class BeansDslApplicationContextInitializer : ApplicationContextInitializer<GenericApplicationContext> {
    override fun initialize(applicationContext: GenericApplicationContext) {
        beans(Clock.System).initializer().initialize(applicationContext)
    }
}
