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
package eu.europa.ec.eudi.pidissuer.adapter.out.arrow

import arrow.core.raise.result
import kotlinx.coroutines.CancellationException
import kotlin.test.Test
import kotlin.test.assertTrue
import kotlin.test.fail

internal class ResultRaiseTest {

    @Test
    internal fun `catches all non fatal exceptions`() {
        val nonFatal = listOf(
            IllegalArgumentException::class.java,
            IllegalStateException::class.java,
            NumberFormatException::class.java,
        )

        nonFatal.forEach {
            try {
                val result = result {
                    throw it.getDeclaredConstructor().newInstance()
                }
                assertTrue { result.isFailure }
            } catch (e: Throwable) {
                fail("Did not expect Throwable to be thrown", e)
            }
        }
    }

    @Test
    internal fun `does not catch fatal exceptions`() {
        val fatal = listOf(
            ThreadDeath::class.java,
            CancellationException::class.java,
            InterruptedException::class.java,
        )

        fatal.forEach {
            try {
                result {
                    throw it.getDeclaredConstructor().newInstance()
                }
                fail("Expected Throwable to be thrown")
            } catch (e: Throwable) {
                assertTrue { it.isInstance(e) }
            }
        }
    }
}
