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
package eu.europa.ec.eudi.pidissuer.domain

import org.junit.jupiter.api.Test
import org.junit.jupiter.api.assertThrows
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertNotNull
import kotlin.test.assertNull
import kotlin.test.assertTrue

class CredentialReusePolicyTest {

    @Test
    fun `once_only option requires batch_size and reissue_trigger_unused`() {
        val option = ArfReusePolicyOption(
            details = listOf(ArfReuseMethod.OnceOnly),
            batchSize = 10,
            reissueTriggerUnused = 3,
        )
        assertTrue(option.allowsBatchIssuance)
        assertEquals(10, option.batchSize)
        assertEquals(3, option.reissueTriggerUnused)
    }

    @Test
    fun `once_only option fails without batch_size`() {
        assertThrows<IllegalArgumentException> {
            ArfReusePolicyOption(
                details = listOf(ArfReuseMethod.OnceOnly),
                reissueTriggerUnused = 3,
            )
        }
    }

    @Test
    fun `once_only option fails without reissue_trigger_unused`() {
        assertThrows<IllegalArgumentException> {
            ArfReusePolicyOption(
                details = listOf(ArfReuseMethod.OnceOnly),
                batchSize = 10,
            )
        }
    }

    @Test
    fun `once_only option fails when reissue_trigger_unused greater or equal to batch_size`() {
        assertThrows<IllegalArgumentException> {
            ArfReusePolicyOption(
                details = listOf(ArfReuseMethod.OnceOnly),
                batchSize = 10,
                reissueTriggerUnused = 10,
            )
        }
    }

    @Test
    fun `limited_time option requires reissue_trigger_lifetime_left`() {
        val option = ArfReusePolicyOption(
            details = listOf(ArfReuseMethod.LimitedTime),
            reissueTriggerLifetimeLeft = 655433,
        )
        assertFalse(option.allowsBatchIssuance)
        assertNull(option.batchSize)
        assertEquals(655433, option.reissueTriggerLifetimeLeft)
    }

    @Test
    fun `limited_time option fails without reissue_trigger_lifetime_left`() {
        assertThrows<IllegalArgumentException> {
            ArfReusePolicyOption(
                details = listOf(ArfReuseMethod.LimitedTime),
            )
        }
    }

    @Test
    fun `details must contain exactly one of once_only or limited_time`() {
        assertThrows<IllegalArgumentException> {
            ArfReusePolicyOption(
                details = listOf(ArfReuseMethod.OnceOnly, ArfReuseMethod.LimitedTime),
                batchSize = 10,
                reissueTriggerUnused = 3,
                reissueTriggerLifetimeLeft = 100,
            )
        }
    }

    @Test
    fun `details must contain at least once_only or limited_time`() {
        assertThrows<IllegalArgumentException> {
            ArfReusePolicyOption(
                details = listOf(ArfReuseMethod.RotatingBatch),
                batchSize = 10,
                reissueTriggerLifetimeLeft = 100,
            )
        }
    }

    @Test
    fun `limited_time with rotating-batch requires batch_size and reissue_trigger_lifetime_left`() {
        val option = ArfReusePolicyOption(
            details = listOf(ArfReuseMethod.LimitedTime, ArfReuseMethod.RotatingBatch),
            batchSize = 5,
            reissueTriggerLifetimeLeft = 655433,
        )
        assertTrue(option.allowsBatchIssuance)
        assertEquals(5, option.batchSize)
    }

    @Test
    fun `limited_time with per-relying-party requires batch_size and reissue_trigger_lifetime_left`() {
        val option = ArfReusePolicyOption(
            details = listOf(ArfReuseMethod.LimitedTime, ArfReuseMethod.PerRelyingParty),
            batchSize = 60,
            reissueTriggerLifetimeLeft = 777543,
        )
        assertTrue(option.allowsBatchIssuance)
    }

    @Test
    fun `once_only with rotating-batch and per-relying-party`() {
        val option = ArfReusePolicyOption(
            details = listOf(ArfReuseMethod.OnceOnly, ArfReuseMethod.RotatingBatch, ArfReuseMethod.PerRelyingParty),
            batchSize = 20,
            reissueTriggerUnused = 5,
            reissueTriggerLifetimeLeft = 1000,
        )
        assertTrue(option.allowsBatchIssuance)
        assertEquals(20, option.batchSize)
    }

    @Test
    fun `credential reuse policy with single once_only option`() {
        val policy = CredentialReusePolicy.ArfAnnex2ReusePolicy(
            id = CredentialReusePolicy.ArfAnnex2ReusePolicy.ARF_ANNEX_II_ID,
            options = listOf(
                ArfReusePolicyOption(
                    details = listOf(ArfReuseMethod.OnceOnly),
                    batchSize = 10,
                    reissueTriggerUnused = 3,
                ),
            ),
        )
        assertEquals("arf_annex_ii", policy.id)
        assertTrue(policy.allowsBatchIssuance)
        assertEquals(10, policy.effectiveBatchSize)
    }

    @Test
    fun `credential reuse policy with limited_time only is limited time only`() {
        val policy = CredentialReusePolicy.ArfAnnex2ReusePolicy(
            id = CredentialReusePolicy.ArfAnnex2ReusePolicy.ARF_ANNEX_II_ID,
            options = listOf(
                ArfReusePolicyOption(
                    details = listOf(ArfReuseMethod.LimitedTime),
                    reissueTriggerLifetimeLeft = 885433,
                ),
            ),
        )
        assertFalse(policy.allowsBatchIssuance)
        assertNull(policy.effectiveBatchSize)
    }

    @Test
    fun `credential reuse policy with multiple options - no overlapping details`() {
        val policy = CredentialReusePolicy.ArfAnnex2ReusePolicy(
            id = CredentialReusePolicy.ArfAnnex2ReusePolicy.ARF_ANNEX_II_ID,
            options = listOf(
                ArfReusePolicyOption(
                    details = listOf(ArfReuseMethod.LimitedTime),
                    reissueTriggerLifetimeLeft = 885433,
                ),
                ArfReusePolicyOption(
                    details = listOf(ArfReuseMethod.OnceOnly),
                    batchSize = 10,
                    reissueTriggerUnused = 4,
                ),
            ),
        )
        assertNotNull(policy)
        assertTrue(policy.allowsBatchIssuance)
        assertEquals(10, policy.effectiveBatchSize)
    }

    @Test
    fun `credential reuse policy rejects overlapping details`() {
        assertThrows<IllegalArgumentException> {
            CredentialReusePolicy.ArfAnnex2ReusePolicy(
                id = CredentialReusePolicy.ArfAnnex2ReusePolicy.ARF_ANNEX_II_ID,
                options = listOf(
                    ArfReusePolicyOption(
                        details = listOf(ArfReuseMethod.OnceOnly),
                        batchSize = 10,
                        reissueTriggerUnused = 3,
                    ),
                    ArfReusePolicyOption(
                        details = listOf(ArfReuseMethod.OnceOnly),
                        batchSize = 20,
                        reissueTriggerUnused = 5,
                    ),
                ),
            )
        }
    }

    @Test
    fun `credential reuse policy rejects empty options`() {
        assertThrows<IllegalArgumentException> {
            CredentialReusePolicy.ArfAnnex2ReusePolicy(
                id = CredentialReusePolicy.ArfAnnex2ReusePolicy.ARF_ANNEX_II_ID,
                options = emptyList(),
            )
        }
    }

    @Test
    fun `ArfReuseMethod fromValue works correctly`() {
        assertEquals(ArfReuseMethod.OnceOnly, ArfReuseMethod.fromValue("once_only"))
        assertEquals(ArfReuseMethod.LimitedTime, ArfReuseMethod.fromValue("limited_time"))
        assertEquals(ArfReuseMethod.RotatingBatch, ArfReuseMethod.fromValue("rotating-batch"))
        assertEquals(ArfReuseMethod.PerRelyingParty, ArfReuseMethod.fromValue("per-relying-party"))
        assertNull(ArfReuseMethod.fromValue("unknown"))
    }
}
