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
import kotlin.test.*
import kotlin.time.Duration.Companion.seconds

class CredentialReusePolicyTest {

    @Test
    fun `OnceOnly option requires valid batch_size and reissue_trigger_unused`() {
        val option = EudiReusePolicy.OnceOnly(
            batchSize = 10,
            reissueTriggerUnused = 3,
        )
        assertEquals(10, option.batchSize)
        assertEquals(3, option.reissueTriggerUnused)
        assertNull(option.reissueTriggerLifetimeLeft)
    }

    @Test
    fun `OnceOnly option fails with batch_size 1`() {
        assertThrows<IllegalArgumentException> {
            EudiReusePolicy.OnceOnly(
                batchSize = 1,
                reissueTriggerUnused = 0,
            )
        }
    }

    @Test
    fun `OnceOnly option fails when reissue_trigger_unused greater or equal to batch_size`() {
        assertThrows<IllegalArgumentException> {
            EudiReusePolicy.OnceOnly(
                batchSize = 10,
                reissueTriggerUnused = 10,
            )
        }
    }

    @Test
    fun `OnceOnly option fails with negative reissue_trigger_unused`() {
        assertThrows<IllegalArgumentException> {
            EudiReusePolicy.OnceOnly(
                batchSize = 10,
                reissueTriggerUnused = -1,
            )
        }
    }

    @Test
    fun `LimitedTime option requires reissue_trigger_lifetime_left`() {
        val option = EudiReusePolicy.LimitedTime(
            reissueTriggerLifetimeLeft = 655433.seconds,
        )
        assertNull(option.batchSize)
        assertNull(option.reissueTriggerUnused)
        assertEquals(655433.seconds, option.reissueTriggerLifetimeLeft)
    }

    @Test
    fun `LimitedTime option fails with reissue_trigger_lifetime_left zero`() {
        assertThrows<IllegalArgumentException> {
            EudiReusePolicy.LimitedTime(
                reissueTriggerLifetimeLeft = 0.seconds,
            )
        }
    }

    @Test
    fun `LimitedTime option fails with negative reissue_trigger_lifetime_left`() {
        assertThrows<IllegalArgumentException> {
            EudiReusePolicy.LimitedTime(
                reissueTriggerLifetimeLeft = (-1).seconds,
            )
        }
    }

    @Test
    fun `RotatingBatch option requires batch_size and reissue_trigger_lifetime_left`() {
        val option = EudiReusePolicy.RotatingBatch(
            batchSize = 5,
            reissueTriggerLifetimeLeft = 655433.seconds,
        )
        assertEquals(5, option.batchSize)
        assertEquals(655433.seconds, option.reissueTriggerLifetimeLeft)
        assertNull(option.reissueTriggerUnused)
    }

    @Test
    fun `RotatingBatch option fails with batch_size 1`() {
        assertThrows<IllegalArgumentException> {
            EudiReusePolicy.RotatingBatch(
                batchSize = 1,
                reissueTriggerLifetimeLeft = 100.seconds,
            )
        }
    }

    @Test
    fun `PerRelyingParty option requires batch_size, reissue_trigger_lifetime_left, and reissue_trigger_unused`() {
        val option = EudiReusePolicy.PerRelyingParty(
            batchSize = 60,
            reissueTriggerLifetimeLeft = 777543.seconds,
            reissueTriggerUnused = 5,
        )
        assertEquals(60, option.batchSize)
        assertEquals(777543.seconds, option.reissueTriggerLifetimeLeft)
        assertEquals(5, option.reissueTriggerUnused)
    }

    @Test
    fun `PerRelyingParty option fails when reissue_trigger_unused greater or equal to batch_size`() {
        assertThrows<IllegalArgumentException> {
            EudiReusePolicy.PerRelyingParty(
                batchSize = 10,
                reissueTriggerLifetimeLeft = 100.seconds,
                reissueTriggerUnused = 10,
            )
        }
    }

    @Test
    fun `credential reuse policy with single OnceOnly option`() {
        val policy = CredentialReusePolicy.EUDI(
            id = CredentialReusePolicy.EUDI.ARF_ANNEX_II_ID,
            options = listOf(
                EudiReusePolicy.OnceOnly(batchSize = 10, reissueTriggerUnused = 3),
            ),
        )
        assertEquals("arf_annex_ii", policy.id)
        assertTrue(policy.allowsBatchIssuance)
        assertEquals(10, policy.effectiveBatchSize)
    }

    @Test
    fun `credential reuse policy with LimitedTime only does not allow batch issuance`() {
        val policy = CredentialReusePolicy.EUDI(
            id = CredentialReusePolicy.EUDI.ARF_ANNEX_II_ID,
            options = listOf(
                EudiReusePolicy.LimitedTime(reissueTriggerLifetimeLeft = 885433.seconds),
            ),
        )
        assertFalse(policy.allowsBatchIssuance)
        assertNull(policy.effectiveBatchSize)
    }

    @Test
    fun `credential reuse policy with multiple compatible options uses smallest batch size`() {
        val policy = CredentialReusePolicy.EUDI(
            id = CredentialReusePolicy.EUDI.ARF_ANNEX_II_ID,
            options = listOf(
                EudiReusePolicy.RotatingBatch(batchSize = 15, reissueTriggerLifetimeLeft = 885433.seconds),
                EudiReusePolicy.OnceOnly(batchSize = 10, reissueTriggerUnused = 4),
            ),
        )
        assertNotNull(policy)
        assertTrue(policy.allowsBatchIssuance)
        assertEquals(10, policy.effectiveBatchSize)
    }

    @Test
    fun `credential reuse policy rejects OnceOnly and LimitedTime together`() {
        assertThrows<IllegalArgumentException> {
            CredentialReusePolicy.EUDI(
                id = CredentialReusePolicy.EUDI.ARF_ANNEX_II_ID,
                options = listOf(
                    EudiReusePolicy.OnceOnly(batchSize = 10, reissueTriggerUnused = 3),
                    EudiReusePolicy.LimitedTime(reissueTriggerLifetimeLeft = 885433.seconds),
                ),
            )
        }
    }

    @Test
    fun `credential reuse policy rejects duplicate option types`() {
        assertThrows<IllegalArgumentException> {
            CredentialReusePolicy.EUDI(
                id = CredentialReusePolicy.EUDI.ARF_ANNEX_II_ID,
                options = listOf(
                    EudiReusePolicy.OnceOnly(batchSize = 10, reissueTriggerUnused = 3),
                    EudiReusePolicy.OnceOnly(batchSize = 20, reissueTriggerUnused = 5),
                ),
            )
        }
    }

    @Test
    fun `credential reuse policy rejects empty options`() {
        assertThrows<IllegalArgumentException> {
            CredentialReusePolicy.EUDI(
                id = CredentialReusePolicy.EUDI.ARF_ANNEX_II_ID,
                options = emptyList(),
            )
        }
    }

    @Test
    fun `shouldIncludeStatusList is false for LimitedTime policy`() {
        val policy = CredentialReusePolicy.EUDI(
            id = CredentialReusePolicy.EUDI.ARF_ANNEX_II_ID,
            options = listOf(
                EudiReusePolicy.LimitedTime(reissueTriggerLifetimeLeft = 1000.seconds),
            ),
        )
        assertFalse(policy.shouldIncludeStatusList)
    }

    @Test
    fun `shouldIncludeStatusList is true for OnceOnly policy`() {
        val policy = CredentialReusePolicy.EUDI(
            id = CredentialReusePolicy.EUDI.ARF_ANNEX_II_ID,
            options = listOf(
                EudiReusePolicy.OnceOnly(batchSize = 10, reissueTriggerUnused = 3),
            ),
        )
        assertTrue(policy.shouldIncludeStatusList)
    }

    @Test
    fun `shouldIncludeStatusList is true for None policy`() {
        assertTrue(CredentialReusePolicy.None.shouldIncludeStatusList)
    }

    @Test
    fun `ArfAnnex2ReuseMethod fromValue works correctly`() {
        assertEquals(EudiReusePolicyType.OnceOnly, EudiReusePolicyType.fromValue("once_only"))
        assertEquals(EudiReusePolicyType.LimitedTime, EudiReusePolicyType.fromValue("limited_time"))
        assertEquals(EudiReusePolicyType.RotatingBatch, EudiReusePolicyType.fromValue("rotating-batch"))
        assertEquals(EudiReusePolicyType.PerRelyingParty, EudiReusePolicyType.fromValue("per-relying-party"))
        assertNull(EudiReusePolicyType.fromValue("unknown"))
    }
}
