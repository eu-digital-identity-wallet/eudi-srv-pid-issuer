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
    fun `OnceOnly option requires valid batch_size and reissue_trigger_unused`() {
        val option = ArfAnnex2ReusePolicyOption.OnceOnly(
            batchSize = 10,
            reissueTriggerUnused = 3,
        )
        assertEquals(10, option.batchSize)
        assertEquals(3, option.reissueTriggerUnused)
        assertNull(option.reissueTriggerLifetimeLeft)
    }

    @Test
    fun `OnceOnly option fails with batch_size zero`() {
        assertThrows<IllegalArgumentException> {
            ArfAnnex2ReusePolicyOption.OnceOnly(
                batchSize = 0,
                reissueTriggerUnused = 0,
            )
        }
    }

    @Test
    fun `OnceOnly option fails when reissue_trigger_unused greater or equal to batch_size`() {
        assertThrows<IllegalArgumentException> {
            ArfAnnex2ReusePolicyOption.OnceOnly(
                batchSize = 10,
                reissueTriggerUnused = 10,
            )
        }
    }

    @Test
    fun `OnceOnly option fails with negative reissue_trigger_unused`() {
        assertThrows<IllegalArgumentException> {
            ArfAnnex2ReusePolicyOption.OnceOnly(
                batchSize = 10,
                reissueTriggerUnused = -1,
            )
        }
    }

    @Test
    fun `LimitedTime option requires reissue_trigger_lifetime_left`() {
        val option = ArfAnnex2ReusePolicyOption.LimitedTime(
            reissueTriggerLifetimeLeft = 655433,
        )
        assertNull(option.batchSize)
        assertNull(option.reissueTriggerUnused)
        assertEquals(655433, option.reissueTriggerLifetimeLeft)
    }

    @Test
    fun `LimitedTime option fails with reissue_trigger_lifetime_left zero`() {
        assertThrows<IllegalArgumentException> {
            ArfAnnex2ReusePolicyOption.LimitedTime(
                reissueTriggerLifetimeLeft = 0,
            )
        }
    }

    @Test
    fun `LimitedTime option fails with negative reissue_trigger_lifetime_left`() {
        assertThrows<IllegalArgumentException> {
            ArfAnnex2ReusePolicyOption.LimitedTime(
                reissueTriggerLifetimeLeft = -1,
            )
        }
    }

    @Test
    fun `RotatingBatch option requires batch_size and reissue_trigger_lifetime_left`() {
        val option = ArfAnnex2ReusePolicyOption.RotatingBatch(
            batchSize = 5,
            reissueTriggerLifetimeLeft = 655433,
        )
        assertEquals(5, option.batchSize)
        assertEquals(655433, option.reissueTriggerLifetimeLeft)
        assertNull(option.reissueTriggerUnused)
    }

    @Test
    fun `RotatingBatch option fails with batch_size zero`() {
        assertThrows<IllegalArgumentException> {
            ArfAnnex2ReusePolicyOption.RotatingBatch(
                batchSize = 0,
                reissueTriggerLifetimeLeft = 100,
            )
        }
    }

    @Test
    fun `PerRelyingParty option requires batch_size, reissue_trigger_lifetime_left, and reissue_trigger_unused`() {
        val option = ArfAnnex2ReusePolicyOption.PerRelyingParty(
            batchSize = 60,
            reissueTriggerLifetimeLeft = 777543,
            reissueTriggerUnused = 5,
        )
        assertEquals(60, option.batchSize)
        assertEquals(777543, option.reissueTriggerLifetimeLeft)
        assertEquals(5, option.reissueTriggerUnused)
    }

    @Test
    fun `PerRelyingParty option fails when reissue_trigger_unused greater or equal to batch_size`() {
        assertThrows<IllegalArgumentException> {
            ArfAnnex2ReusePolicyOption.PerRelyingParty(
                batchSize = 10,
                reissueTriggerLifetimeLeft = 100,
                reissueTriggerUnused = 10,
            )
        }
    }

    @Test
    fun `credential reuse policy with single OnceOnly option`() {
        val policy = CredentialReusePolicy.ArfAnnex2ReusePolicy(
            id = CredentialReusePolicy.ArfAnnex2ReusePolicy.ARF_ANNEX_II_ID,
            options = listOf(
                ArfAnnex2ReusePolicyOption.OnceOnly(batchSize = 10, reissueTriggerUnused = 3),
            ),
        )
        assertEquals("arf_annex_ii", policy.id)
        assertTrue(policy.allowsBatchIssuance)
        assertEquals(10, policy.effectiveBatchSize)
    }

    @Test
    fun `credential reuse policy with LimitedTime only does not allow batch issuance`() {
        val policy = CredentialReusePolicy.ArfAnnex2ReusePolicy(
            id = CredentialReusePolicy.ArfAnnex2ReusePolicy.ARF_ANNEX_II_ID,
            options = listOf(
                ArfAnnex2ReusePolicyOption.LimitedTime(reissueTriggerLifetimeLeft = 885433),
            ),
        )
        assertFalse(policy.allowsBatchIssuance)
        assertNull(policy.effectiveBatchSize)
    }

    @Test
    fun `credential reuse policy with multiple compatible options`() {
        val policy = CredentialReusePolicy.ArfAnnex2ReusePolicy(
            id = CredentialReusePolicy.ArfAnnex2ReusePolicy.ARF_ANNEX_II_ID,
            options = listOf(
                ArfAnnex2ReusePolicyOption.OnceOnly(batchSize = 10, reissueTriggerUnused = 4),
                ArfAnnex2ReusePolicyOption.RotatingBatch(batchSize = 15, reissueTriggerLifetimeLeft = 885433),
            ),
        )
        assertNotNull(policy)
        assertTrue(policy.allowsBatchIssuance)
        assertEquals(10, policy.effectiveBatchSize)
    }

    @Test
    fun `credential reuse policy rejects OnceOnly and LimitedTime together`() {
        assertThrows<IllegalArgumentException> {
            CredentialReusePolicy.ArfAnnex2ReusePolicy(
                id = CredentialReusePolicy.ArfAnnex2ReusePolicy.ARF_ANNEX_II_ID,
                options = listOf(
                    ArfAnnex2ReusePolicyOption.OnceOnly(batchSize = 10, reissueTriggerUnused = 3),
                    ArfAnnex2ReusePolicyOption.LimitedTime(reissueTriggerLifetimeLeft = 885433),
                ),
            )
        }
    }

    @Test
    fun `credential reuse policy rejects duplicate option types`() {
        assertThrows<IllegalArgumentException> {
            CredentialReusePolicy.ArfAnnex2ReusePolicy(
                id = CredentialReusePolicy.ArfAnnex2ReusePolicy.ARF_ANNEX_II_ID,
                options = listOf(
                    ArfAnnex2ReusePolicyOption.OnceOnly(batchSize = 10, reissueTriggerUnused = 3),
                    ArfAnnex2ReusePolicyOption.OnceOnly(batchSize = 20, reissueTriggerUnused = 5),
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
    fun `shouldIncludeStatusList is false for LimitedTime policy`() {
        val policy = CredentialReusePolicy.ArfAnnex2ReusePolicy(
            id = CredentialReusePolicy.ArfAnnex2ReusePolicy.ARF_ANNEX_II_ID,
            options = listOf(
                ArfAnnex2ReusePolicyOption.LimitedTime(reissueTriggerLifetimeLeft = 1000),
            ),
        )
        assertFalse(policy.shouldIncludeStatusList)
    }

    @Test
    fun `shouldIncludeStatusList is true for OnceOnly policy`() {
        val policy = CredentialReusePolicy.ArfAnnex2ReusePolicy(
            id = CredentialReusePolicy.ArfAnnex2ReusePolicy.ARF_ANNEX_II_ID,
            options = listOf(
                ArfAnnex2ReusePolicyOption.OnceOnly(batchSize = 10, reissueTriggerUnused = 3),
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
        assertEquals(ArfAnnex2ReuseMethod.ONCE_ONLY, ArfAnnex2ReuseMethod.fromValue("once_only"))
        assertEquals(ArfAnnex2ReuseMethod.LIMITED_TIME, ArfAnnex2ReuseMethod.fromValue("limited_time"))
        assertEquals(ArfAnnex2ReuseMethod.ROTATING_BATCH, ArfAnnex2ReuseMethod.fromValue("rotating-batch"))
        assertEquals(ArfAnnex2ReuseMethod.PER_RELYING_PARTY, ArfAnnex2ReuseMethod.fromValue("per-relying-party"))
        assertNull(ArfAnnex2ReuseMethod.fromValue("unknown"))
    }
}
