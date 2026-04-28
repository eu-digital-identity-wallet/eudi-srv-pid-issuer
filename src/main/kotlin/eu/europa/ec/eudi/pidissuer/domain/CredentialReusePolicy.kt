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

import kotlin.time.Duration

enum class EudiReusePolicyType(val value: String) {
    OnceOnly("once_only"),
    LimitedTime("limited_time"),
    RotatingBatch("rotating-batch"),
    PerRelyingParty("per-relying-party"),
    ;

    companion object {
        fun fromValue(value: String): EudiReusePolicyType? = entries.firstOrNull { it.value == value }
    }
}

private fun validateBatchSize(batchSize: Int) {
    require(batchSize >= 2) { "'batch_size' must be equal or greater than 2" }
}

private fun validateReissueTriggerUnused(reissueTriggerUnused: Int, batchSize: Int) {
    require(reissueTriggerUnused >= 0) { "'reissue_trigger_unused' must be non-negative" }
    require(reissueTriggerUnused < batchSize) { "'reissue_trigger_unused' must be lower than 'batch_size'" }
}

private fun validateReissueTriggerLifetimeLeft(reissueTriggerLifetimeLeft: Duration) {
    require(reissueTriggerLifetimeLeft.isPositive()) { "'reissue_trigger_lifetime_left' must be greater than 0" }
}

/**
 * A single ARF Annex II option in the reuse policy.
 */
sealed interface EudiReusePolicy {

    val batchSize: Int?
    val reissueTriggerUnused: Int?
    val reissueTriggerLifetimeLeft: Duration?

    data class OnceOnly(
        override val batchSize: Int,
        override val reissueTriggerUnused: Int,
    ) : EudiReusePolicy {

        init {
            validateBatchSize(batchSize)
            validateReissueTriggerUnused(reissueTriggerUnused, batchSize)
        }

        override val reissueTriggerLifetimeLeft: Duration? = null
    }

    data class LimitedTime(
        override val reissueTriggerLifetimeLeft: Duration,
    ) : EudiReusePolicy {

        init {
            validateReissueTriggerLifetimeLeft(reissueTriggerLifetimeLeft)
        }

        override val reissueTriggerUnused: Int? = null
        override val batchSize: Int? = null
    }

    data class RotatingBatch(
        override val batchSize: Int,
        override val reissueTriggerLifetimeLeft: Duration,
    ) : EudiReusePolicy {

        init {
            validateBatchSize(batchSize)
            validateReissueTriggerLifetimeLeft(reissueTriggerLifetimeLeft)
        }

        override val reissueTriggerUnused: Int? = null
    }

    data class PerRelyingParty(
        override val batchSize: Int,
        override val reissueTriggerLifetimeLeft: Duration,
        override val reissueTriggerUnused: Int,
    ) : EudiReusePolicy {

        init {
            validateBatchSize(batchSize)
            validateReissueTriggerLifetimeLeft(reissueTriggerLifetimeLeft)
            validateReissueTriggerUnused(reissueTriggerUnused, batchSize)
        }
    }
}

/**
 * Credential reuse policy as defined in ETSI TS 119 472-3,
 * following the ARF Annex II reuse policies.
 */
sealed interface CredentialReusePolicy {

    val effectiveBatchSize: Int?
        get() = null

    /**
     * Returns true if at least one option allows batch issuance.
     */
    val allowsBatchIssuance: Boolean
        get() = true

    /**
     * Represents the absence of a credential reuse policy.
     */
    data object None : CredentialReusePolicy

    /**
     * Credential reuse policy as defined in ETSI TS 119 472-3,
     * following the ARF Annex II reuse policies.
     *
     * @param options the ordered list of policy options; the order represents issuer priority
     */
    data class EUDI(
        val id: String,
        val options: List<EudiReusePolicy>,
    ) : CredentialReusePolicy {
        init {
            require(options.isNotEmpty()) { "'options' must not be empty" }

            // Validate no duplicate option types
            val optionTypes = options.map { it::class }
            require(optionTypes.size == optionTypes.distinct().size) {
                "Policy options must not contain duplicate option types"
            }

            require(options.count { it is EudiReusePolicy.OnceOnly || it is EudiReusePolicy.LimitedTime } <= 1) {
                "Policy options must not contain both 'once_only' and 'limited_time'"
            }
        }

        /**
         * Returns the effective batch size from the smallest policy option that allows batch issuance,
         * or null if no option allows batch issuance.
         */
        override val effectiveBatchSize: Int?
            get() = options.mapNotNull { it.batchSize }.minOrNull()

        /**
         * Returns true if at least one option allows batch issuance.
         */
        override val allowsBatchIssuance: Boolean
            get() = options.any { it.batchSize != null }

        companion object {
            const val ARF_ANNEX_II_ID = "arf_annex_ii"
        }
    }
}

val CredentialReusePolicy.shouldIncludeStatusList: Boolean
    get() = when (this) {
        CredentialReusePolicy.None -> true
        is CredentialReusePolicy.EUDI -> options.none { it is EudiReusePolicy.LimitedTime }
    }
