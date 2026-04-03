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

/**
 * Represents the details of an ARF Annex II reuse method.
 */
enum class ArfReuseMethod(val value: String) {
    OnceOnly("once_only"),
    LimitedTime("limited_time"),
    RotatingBatch("rotating-batch"),
    PerRelyingParty("per-relying-party"),
    ;

    companion object {
        fun fromValue(value: String): ArfReuseMethod? = entries.firstOrNull { it.value == value }
    }
}

/**
 * A single option within an ARF Annex II credential reuse policy.
 *
 * @param details the reuse methods for this option; must contain exactly one of [ArfReuseMethod.OnceOnly]
 *   or [ArfReuseMethod.LimitedTime] (but not both), and optionally [ArfReuseMethod.RotatingBatch]
 *   and/or [ArfReuseMethod.PerRelyingParty]
 * @param batchSize the size of the batch during issuance; required when details contains
 *   [ArfReuseMethod.OnceOnly], [ArfReuseMethod.RotatingBatch], or [ArfReuseMethod.PerRelyingParty]
 * @param reissueTriggerUnused the lower limit of unused attestations triggering re-issuance;
 *   required when details contains [ArfReuseMethod.OnceOnly]; must be lower than [batchSize]
 * @param reissueTriggerLifetimeLeft seconds before expiration that triggers re-issuance;
 *   required when details contains [ArfReuseMethod.LimitedTime], [ArfReuseMethod.RotatingBatch],
 *   or [ArfReuseMethod.PerRelyingParty]
 */
data class ArfReusePolicyOption(
    val details: List<ArfReuseMethod>,
    val batchSize: Int? = null,
    val reissueTriggerUnused: Int? = null,
    val reissueTriggerLifetimeLeft: Long? = null,
) {
    init {
        val hasOnceOnly = ArfReuseMethod.OnceOnly in details
        val hasLimitedTime = ArfReuseMethod.LimitedTime in details
        val hasRotatingBatch = ArfReuseMethod.RotatingBatch in details
        val hasPerRelyingParty = ArfReuseMethod.PerRelyingParty in details

        require(hasOnceOnly xor hasLimitedTime) {
            "'details' must contain exactly one of 'once_only' or 'limited_time'"
        }

        val needsBatchSize = hasOnceOnly || hasRotatingBatch || hasPerRelyingParty
        if (needsBatchSize) {
            requireNotNull(batchSize) { "'batch_size' is required when details contains once_only, rotating-batch, or per-relying-party" }
            require(batchSize > 0) { "'batch_size' must be greater than 0" }
        }

        if (hasOnceOnly) {
            requireNotNull(reissueTriggerUnused) { "'reissue_trigger_unused' is required when details contains 'once_only'" }
            require(reissueTriggerUnused >= 0) { "'reissue_trigger_unused' must be non-negative" }
            requireNotNull(batchSize)
            require(reissueTriggerUnused < batchSize) { "'reissue_trigger_unused' must be lower than 'batch_size'" }
        }

        val needsLifetimeLeft = hasLimitedTime || hasRotatingBatch || hasPerRelyingParty
        if (needsLifetimeLeft) {
            requireNotNull(reissueTriggerLifetimeLeft) {
                "'reissue_trigger_lifetime_left' is required when details contains 'limited_time', 'rotating-batch', or 'per-relying-party'"
            }
            require(reissueTriggerLifetimeLeft > 0) { "'reissue_trigger_lifetime_left' must be greater than 0" }
        }
    }

    val allowsBatchIssuance: Boolean
        get() = ArfReuseMethod.OnceOnly in details ||
            ArfReuseMethod.RotatingBatch in details ||
            ArfReuseMethod.PerRelyingParty in details
}

/**
 * Credential reuse policy as defined in ETSI TS 119 472-3,
 * following the ARF Annex II reuse policies.
 */
sealed interface CredentialReusePolicy {

    /**
     * Returns the effective batch size from the first policy option that allows batch issuance,
     * or null if no option allows batch issuance.
     */
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
    data class ArfAnnex2ReusePolicy(
        val id: String,
        val options: List<ArfReusePolicyOption>,
    ) : CredentialReusePolicy {
        init {
            require(options.isNotEmpty()) { "'options' must not be empty" }

            // Validate no overlapping details across options
            val allDetails = options.flatMap { it.details }
            require(allDetails.size == allDetails.distinct().size) {
                "Policy options must not have overlapping 'details' values"
            }
        }

        /**
         * Returns the effective batch size from the first policy option that allows batch issuance,
         * or null if no option allows batch issuance.
         */
        override val effectiveBatchSize: Int?
            get() = options.firstOrNull { it.allowsBatchIssuance }?.batchSize

        /**
         * Returns true if at least one option allows batch issuance.
         */
        override val allowsBatchIssuance: Boolean
            get() = options.any { it.allowsBatchIssuance }

        companion object {
            const val ARF_ANNEX_II_ID = "arf_annex_ii"
        }
    }
}
