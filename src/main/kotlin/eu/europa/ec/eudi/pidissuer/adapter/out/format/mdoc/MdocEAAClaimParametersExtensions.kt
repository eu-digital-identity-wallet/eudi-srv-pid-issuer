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
package eu.europa.ec.eudi.pidissuer.adapter.out.format.mdoc

import eu.europa.ec.eudi.pidissuer.domain.ClaimDefinition
import eu.europa.ec.eudi.pidissuer.domain.attributeName
import eu.europa.ec.eudi.pidissuer.domain.nameSpace
import eu.europa.esig.dss.cbades.cbor.CBORObject
import eu.europa.esig.dss.cbades.cbor.CBORObjectFactory
import eu.europa.esig.dss.eaa.mdoc.creation.MdocEAAClaimParameters
import eu.europa.esig.dss.eaa.mdoc.creation.claim.MdocEAAClaim
import kotlinx.datetime.LocalDate
import kotlin.time.Instant

fun MdocEAAClaimParameters.addItemToSign(
    claim: ClaimDefinition,
    value: String,
) {
    addItemToSign(claim, CBORObjectFactory.toCBORObject(value))
}

fun MdocEAAClaimParameters.addItemToSign(
    claim: ClaimDefinition,
    value: UInt,
) {
    addItemToSign(claim, CBORObjectFactory.toCBORObject(value.toInt()))
}

fun MdocEAAClaimParameters.addItemToSign(
    claim: ClaimDefinition,
    value: ByteArray,
) {
    addItemToSign(claim, CBORObjectFactory.toCBORObject(value))
}

fun MdocEAAClaimParameters.addItemToSign(
    claim: ClaimDefinition,
    value: LocalDate,
) {
    addItemToSign(claim, value.toFullDate())
}

fun MdocEAAClaimParameters.addItemToSign(
    claim: ClaimDefinition,
    value: Instant,
) {
    addItemToSign(claim, value.toTDate())
}

fun MdocEAAClaimParameters.addItemToSign(
    claim: ClaimDefinition,
    value: Boolean,
) {
    addItemToSign(claim, CBORObjectFactory.toCBORObject(value))
}

fun MdocEAAClaimParameters.addItemToSign(
    claim: ClaimDefinition,
    value: CBORObject,
) {
    otherClaims.add(MdocEAAClaim.create(claim.nameSpace, claim.attributeName, value))
}

fun MdocEAAClaimParameters.addItemToSign(
    claim: ClaimDefinition,
    value: Collection<CBORObject>,
) {
    otherClaims.add(MdocEAAClaim.create(claim.nameSpace, claim.attributeName, CBORObjectFactory.toCBORObject(value)))
}
