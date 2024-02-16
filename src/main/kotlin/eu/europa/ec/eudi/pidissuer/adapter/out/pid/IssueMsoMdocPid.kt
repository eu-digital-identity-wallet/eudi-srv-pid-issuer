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
package eu.europa.ec.eudi.pidissuer.adapter.out.pid

import arrow.core.nonEmptySetOf
import arrow.core.raise.Raise
import arrow.core.raise.withError
import com.nimbusds.jose.JWSAlgorithm
import com.nimbusds.jose.jwk.ECKey
import com.nimbusds.jose.jwk.JWK
import eu.europa.ec.eudi.pidissuer.adapter.out.jose.ValidateProof
import eu.europa.ec.eudi.pidissuer.domain.*
import eu.europa.ec.eudi.pidissuer.port.input.AuthorizationContext
import eu.europa.ec.eudi.pidissuer.port.input.IssueCredentialError
import eu.europa.ec.eudi.pidissuer.port.input.IssueCredentialError.InvalidProof
import eu.europa.ec.eudi.pidissuer.port.out.IssueSpecificCredential
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.async
import kotlinx.coroutines.coroutineScope
import kotlinx.serialization.json.JsonElement
import kotlinx.serialization.json.JsonPrimitive
import org.slf4j.LoggerFactory
import java.util.*

val PidMsoMdocScope: Scope = Scope("${PID_DOCTYPE}_${MSO_MDOC_FORMAT.value}")

private val pidAttributes = pidNameSpace(1) to listOf(

    AttributeDetails(
        name = "family_name",
        display = mapOf(Locale.ENGLISH to "Current Family Name"),
    ),
    AttributeDetails(
        name = "given_name",
        display = mapOf(Locale.ENGLISH to "Current First Names"),
    ),
    AttributeDetails(
        name = "birth_date",
        display = mapOf(Locale.ENGLISH to "Date of Birth"),
    ),
    AttributeDetails(
        name = "age_over_18",
        display = mapOf(Locale.ENGLISH to "Adult or minor"),
    ),
    AttributeDetails(
        name = "age_birth_year",
    ),
    AttributeDetails(
        name = "family_name_birth",
        mandatory = false,
        display = mapOf(Locale.ENGLISH to "Last name(s) or surname(s) of the PID User at the time of birth."),
    ),
    AttributeDetails(
        name = "given_name_birth",
        mandatory = false,
        display = mapOf(Locale.ENGLISH to "First name(s), including middle name(s), of the PID User at the time of birth."),
    ),
    AttributeDetails(
        name = "birth_place",
        mandatory = false,
        display = mapOf(Locale.ENGLISH to "The country, state, and city where the PID User was born."),
    ),
    AttributeDetails(
        name = "birth_country",
        mandatory = false,
        display = mapOf(Locale.ENGLISH to "The country where the PID User was born, as an Alpha-2 country code."),
    ),
    AttributeDetails(
        name = "birth_state",
        mandatory = false,
        display = mapOf(Locale.ENGLISH to "The state, province, district, or local area where the PID User was born. "),
    ),
    AttributeDetails(
        name = "birth_city",
        mandatory = false,
        display = mapOf(Locale.ENGLISH to "The municipality, city, town, or village where the PID User was born. "),
    ),
    AttributeDetails(
        name = "resident_country",
        mandatory = false,
        display = mapOf(
            Locale.ENGLISH to "he country where the PID User currently resides, as an Alpha-2 country code as specified in ISO 3166-1.",
        ),
    ),
    AttributeDetails(
        name = "resident_state",
        mandatory = false,
        display = mapOf(Locale.ENGLISH to "The state, province, district, or local area where the PID User currently resides"),
    ),
    AttributeDetails(
        name = "resident_city",
        mandatory = false,
        display = mapOf(Locale.ENGLISH to "The municipality, city, town, or village where the PID User currently resides."),
    ),
    AttributeDetails(
        name = "resident_postal_code",
        mandatory = false,
        display = mapOf(Locale.ENGLISH to "Postal code of the place where the PID User currently resides."),
    ),
    AttributeDetails(
        name = "resident_street",
        mandatory = false,
        display = mapOf(Locale.ENGLISH to "The name of the street where the PID User currently resides"),
    ),
    AttributeDetails(
        name = "resident_house_number",
        mandatory = false,
        display = mapOf(Locale.ENGLISH to "The house number where the PID User currently resides, including any affix or suffix."),
    ),
    AttributeDetails(
        name = "gender",
        mandatory = false,
        display = mapOf(Locale.ENGLISH to "PID User’s gender, using a value as defined in ISO/IEC 5218."),
    ),
    AttributeDetails(
        name = "nationality",
        mandatory = false,
        display = mapOf(Locale.ENGLISH to "Alpha-2 country code, representing the nationality of the PID User."),
    ),
)

val PidMsoMdocV1: MsoMdocCredentialConfiguration =
    MsoMdocCredentialConfiguration(
        id = CredentialConfigurationId(PidMsoMdocScope.value),
        docType = pidDocType(1),
        display = pidDisplay,
        msoClaims = mapOf(pidAttributes),
        cryptographicBindingMethodsSupported = emptySet(),
        credentialSigningAlgorithmsSupported = emptySet(),
        scope = PidMsoMdocScope,
        proofTypesSupported = nonEmptySetOf(ProofType.Jwt(nonEmptySetOf(JWSAlgorithm.RS256, JWSAlgorithm.ES256))),
    )

//
// Meta
//

private fun pidDomesticNameSpace(v: Int?, countryCode: String): MsoNameSpace =
    if (v == null) "$PID_DOCTYPE.$countryCode"
    else "$PID_DOCTYPE.$countryCode.$v"

private fun pidNameSpace(v: Int?): MsoNameSpace = pidDocType(v)

/**
 * Service for issuing PID MsoMdoc credential
 */
class IssueMsoMdocPid(
    credentialIssuerId: CredentialIssuerId,
    private val getPidData: GetPidData,
    private val encodePidInCbor: EncodePidInCbor,
) : IssueSpecificCredential<JsonElement> {

    private val log = LoggerFactory.getLogger(IssueMsoMdocPid::class.java)

    private val validateProof = ValidateProof(credentialIssuerId)
    override val supportedCredential: CredentialConfiguration
        get() = PidMsoMdocV1
    override val publicKey: JWK? = null

    context(Raise<IssueCredentialError>)
    override suspend fun invoke(
        authorizationContext: AuthorizationContext,
        request: CredentialRequest,
        expectedCNonce: CNonce,
    ): CredentialResponse<JsonElement> = coroutineScope {
        log.info("Handling issuance request ...")
        val holderPubKey = async(Dispatchers.Default) { holderPubKey(request, expectedCNonce) }
        val pidData = async { getPidData(authorizationContext) }
        val (pid, pidMetaData) = pidData.await()
        val cbor = encodePidInCbor(pid, pidMetaData, holderPubKey.await()).also {
            log.info("Issued $it")
        }
        CredentialResponse.Issued(JsonPrimitive(cbor))
    }

    context(Raise<IssueCredentialError>)
    private fun holderPubKey(request: CredentialRequest, expectedCNonce: CNonce): ECKey {
        val key = validateProof(request.unvalidatedProof, expectedCNonce, supportedCredential)
        return withError({ _: Throwable -> InvalidProof("Only EC Key is supported") }) {
            when (key) {
                is CredentialKey.DIDUrl -> raise(InvalidProof("DID not supported"))
                is CredentialKey.Jwk -> key.value.toECKey()
                is CredentialKey.X5c -> ECKey.parse(key.certificate)
            }
        }
    }
}
