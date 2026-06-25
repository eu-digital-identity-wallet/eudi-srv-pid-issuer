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
package eu.europa.ec.eudi.pidissuer.adapter.out.attestation.pid

import eu.europa.ec.eudi.pidissuer.adapter.out.attestation.*
import eu.europa.ec.eudi.pidissuer.domain.ClaimDefinition
import eu.europa.ec.eudi.pidissuer.domain.ClaimPath
import java.util.*

internal object SdJwtVcPidClaims {
    val FamilyName = OidcFamilyName
    val GivenName = OidcGivenName
    val BirthDate = OidcBirthDate
    val BirthFamilyName = OidcAssuranceBirthFamilyName
    val BirthGivenName = OidcAssuranceBirthGivenName
    val PlaceOfBirth = OidcAssurancePlaceOfBirth
    val Address = OidcAddressClaim
    val Sex =
        ClaimDefinition(
            path = ClaimPath.claim("sex"),
            mandatory = false,
            display = mapOf(Locale.ENGLISH to "Sex"),
        )
    val Nationalities = OidcAssuranceNationalities
    val IssuingAuthority =
        ClaimDefinition(
            path = ClaimPath.claim("issuing_authority"),
            mandatory = true,
            display = mapOf(Locale.ENGLISH to "Issuing Authority"),
        )
    val DocumentNumber =
        ClaimDefinition(
            path = ClaimPath.claim("document_number"),
            mandatory = false,
            display = mapOf(Locale.ENGLISH to "Document Number"),
        )
    val PersonalAdministrativeNumber =
        ClaimDefinition(
            path = ClaimPath.claim("personal_administrative_number"),
            mandatory = false,
            display = mapOf(Locale.ENGLISH to "Personal Administrative Number"),
        )
    val IssuingCountry =
        ClaimDefinition(
            path = ClaimPath.claim("issuing_country"),
            mandatory = true,
            display = mapOf(Locale.ENGLISH to "Issuing Country"),
        )
    val IssuingJurisdiction =
        ClaimDefinition(
            path = ClaimPath.claim("issuing_jurisdiction"),
            mandatory = false,
            display = mapOf(Locale.ENGLISH to "Issuing Jurisdiction"),
        )
    val Email =
        ClaimDefinition(
            path = ClaimPath.claim("email"),
            mandatory = false,
            display = mapOf(Locale.ENGLISH to "Email Address"),
        )
    val PhoneNumber =
        ClaimDefinition(
            path = ClaimPath.claim("phone_number"),
            mandatory = false,
            display = mapOf(Locale.ENGLISH to "Mobile Phone Number"),
        )
    val Picture =
        ClaimDefinition(
            path = ClaimPath.claim("picture"),
            mandatory = false,
            display = mapOf(Locale.ENGLISH to "Portrait Image"),
        )
    val DateOfExpiry =
        ClaimDefinition(
            path = ClaimPath.claim("date_of_expiry"),
            mandatory = true,
            display = mapOf(Locale.ENGLISH to "Expiry Date"),
        )
    val DateOfIssuance =
        ClaimDefinition(
            path = ClaimPath.claim("date_of_issuance"),
            mandatory = false,
            display = mapOf(Locale.ENGLISH to "Issuance Date"),
        )
    val TrustAnchor =
        ClaimDefinition(
            path = ClaimPath.claim("trust_anchor"),
            mandatory = false,
            display =
                mapOf(
                    Locale.ENGLISH to "Trust Anchor",
                ),
        )
    val AttestationLegalCategory =
        ClaimDefinition(
            path = ClaimPath.claim("attestation_legal_category"),
            mandatory = false,
            display =
                mapOf(
                    Locale.ENGLISH to "Attestation Legal Category",
                ),
        )

    fun all(): List<ClaimDefinition> =
        listOf(
            FamilyName,
            GivenName,
            BirthDate,
            PlaceOfBirth.attribute,
            Nationalities,
            Address.attribute,
            PersonalAdministrativeNumber,
            Picture,
            BirthFamilyName,
            BirthGivenName,
            Sex,
            Email,
            PhoneNumber,
            DateOfExpiry,
            IssuingAuthority,
            IssuingCountry,
            DocumentNumber,
            IssuingJurisdiction,
            DateOfIssuance,
            TrustAnchor,
            AttestationLegalCategory,
        )
}
