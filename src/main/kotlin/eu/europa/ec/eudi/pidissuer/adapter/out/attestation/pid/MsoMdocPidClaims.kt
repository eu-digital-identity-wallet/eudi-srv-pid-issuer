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

import eu.europa.ec.eudi.pidissuer.domain.ClaimDefinition
import eu.europa.ec.eudi.pidissuer.domain.MsoNameSpace
import eu.europa.ec.eudi.pidissuer.domain.invoke
import java.util.Locale.ENGLISH

internal object MsoMdocPidClaims {
    val nameSpace: MsoNameSpace = pidNameSpace(1)
    val GivenName =
        ClaimDefinition(
            nameSpace,
            "given_name",
            mandatory = true,
            display = mapOf(ENGLISH to "Given Name(s)"),
        )
    val FamilyName =
        ClaimDefinition(
            nameSpace,
            "family_name",
            mandatory = true,
            display = mapOf(ENGLISH to "Family Name(s)"),
        )
    val BirthDate =
        ClaimDefinition(
            nameSpace,
            "birth_date",
            mandatory = true,
            display = mapOf(ENGLISH to "Birth Date"),
        )
    val FamilyNameBirth =
        ClaimDefinition(
            nameSpace,
            "family_name_birth",
            mandatory = false,
            display = mapOf(ENGLISH to "Birth Family Name(s)"),
        )
    val GivenNameBirth =
        ClaimDefinition(
            nameSpace,
            "given_name_birth",
            mandatory = false,
            display = mapOf(ENGLISH to "Birth Given Name(s)"),
        )
    val Sex =
        ClaimDefinition(
            nameSpace,
            "sex",
            mandatory = false,
            display = mapOf(ENGLISH to "Sex"),
        )
    val Nationality =
        ClaimDefinition(
            nameSpace,
            "nationality",
            mandatory = true,
            display = mapOf(ENGLISH to "Nationality"),
        )
    val IssuanceDate =
        ClaimDefinition(
            nameSpace,
            "issuance_date",
            mandatory = false,
            display = mapOf(ENGLISH to "Issuance Date"),
        )
    val ExpiryDate =
        ClaimDefinition(
            nameSpace,
            "expiry_date",
            mandatory = true,
            display = mapOf(ENGLISH to "Expiry Date"),
        )
    val IssuingAuthority =
        ClaimDefinition(
            nameSpace,
            "issuing_authority",
            mandatory = true,
            display = mapOf(ENGLISH to "Issuance Authority"),
        )
    val PlaceOfBirth =
        ClaimDefinition(
            nameSpace,
            "place_of_birth",
            mandatory = true,
            display = mapOf(ENGLISH to "Place of Birth"),
        )
    val ResidenceAddress =
        ClaimDefinition(
            nameSpace,
            "resident_address",
            mandatory = false,
            display = mapOf(ENGLISH to "Resident Address"),
        )
    val ResidenceCountry =
        ClaimDefinition(
            nameSpace,
            "resident_country",
            mandatory = false,
            display = mapOf(ENGLISH to "Resident Country"),
        )
    val ResidenceState =
        ClaimDefinition(
            nameSpace,
            "resident_state",
            mandatory = false,
            display = mapOf(ENGLISH to "Resident State"),
        )
    val ResidenceCity =
        ClaimDefinition(
            nameSpace,
            "resident_city",
            mandatory = false,
            display = mapOf(ENGLISH to "Resident City"),
        )
    val ResidencePostalCode =
        ClaimDefinition(
            nameSpace,
            "resident_postal_code",
            mandatory = false,
            display = mapOf(ENGLISH to "Resident Postal Code"),
        )
    val ResidenceStreet =
        ClaimDefinition(
            nameSpace,
            "resident_street",
            mandatory = false,
            display = mapOf(ENGLISH to "Resident Street"),
        )
    val ResidenceHouseNumber =
        ClaimDefinition(
            nameSpace,
            "resident_house_number",
            mandatory = false,
            display = mapOf(ENGLISH to "Resident House Number"),
        )
    val DocumentNumber =
        ClaimDefinition(
            nameSpace,
            "document_number",
            mandatory = false,
            display = mapOf(ENGLISH to "Document Number"),
        )
    val PersonalAdministrativeNumber =
        ClaimDefinition(
            nameSpace,
            "personal_administrative_number",
            mandatory = false,
            display = mapOf(ENGLISH to "Personal Administrative Number"),
        )
    val IssuingCountry =
        ClaimDefinition(
            nameSpace,
            "issuing_country",
            mandatory = true,
            display = mapOf(ENGLISH to "Issuing Country"),
        )
    val IssuingJurisdiction =
        ClaimDefinition(
            nameSpace,
            "issuing_jurisdiction",
            mandatory = false,
            display = mapOf(ENGLISH to "Issuing Jurisdiction"),
        )
    val Portrait =
        ClaimDefinition(
            nameSpace,
            "portrait",
            mandatory = false,
            display = mapOf(ENGLISH to "Portrait Image"),
        )
    val EmailAddress =
        ClaimDefinition(
            nameSpace,
            "email_address",
            mandatory = false,
            display = mapOf(ENGLISH to "Email Address"),
        )
    val MobilePhoneNumberAttribute =
        ClaimDefinition(
            nameSpace,
            "mobile_phone_number",
            mandatory = false,
            display = mapOf(ENGLISH to "Mobile Phone Number"),
        )
    val TrustAnchor =
        ClaimDefinition(
            nameSpace,
            "trust_anchor",
            mandatory = false,
            display =
                mapOf(
                    ENGLISH to "Trust Anchor",
                ),
        )
    val AttestationLegalCategory =
        ClaimDefinition(
            nameSpace,
            "attestation_legal_category",
            mandatory = false,
            display =
                mapOf(
                    ENGLISH to "Attestation Legal Category",
                ),
        )

    fun all(): List<ClaimDefinition> =
        listOf(
            FamilyName,
            GivenName,
            BirthDate,
            PlaceOfBirth,
            Nationality,
            ResidenceAddress,
            ResidenceCountry,
            ResidenceState,
            ResidenceCity,
            ResidencePostalCode,
            ResidenceStreet,
            ResidenceHouseNumber,
            PersonalAdministrativeNumber,
            Portrait,
            FamilyNameBirth,
            GivenNameBirth,
            Sex,
            EmailAddress,
            MobilePhoneNumberAttribute,
            ExpiryDate,
            IssuingAuthority,
            IssuingCountry,
            DocumentNumber,
            IssuingJurisdiction,
            IssuanceDate,
            TrustAnchor,
            AttestationLegalCategory,
        )
}
