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
package eu.europa.ec.eudi.pidissuer.adapter.out.attestation.mdl

import eu.europa.ec.eudi.pidissuer.domain.ClaimDefinition
import eu.europa.ec.eudi.pidissuer.domain.MsoNameSpace
import eu.europa.ec.eudi.pidissuer.domain.invoke
import java.util.Locale

object MsoMdocMdlV1Claims {
    val nameSpace: MsoNameSpace = mdlNamespace(1u)

    val FamilyName =
        ClaimDefinition(
            nameSpace,
            "family_name",
            mandatory = true,
            display = mapOf(Locale.ENGLISH to "Family Name(s)"),
        )
    val GivenName =
        ClaimDefinition(
            nameSpace,
            "given_name",
            mandatory = true,
            display = mapOf(Locale.ENGLISH to "Given Name(s)"),
        )
    val BirthDate =
        ClaimDefinition(
            nameSpace,
            "birth_date",
            mandatory = true,
            display = mapOf(Locale.ENGLISH to "Birth Date"),
        )
    val IssueDate =
        ClaimDefinition(
            nameSpace,
            "issue_date",
            mandatory = true,
            display = mapOf(Locale.ENGLISH to "Issuance Date"),
        )
    val ExpiryDate =
        ClaimDefinition(
            nameSpace,
            "expiry_date",
            mandatory = true,
            display = mapOf(Locale.ENGLISH to "Expiry Date"),
        )
    val Portrait =
        ClaimDefinition(
            nameSpace,
            "portrait",
            mandatory = true,
            display = mapOf(Locale.ENGLISH to "Portrait Image"),
        )
    val PortraitCaptureDate =
        ClaimDefinition(
            nameSpace,
            "portrait_capture_date",
            mandatory = false,
            display = mapOf(Locale.ENGLISH to "Capture Date of Portrait Image"),
        )
    val Sex =
        ClaimDefinition(
            nameSpace,
            "sex",
            mandatory = false,
            display = mapOf(Locale.ENGLISH to "Sex"),
        )
    val Height =
        ClaimDefinition(
            nameSpace,
            "height",
            mandatory = false,
            display = mapOf(Locale.ENGLISH to "Height"),
        )
    val Weight =
        ClaimDefinition(
            nameSpace,
            "weight",
            mandatory = false,
            display = mapOf(Locale.ENGLISH to "Weight"),
        )
    val HairColour =
        ClaimDefinition(
            nameSpace,
            "hair_colour",
            mandatory = false,
            display = mapOf(Locale.ENGLISH to "Hair Colour"),
        )
    val BirthPlace =
        ClaimDefinition(
            nameSpace,
            "birth_place",
            mandatory = false,
            display = mapOf(Locale.ENGLISH to "Birth Place"),
        )
    val ResidentAddress =
        ClaimDefinition(
            nameSpace,
            "resident_address",
            mandatory = false,
            display =
                buildMap {
                    put(Locale.ENGLISH, "Resident Address")
                },
        )
    val EyeColour =
        ClaimDefinition(
            nameSpace,
            "eye_colour",
            mandatory = false,
            display = mapOf(Locale.ENGLISH to "Eye Colour"),
        )
    val ResidentCity =
        ClaimDefinition(
            nameSpace,
            "resident_city",
            mandatory = false,
            display = mapOf(Locale.ENGLISH to "Resident City"),
        )
    val ResidentState =
        ClaimDefinition(
            nameSpace,
            "resident_state",
            mandatory = false,
            display = mapOf(Locale.ENGLISH to "Resident State"),
        )
    val ResidentPostalCode =
        ClaimDefinition(
            nameSpace,
            "resident_postal_code",
            mandatory = false,
            display = mapOf(Locale.ENGLISH to "Resident Postal Code"),
        )
    val ResidentCountry =
        ClaimDefinition(
            nameSpace,
            "resident_country",
            mandatory = false,
            display =
                buildMap {
                    put(Locale.ENGLISH, "Resident Country")
                },
        )
    val AgeInYears =
        ClaimDefinition(
            nameSpace,
            "age_in_years",
            mandatory = false,
            display = mapOf(Locale.ENGLISH to "Age in Years"),
        )
    val AgeBirthYear =
        ClaimDefinition(
            nameSpace,
            "age_birth_year",
            mandatory = false,
            display = mapOf(Locale.ENGLISH to "Age Year of Birth"),
        )
    val AgeOver18 =
        ClaimDefinition(
            nameSpace,
            "age_over_18",
            mandatory = false,
            display = mapOf(Locale.ENGLISH to "Age Over 18"),
        )
    val AgeOver21 =
        ClaimDefinition(
            nameSpace,
            "age_over_21",
            mandatory = false,
            display = mapOf(Locale.ENGLISH to "Age Over 21"),
        )
    val Nationality =
        ClaimDefinition(
            nameSpace,
            "nationality",
            mandatory = false,
            display =
                buildMap {
                    put(Locale.ENGLISH, "Nationality")
                },
        )
    val FamilyNameNationalCharacter =
        ClaimDefinition(
            nameSpace,
            "family_name_national_character",
            mandatory = false,
            display = mapOf(Locale.ENGLISH to "National Family Name(s)"),
        )
    val GivenNameNationalCharacter =
        ClaimDefinition(
            nameSpace,
            "given_name_national_character",
            mandatory = false,
            display = mapOf(Locale.ENGLISH to "National Given Name(s)"),
        )
    val SignatureUsualMark =
        ClaimDefinition(
            nameSpace,
            "signature_usual_mark",
            mandatory = false,
            display = mapOf(Locale.ENGLISH to "Signature"),
        )
    val IssuingCountry =
        ClaimDefinition(
            nameSpace,
            "issuing_country",
            mandatory = true,
            display =
                buildMap {
                    put(Locale.ENGLISH, "Issuing Country")
                },
        )
    val IssuingAuthority =
        ClaimDefinition(
            nameSpace,
            "issuing_authority",
            mandatory = true,
            display = mapOf(Locale.ENGLISH to "Issuing Authority"),
        )
    val IssuingCountryDistinguishingSign =
        ClaimDefinition(
            nameSpace,
            "un_distinguishing_sign",
            mandatory = true,
            display = mapOf(Locale.ENGLISH to "Distinguishing Sign"),
        )
    val IssuingJurisdiction =
        ClaimDefinition(
            nameSpace,
            "issuing_jurisdiction",
            mandatory = false,
            display =
                buildMap {
                    put(Locale.ENGLISH, "Issuing Jurisdiction")
                },
        )
    val DocumentNumber =
        ClaimDefinition(
            nameSpace,
            "document_number",
            mandatory = true,
            display = mapOf(Locale.ENGLISH to "Document Number"),
        )
    val AdministrativeNumber =
        ClaimDefinition(
            nameSpace,
            "administrative_number",
            mandatory = false,
            display = mapOf(Locale.ENGLISH to "Administrative Number"),
        )
    val DrivingPrivileges =
        ClaimDefinition(
            nameSpace,
            "driving_privileges",
            mandatory = true,
            display = mapOf(Locale.ENGLISH to "Driving Privileges"),
        )

    fun all(): List<ClaimDefinition> =
        listOf(
            FamilyName,
            GivenName,
            BirthDate,
            IssueDate,
            ExpiryDate,
            IssuingCountry,
            IssuingAuthority,
            DocumentNumber,
            Portrait,
            DrivingPrivileges,
            IssuingCountryDistinguishingSign,
            AdministrativeNumber,
            Sex,
            Height,
            Weight,
            EyeColour,
            HairColour,
            BirthPlace,
            ResidentAddress,
            PortraitCaptureDate,
            AgeInYears,
            AgeBirthYear,
            AgeOver18,
            AgeOver21,
            IssuingJurisdiction,
            Nationality,
            ResidentCity,
            ResidentState,
            ResidentPostalCode,
            ResidentCountry,
            FamilyNameNationalCharacter,
            GivenNameNationalCharacter,
            SignatureUsualMark,
        )
}
