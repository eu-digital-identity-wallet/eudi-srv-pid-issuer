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
package eu.europa.ec.eudi.pidissuer.adapter.out.mdl

import COSE.AlgorithmID
import COSE.OneKey
import arrow.core.raise.Raise
import com.nimbusds.jose.JWSAlgorithm
import com.nimbusds.jose.jwk.ECKey
import com.nimbusds.jose.util.X509CertChainUtils
import eu.europa.ec.eudi.pidissuer.adapter.out.mdl.DrivingPrivilege.Restriction.GenericRestriction
import eu.europa.ec.eudi.pidissuer.adapter.out.mdl.DrivingPrivilege.Restriction.ParameterizedRestriction
import eu.europa.ec.eudi.pidissuer.domain.AttributeDetails
import eu.europa.ec.eudi.pidissuer.port.input.IssueCredentialError.Unexpected
import id.walt.mdoc.COSECryptoProviderKeyInfo
import id.walt.mdoc.SimpleCOSECryptoProvider
import id.walt.mdoc.dataelement.*
import id.walt.mdoc.doc.MDocBuilder
import id.walt.mdoc.mso.DeviceKeyInfo
import id.walt.mdoc.mso.ValidityInfo
import kotlinx.datetime.toKotlinInstant
import kotlinx.datetime.toKotlinLocalDate
import java.time.Clock
import java.time.LocalDate
import kotlin.io.encoding.Base64
import kotlin.io.encoding.ExperimentalEncodingApi
import kotlin.time.Duration

@OptIn(ExperimentalEncodingApi::class)
class EncodeMobileDrivingLicenceInCborWithWalt(
    private val clock: Clock,
    private val issuerKey: ECKey,
    private val algorithm: JWSAlgorithm,
    private val validityDuration: Duration,
) : EncodeMobileDrivingLicenceInCbor {
    init {
        require(issuerKey.isPrivate) { "a private key is required for signing" }
        require(!issuerKey.keyID.isNullOrBlank()) { "issuer key must have kid" }
        require(!issuerKey.x509CertChain.isNullOrEmpty()) { "issuer key must have an x5c certificate chain" }
        require(algorithm in JWSAlgorithm.Family.EC) { "signing algorithm must be an EC algorithm" }
    }

    private val issuerCryptoProvider: SimpleCOSECryptoProvider by lazy {
        SimpleCOSECryptoProvider(
            listOf(
                COSECryptoProviderKeyInfo(
                    keyID = issuerKey.keyID,
                    algorithmID = algorithm.asAlgorithmId(),
                    publicKey = issuerKey.toECPublicKey(),
                    privateKey = issuerKey.toECPrivateKey(),
                    x5Chain = X509CertChainUtils.parse(issuerKey.x509CertChain),
                    trustedRootCAs = emptyList(),
                ),
            ),
        )
    }

    context(Raise<Unexpected>)
    override suspend fun invoke(licence: MobileDrivingLicence, holderKey: ECKey): String =
        try {
            val validityInfo = validityInfo(clock, validityDuration)
            val deviceKeyInfo: DeviceKeyInfo = getDeviceKeyInfo(holderKey)
            val mdoc = MDocBuilder(MobileDrivingLicenceV1.docType).apply {
                addItemsToSign(licence)
            }.sign(validityInfo, deviceKeyInfo, issuerCryptoProvider, issuerKey.keyID)
            Base64.UrlSafe.encode(mdoc.toCBOR())
        } catch (t: Throwable) {
            raise(Unexpected("Failed to encode mDL", t))
        }
}

private fun JWSAlgorithm.asAlgorithmId(): AlgorithmID =
    when (this) {
        JWSAlgorithm.ES256 -> AlgorithmID.ECDSA_256
        JWSAlgorithm.ES384 -> AlgorithmID.ECDSA_384
        JWSAlgorithm.ES512 -> AlgorithmID.ECDSA_512
        else -> error("Unsupported JWSAlgorithm $this")
    }

private fun validityInfo(clock: Clock, duration: Duration): ValidityInfo {
    val signedAt = clock.instant().toKotlinInstant()
    val validTo = signedAt.plus(duration)
    return ValidityInfo(signed = signedAt, validFrom = signedAt, validUntil = validTo, expectedUpdate = null)
}

private fun getDeviceKeyInfo(deviceKey: ECKey): DeviceKeyInfo {
    val key = OneKey(deviceKey.toECPublicKey(), null)
    val deviceKeyDataElement: MapElement = DataElement.fromCBOR(key.AsCBOR().EncodeToBytes())
    return DeviceKeyInfo(deviceKeyDataElement, null, null)
}

private fun MDocBuilder.addItemsToSign(licence: MobileDrivingLicence) {
    addItemsToSign(licence.driver)
    addItemsToSign(licence.issueAndExpiry)
    addItemsToSign(licence.issuer)
    addItemToSign(DocumentNumber, licence.documentNumber.toDE())
    addItemToSign(DrivingPrivileges, licence.privileges.toDE())
    licence.administrativeNumber?.let { addItemToSign(AdministrativeNumber, it.toDE()) }
}

private fun MDocBuilder.addItemsToSign(driver: Driver) {
    addItemToSign(FamilyName, driver.familyName.latin.toDE())
    addItemToSign(GivenName, driver.givenName.latin.value.toDE())
    addItemToSign(BirthDate, driver.birthDate.toDE())
    addItemToSign(PortraitAttribute, driver.portrait.toDE())
    driver.portrait.capturedAt?.let { addItemToSign(PortraitCaptureDate, it.toLocalDate().toDE()) }
    driver.sex?.let { addItemToSign(SexAttribute, it.toDE()) }
    driver.height?.let { addItemToSign(Height, it.toDE()) }
    driver.weight?.let { addItemToSign(Weight, it.toDE()) }
    driver.eyeColour?.let { addItemToSign(EyeColourAttribute, it.toDE()) }
    driver.hairColour?.let { addItemToSign(HairColourAttribute, it.toDE()) }
    driver.birthPlace?.let { addItemToSign(BirthPlace, it.toDE()) }
    driver.residence?.let { residence ->
        residence.address?.let { addItemToSign(ResidentAddress, it.toDE()) }
        residence.city?.let { addItemToSign(ResidentCity, it.toDE()) }
        residence.state?.let { addItemToSign(ResidentState, it.toDE()) }
        residence.postalCode?.let { addItemToSign(ResidentPostalCode, it.toDE()) }
        addItemToSign(ResidentCountry, residence.country.toDE())
    }
    driver.age?.let { age ->
        addItemToSign(AgeInYears, age.value.toDE())
        age.birthYear?.let { addItemToSign(AgeBirthYear, it.toDE()) }
        addItemToSign(AgeOver18, age.over18.toDE())
        addItemToSign(AgeOver21, age.over21.toDE())
    }
    driver.nationality?.let { addItemToSign(Nationality, it.toDE()) }
    driver.familyName.utf8?.let { addItemToSign(FamilyNameNationalCharacter, it.toDE()) }
    driver.givenName.utf8?.let { addItemToSign(GivenNameNationalCharacter, it.toDE()) }
    driver.signature?.let { addItemToSign(SignatureUsualMark, it.content.toDE()) }
}

private fun MDocBuilder.addItemsToSign(issueAndExpiry: IssueAndExpiry) {
    addItemToSign(IssueDate, issueAndExpiry.issuedAt.toDE())
    addItemToSign(ExpiryDate, issueAndExpiry.expiresAt.toDE())
}

private fun MDocBuilder.addItemsToSign(issuer: Issuer) {
    addItemToSign(IssuingCountryAttribute, issuer.country.countryCode.toDE())
    addItemToSign(IssuingAuthority, issuer.authority.toDE())
    addItemToSign(IssuingCountryDistinguishingSign, issuer.country.distinguishingSign.toDE())
    issuer.jurisdiction?.let { addItemToSign(IssuingJurisdiction, it.toDE()) }
}

private fun MDocBuilder.addItemToSign(attr: AttributeDetails, value: DataElement<*>) {
    addItemToSign(MobileDrivingLicenceV1Namespace, attr.name, value)
}

private fun Latin150.toDE(): StringElement = StringElement(value)
private fun LocalDate.toDE(): FullDateElement = FullDateElement(this.toKotlinLocalDate())
private fun ByteArray.toDE(): ByteStringElement = ByteStringElement(this)
private fun Portrait.toDE(): ByteStringElement = this.image.content.toDE()
private fun UInt.toDE(): NumberElement = NumberElement(this)
private fun Sex.toDE(): NumberElement = code.toDE()
private fun Cm.toDE(): NumberElement = value.toDE()
private fun Kg.toDE(): NumberElement = value.toDE()
private fun HairColour.toDE(): StringElement = StringElement(code)
private fun EyeColour.toDE(): StringElement = StringElement(code)
private fun IsoAlpha2CountryCode.toDE(): StringElement = StringElement(code)
private fun Natural.toDE(): NumberElement = value.toDE()
private fun Boolean.toDE(): BooleanElement = BooleanElement(this)
private fun DistinguishingSign.toDE(): StringElement = StringElement(code)
private fun VehicleCategory.toDE(): StringElement = StringElement(code)
private fun DrivingPrivilege.toDE(): MapElement = MapElement(
    buildMap {
        put(MapKey("vehicle_category_code"), this@toDE.vehicleCategory.toDE())
        this@toDE.issueAndExpiry?.let { issueAndExpiry ->
            put(MapKey("issue_date"), issueAndExpiry.issuedAt.toDE())
            put(MapKey("expiry_date"), issueAndExpiry.expiresAt.toDE())
        }
        this@toDE.restrictions?.let { restrictions ->
            put(MapKey("codes"), restrictions.toDE())
        }
    },
)

@JvmName("convertDrivingPrivileges")
private fun Set<DrivingPrivilege>.toDE(): ListElement = ListElement(this.map { it.toDE() })
private fun DrivingPrivilege.Restriction.toDE(): MapElement = MapElement(
    buildMap {
        val (code, sign, value) =
            when (this@toDE) {
                is GenericRestriction -> Triple(code, null, null)
                is ParameterizedRestriction.VehiclePower -> Triple(
                    code,
                    value.code,
                    value.value.value,
                )

                is ParameterizedRestriction.VehicleAuthorizedMass -> Triple(
                    code,
                    value.code,
                    value.value.value,
                )

                is ParameterizedRestriction.VehicleCylinderCapacity -> Triple(
                    code,
                    value.code,
                    value.value.value,
                )

                is ParameterizedRestriction.VehicleAuthorizedPassengerSeats -> Triple(
                    code,
                    value.code,
                    value.value.value,
                )
            }

        put(MapKey("code"), code.toDE())
        sign?.let { put(MapKey("sign"), it.toDE()) }
        value?.let { put(MapKey("value"), it.toDE()) }
    },
)

@JvmName("convertRestrictions")
private fun Set<DrivingPrivilege.Restriction>.toDE(): ListElement = ListElement(this.map { it.toDE() })
