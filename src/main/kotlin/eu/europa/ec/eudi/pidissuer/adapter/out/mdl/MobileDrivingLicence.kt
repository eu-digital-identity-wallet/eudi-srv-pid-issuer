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

import arrow.core.NonEmptySet
import eu.europa.ec.eudi.pidissuer.domain.MsoDocType
import eu.europa.ec.eudi.pidissuer.domain.MsoNameSpace
import java.time.LocalDate
import java.time.LocalDateTime

/**
 * Get the versioned document type for a mDL.
 */
fun mdlDocType(version: UInt): MsoDocType = "org.iso.18013.5.$version.mDL"

/**
 * Get the versioned namespace for a mDL.
 */
fun mdlNamespace(version: UInt): MsoNameSpace = "org.iso.18013.5.$version"

/**
 * A string that contains characters in the [ISO/IEC 8859-1](https://en.wikipedia.org/wiki/ISO/IEC_8859-1)
 * character set and has a max length of 150 characters.
 *
 * ISO/IEC 8859-1 corresponds to the Latin1 character set, also known as Latin alphabet No. 1.
 * Its characters are contained in the [Basic Latin](https://en.wikipedia.org/wiki/Basic_Latin_(Unicode_block))
 * and [Latin 1 Supplement](https://en.wikipedia.org/wiki/Latin-1_Supplement) Unicode blocks.
 */
@JvmInline
value class Latin150(val value: String) {
    init {
        require(value.length in 1..150) { "value must be at least 1 and at most 150 characters long" }
        require(value.matches(REGEX)) { "value contains non ISO/IEC 8859-1 characters" }
    }

    companion object {

        /**
         * Regular expression used to verify a string contains only ISO/IEC 8859-1 characters.
         *
         * The range 0020-007e corresponds to Basic Latin while the range 00a0-00ff corresponds
         * to Latin 1 Supplement
         */
        val REGEX: Regex = """^[\u0020-\u007e\u00a0-\u00ff]+$""".toRegex()
    }
}

/**
 * Issue and expiry date of an mDL.
 *
 * TODO: issuedAt and expiredAt are defined as either LocalDate or LocalDateTime.
 */
data class IssueAndExpiry(
    val issuedAt: LocalDate,
    val expiresAt: LocalDate,
) {
    init {
        require(issuedAt <= expiresAt)
    }
}

/**
 * An ISO 3166-1 alpha-2 country code.
 */
@JvmInline
value class IsoAlpha2CountryCode(val code: String) {
    init {
        require(code.matches(REGEX)) { "Not a valid ISO 3166-1 alpha-2 country code" }
    }

    companion object {

        /**
         * Regular expression for matching [ISO 3166-1 alpha-2](https://en.wikipedia.org/wiki/ISO_3166-1_alpha-2)
         * country codes.
         *
         * This is merely used for syntactic checks of the input values and does not actually validate whether the
         * matching values correspond to an assigned code.
         */
        val REGEX: Regex = """^[A-Z]{2}$""".toRegex()
    }
}

/**
 * Distinguishing sign of Vehicles of a country according to ISO/IEC 18013-1:2018, Annex F.
 */
@JvmInline
value class DistinguishingSign(val code: String) {
    init {
        require(code.matches(REGEX)) { "Not a valid Distinguishing Sign of Vehicle as per ISO/IEC 18013-1:2018" }
    }

    companion object {

        /**
         * Regular expression for matching [Distinguishing Sings of Vehicles](https://unece.org/DAM/trans/conventn/Distsigns.pdf).
         *
         * This is merely used for syntactic checks of the input values and does not actually validate whether the
         * matching values correspond to assigned code.
         */
        @Suppress("RegExpRedundantEscape")
        val REGEX: Regex = """^[A-Z\./]{1,6}$""".toRegex()
    }
}

/**
 * The country issuing a Mobile Driving Licence.
 */
data class IssuingCountry(
    val countryCode: IsoAlpha2CountryCode,
    val distinguishingSign: DistinguishingSign,
)

/**
 * The issuer of a Mobile Driving Licence.
 */
data class Issuer(
    val country: IssuingCountry,
    val authority: Latin150,
    val jurisdiction: Latin150? = null,
) {
    init {
        jurisdiction?.let {
            require(it.value.startsWith(country.countryCode.code)) { "Issuing Jurisdiction must be in the Issuing Country" }
        }
    }
}

/**
 * An image.
 */
sealed interface Image {

    /**
     * The binary content of the image.
     */
    val content: ByteArray

    /**
     * An image compressed using the JPEG standard.
     */
    @JvmInline
    value class Jpeg(override val content: ByteArray) : Image {
        init {
            require(content.isNotEmpty()) { "content cannot be empty" }
        }
    }

    /**
     * An image compressed using the JPEG2000 standard.
     */
    @JvmInline
    value class Jpeg2000(override val content: ByteArray) : Image {
        init {
            require(content.isNotEmpty()) { "content cannot be empty" }
        }
    }
}

/**
 * The portrait of a Mobile Driving Licence Holder.
 */
data class Portrait(
    val image: Image,
    val capturedAt: LocalDateTime? = null,
)

/**
 * The category of a vehicle as defined in ISO/IEC 18013-1.
 * [Reference](https://unece.org/DAM/trans/doc/2011/wp1/Informal_document_ISOe-UN-EU._comparison.pdf)
 */
enum class VehicleCategory(val code: String) {
    MOTORCYCLE("A"),
    LIGHT_MOTORCYCLE("A1"),
    MEDIUM_MOTORCYCLE("A2"),
    MOPED("AM"),
    LIGHT_VEHICLE("B"),
    LIGHT_VEHICLE_WITH_TRAILER("BE"),
    MOTOR_POWERED_QUADRICYCLE("B1"),
    GOODS_VEHICLE("C"),
    GOODS_VEHICLE_WITH_TRAILER("CE"),
    MEDIUM_GOODS_VEHICLE("C1"),
    MEDIUM_GOODS_VEHICLE_WITH_TRAILER("C1E"),
    PASSENGER_VEHICLE("D"),
    PASSENGER_VEHICLE_WITH_TRAILER("DE"),
    MEDIUM_PASSENGER_VEHICLE("D1"),
    MEDIUM_PASSENGER_VEHICLE_WITH_TRAILER("D1E"),
}

/**
 * Sex as defined in ISO/IEC 5218.
 */
enum class Sex(val code: UInt) {
    NOT_KNOWN(0u),
    MALE(1u),
    FEMALE(2u),
    NOT_APPLICABLE(9u),
}

/**
 * A [UInt] that represents centimeters.
 */
@JvmInline
value class Cm(val value: UInt)

/**
 * Wraps [this] to a [Cm] instance.
 *
 * @receiver the [UInt] to wrap
 * @return the resulting [Cm] instance
 */
fun UInt.cm(): Cm = Cm(this)

/**
 * A [UInt] that represents kilograms.
 */
@JvmInline
value class Kg(val value: UInt)

/**
 * Wraps [this] to a [Kg] instance.
 *
 * @receiver the [UInt] to wrap
 * @return the resulting [Kg] instance
 */
fun UInt.kg(): Kg = Kg(this)

/**
 * A [UInt] that represents a natural number.
 */
@JvmInline
value class Natural(val value: UInt) {
    init {
        require(value > 0u) { "value is not a natural number" }
    }
}

/**
 * Wraps [this] to a [Natural] instance.
 *
 * @receiver the [UInt] to wrap
 * @return the resulting [Natural] instance
 */
fun UInt.natural(): Natural = Natural(this)

/**
 * A [UInt] that represents cubic centimeters.
 */
@JvmInline
value class Cm3(val value: UInt)

/**
 * Wraps [this] to a [Cm3] instance.
 *
 * @receiver the [UInt] to wrap
 * @return the resulting [Cm3] instance
 */
fun UInt.cm3(): Cm3 = Cm3(this)

/**
 * A [UInt] that represents kilowatts.
 */
@JvmInline
value class KWatt(val value: UInt)

/**
 * Wraps [this] to a [KWatt] instance.
 *
 * @receiver the [UInt] to wrap
 * @return the resulting [KWatt] instance
 */
fun UInt.kwatt(): KWatt = KWatt(this)

/**
 * Eye colour as defined in ISO/IEC 18013-5.
 */
enum class EyeColour(val code: String) {
    BLACK("black"),
    BLUE("blue"),
    BROWN("brown"),
    DICHROMATIC("dichromatic"),
    GREY("grey"),
    GREEN("green"),
    HAZEL("hazel"),
    MAROON("maroon"),
    PINK("pink"),
    UNKNOWN("unknown"),
}

/**
 * Hair colour as defined in ISO/IEC 18013-5.
 */
enum class HairColour(val code: String) {
    BALD("bald"),
    BLACK("black"),
    BLOND("blond"),
    Brown("brown"),
    GREY("grey"),
    RED("red"),
    AUBURN("auburn"),
    SANDY("sandy"),
    WHITE("white"),
    UNKNOWN("unknown"),
}

/**
 * Represents a comparison with a value as per ISO/IEC 18013-2 Annex A.
 */
sealed interface Sign<V> {

    val value: V
    val code: String

    data class LessThan<V>(override val value: V) : Sign<V> {
        override val code: String = "<"
    }

    data class LessThanOrEqualTo<V>(override val value: V) : Sign<V> {
        override val code: String = "<="
    }

    data class EqualTo<V>(override val value: V) : Sign<V> {
        override val code: String = "="
    }

    data class MoreThan<V>(override val value: V) : Sign<V> {
        override val code: String = ">"
    }

    data class MoreThanOrEqualTo<V>(override val value: V) : Sign<V> {
        override val code: String = ">="
    }
}

/**
 * A Driving Privilege as defined in ISO/IEC 18013-1:2018, Clause 5.
 */
data class DrivingPrivilege(
    val vehicleCategory: VehicleCategory,
    val issueAndExpiry: IssueAndExpiry? = null,
    val restrictions: NonEmptySet<Restriction>? = null,
) {

    /**
     * Restrictions for a [DrivingPrivilege] as defined in ISO/IEC 18013-2 Annex A.
     */
    sealed interface Restriction {

        val code: String

        /**
         * Generic restrictions for the driver or the vehicle.
         */
        @Suppress("unused")
        enum class GenericRestriction(override val code: String) : Restriction {
            EYESIGHT_CORRECTION_OR_PROTECTION("01"),
            PROSTHETIC_DEVICE_FOR_LIMBS("03"),
            VEHICLE_WITH_AUTOMATIC_TRANSMISSION("78"),
            VEHICLE_WITH_ADAPTER_FOR_PHYSICALLY_DISABLED("S05"),
        }

        /**
         * Parameterized restrictions for the vehicle.
         */
        sealed interface ParameterizedRestriction<V> : Restriction {

            val value: Sign<V>

            data class VehicleAuthorizedMass(override val value: Sign<Kg>) : ParameterizedRestriction<Kg> {
                override val code: String = "S01"
            }

            data class VehicleAuthorizedPassengerSeats(override val value: Sign<Natural>) :
                ParameterizedRestriction<Natural> {
                    override val code: String = "S02"
                }

            data class VehicleCylinderCapacity(override val value: Sign<Cm3>) : ParameterizedRestriction<Cm3> {
                override val code: String = "S03"
            }

            data class VehiclePower(override val value: Sign<KWatt>) : ParameterizedRestriction<KWatt> {
                override val code: String = "S04"
            }
        }
    }
}

/**
 * A [Latin150] value, optionally alongside its [original][utf8] UTF-8 representation.
 */
data class Latin150AndUtf8(
    val latin: Latin150,
    val utf8: String? = null,
)

/**
 * The age of a [Driver].
 */
data class Age(
    val value: Natural,
    val birthYear: Natural? = null,
) {
    val over18: Boolean
        get() = value.value > 18u

    val over21: Boolean
        get() = value.value > 21u
}

/**
 * Details of a residence.
 */
data class Residence(
    val country: IsoAlpha2CountryCode,
    val postalCode: Latin150? = null,
    val state: Latin150? = null,
    val city: Latin150? = null,
    val address: Latin150? = null,
)

/**
 * A Driver for whom a Mobile Driving Licence is issued.
 *
 * TODO: Model and add missing optional 'biometric_template_xx' data element.
 */
data class Driver(
    val familyName: Latin150AndUtf8,
    val givenName: Latin150AndUtf8,
    val birthDate: LocalDate,
    val portrait: Portrait,
    val sex: Sex? = null,
    val height: Cm? = null,
    val weight: Kg? = null,
    val eyeColour: EyeColour? = null,
    val hairColour: HairColour? = null,
    val birthPlace: Latin150? = null,
    val age: Age? = null,
    val nationality: IsoAlpha2CountryCode? = null,
    val residence: Residence? = null,
    val signature: Image? = null,
)

/**
 * A Mobile Driving Licence (mDL) as per ISO/IEC 18013-5.
 */
data class MobileDrivingLicence(
    val driver: Driver,
    val issueAndExpiry: IssueAndExpiry,
    val issuer: Issuer,
    val documentNumber: Latin150,
    val privileges: Set<DrivingPrivilege>,
    val administrativeNumber: Latin150? = null,
)
