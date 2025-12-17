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
package eu.europa.ec.eudi.pidissuer.adapter.out.msomdoc

import arrow.core.NonEmptyList
import arrow.core.nonEmptyListOf
import arrow.core.serialization.NonEmptyListSerializer
import eu.europa.ec.eudi.pidissuer.domain.Iso180135
import id.walt.mdoc.dataelement.ListElement
import id.walt.mdoc.dataelement.MapElement
import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable
import kotlinx.serialization.decodeFromByteArray
import kotlinx.serialization.encodeToByteArray
import kotlinx.serialization.encodeToHexString
import cbor.Cbor as WaltIdCbor
import eu.europa.ec.eudi.pidissuer.adapter.out.msomdoc.kotlinXSerializationCbor as myKotlinXSerializationCbor
import eu.europa.ec.eudi.pidissuer.adapter.out.msomdoc.waltIdCbor as myWaltIdCbor
import kotlinx.serialization.cbor.Cbor as KotlinXSerializationCbor

typealias NameSpace = String

@JvmInline
@Serializable
value class AuthorizedNameSpaces(
    @Serializable(with = NonEmptyListSerializer::class) val value: NonEmptyList<NameSpace>,
) {
    constructor(first: NameSpace, vararg rest: NameSpace) : this(nonEmptyListOf(first, *rest))

    fun toCbor(cbor: KotlinXSerializationCbor = myKotlinXSerializationCbor): ByteArray = cbor.encodeToByteArray(this)
    fun toCborHex(cbor: KotlinXSerializationCbor = myKotlinXSerializationCbor): String = cbor.encodeToHexString(this)
    fun toListElement(
        kotlinXSerializationCbor: KotlinXSerializationCbor = myKotlinXSerializationCbor,
        waltIdCbor: WaltIdCbor = myWaltIdCbor,
    ): ListElement = waltIdCbor.decodeFromByteArray(toCbor(kotlinXSerializationCbor))
}

typealias DataElementIdentifier = String

@JvmInline
@Serializable
value class DataElementsArray(
    @Serializable(with = NonEmptyListSerializer::class) val value: NonEmptyList<DataElementIdentifier>,
) {
    constructor(first: DataElementIdentifier, vararg rest: DataElementIdentifier) : this(nonEmptyListOf(first, *rest))

    fun toCbor(cbor: KotlinXSerializationCbor = myKotlinXSerializationCbor): ByteArray = cbor.encodeToByteArray(this)
    fun toCborHex(cbor: KotlinXSerializationCbor = myKotlinXSerializationCbor): String = cbor.encodeToHexString(this)
    fun toListElement(
        kotlinXSerializationCbor: KotlinXSerializationCbor = myKotlinXSerializationCbor,
        waltIdCbor: WaltIdCbor = myWaltIdCbor,
    ): ListElement = waltIdCbor.decodeFromByteArray(toCbor(kotlinXSerializationCbor))
}

@JvmInline
@Serializable
value class AuthorizedDataElements(val value: Map<NameSpace, DataElementsArray>) {
    constructor(
        first: Pair<NameSpace, DataElementsArray>,
        vararg rest: Pair<NameSpace, DataElementsArray>,
    ) : this(mapOf(first, *rest))

    init {
        require(value.isNotEmpty()) { "AuthorizedDataElements must contain at least one NameSpace" }
    }

    fun toCbor(cbor: KotlinXSerializationCbor = myKotlinXSerializationCbor): ByteArray = cbor.encodeToByteArray(this)
    fun toCborHex(cbor: KotlinXSerializationCbor = myKotlinXSerializationCbor): String = cbor.encodeToHexString(this)
    fun toMapElement(
        kotlinXSerializationCbor: KotlinXSerializationCbor = myKotlinXSerializationCbor,
        waltIdCbor: WaltIdCbor = myWaltIdCbor,
    ): MapElement = waltIdCbor.decodeFromByteArray(toCbor(kotlinXSerializationCbor))
}

@Serializable
data class KeyAuthorizations(
    @SerialName(Iso180135.KEY_AUTHORIZATIONS_NAMESPACES) val authorizedNameSpaces: AuthorizedNameSpaces?,
    @SerialName(Iso180135.KEY_AUTHORIZATIONS_DATA_ELEMENTS) val dataElements: AuthorizedDataElements?,
) {
    constructor(
        first: NameSpace,
        vararg rest: NameSpace,
    ) : this(authorizedNameSpaces = AuthorizedNameSpaces(first, *rest), dataElements = null)

    constructor(
        first: Pair<NameSpace, DataElementsArray>,
        vararg rest: Pair<NameSpace, DataElementsArray>,
    ) : this(authorizedNameSpaces = null, dataElements = AuthorizedDataElements(first, *rest))

    init {
        require(null != authorizedNameSpaces || null != dataElements) {
            "KeyAuthorizations must contain either AuthorizedNameSpaces or AuthorizedDataElements"
        }
        if (null != authorizedNameSpaces && null != dataElements) {
            val commonNameSpaces = authorizedNameSpaces.value.toSet().intersect(dataElements.value.keys.toSet())
            require(commonNameSpaces.isEmpty()) {
                "NameSpaces included in AuthorizedNameSpaces must not be included in AuthorizedDataElements. " +
                    "Non-compliant NameSpaces: ${commonNameSpaces.joinToString()}"
            }
        }
    }

    fun toCbor(cbor: KotlinXSerializationCbor = myKotlinXSerializationCbor): ByteArray = cbor.encodeToByteArray(this)
    fun toCborHex(cbor: KotlinXSerializationCbor = myKotlinXSerializationCbor): String = cbor.encodeToHexString(this)
    fun toMapElement(
        kotlinXSerializationCbor: KotlinXSerializationCbor = myKotlinXSerializationCbor,
        waltIdCbor: WaltIdCbor = myWaltIdCbor,
    ): MapElement = waltIdCbor.decodeFromByteArray(toCbor(kotlinXSerializationCbor))
}
