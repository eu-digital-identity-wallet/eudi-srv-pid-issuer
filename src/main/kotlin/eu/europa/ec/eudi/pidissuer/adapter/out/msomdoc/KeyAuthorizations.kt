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
import cbor.Cbor
import eu.europa.ec.eudi.pidissuer.domain.Iso180135
import id.walt.mdoc.dataelement.ListElement
import id.walt.mdoc.dataelement.MapElement
import kotlinx.serialization.*
import eu.europa.ec.eudi.pidissuer.adapter.out.msomdoc.cbor as myCbor

typealias NameSpace = String

@JvmInline
@Serializable
value class AuthorizedNameSpaces(
    @Serializable(with = NonEmptyListSerializer::class) val value: NonEmptyList<NameSpace>,
) {
    constructor(first: NameSpace, vararg rest: NameSpace) : this(nonEmptyListOf(first, *rest))

    fun toCbor(cbor: Cbor = myCbor): ByteArray = cbor.encodeToByteArray(this)
    fun toCborHex(cbor: Cbor = myCbor): String = cbor.encodeToHexString(this)
    fun toListElement(cbor: Cbor = myCbor): ListElement = cbor.decodeFromByteArray(toCbor(cbor))
}

typealias DataElementIdentifier = String

@JvmInline
@Serializable
value class DataElementsArray(
    @Serializable(with = NonEmptyListSerializer::class) val value: NonEmptyList<DataElementIdentifier>,
) {
    constructor(first: DataElementIdentifier, vararg rest: DataElementIdentifier) : this(nonEmptyListOf(first, *rest))

    fun toCbor(cbor: Cbor = myCbor): ByteArray = cbor.encodeToByteArray(this)
    fun toCborHex(cbor: Cbor = myCbor): String = cbor.encodeToHexString(this)
    fun toListElement(cbor: Cbor = myCbor): ListElement = cbor.decodeFromByteArray(toCbor(cbor))
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

    fun toCbor(cbor: Cbor = myCbor): ByteArray = cbor.encodeToByteArray(this)
    fun toCborHex(cbor: Cbor = myCbor): String = cbor.encodeToHexString(this)
    fun toMapElement(cbor: Cbor = myCbor): MapElement = cbor.decodeFromByteArray(toCbor(cbor))
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

    fun toCbor(cbor: Cbor = myCbor): ByteArray = cbor.encodeToByteArray(this)
    fun toCborHex(cbor: Cbor = myCbor): String = cbor.encodeToHexString(this)
    fun toMapElement(cbor: Cbor = myCbor): MapElement = cbor.decodeFromByteArray(toCbor(cbor))
}
