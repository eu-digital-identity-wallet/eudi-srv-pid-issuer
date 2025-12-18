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
import cbor.Cbor
import eu.europa.ec.eudi.pidissuer.domain.Iso180135
import id.walt.mdoc.dataelement.ListElement
import id.walt.mdoc.dataelement.MapElement
import id.walt.mdoc.dataelement.toDataElement
import kotlinx.serialization.*
import eu.europa.ec.eudi.pidissuer.adapter.out.msomdoc.cbor as myCbor

typealias NameSpace = String

@JvmInline
value class AuthorizedNameSpaces(val value: NonEmptyList<NameSpace>) {
    constructor(first: NameSpace, vararg rest: NameSpace) : this(nonEmptyListOf(first, *rest))

    fun toCbor(cbor: Cbor = myCbor): ByteArray = cbor.encodeToByteArray(toListElement())
    fun toCborHex(cbor: Cbor = myCbor): String = cbor.encodeToHexString(toListElement())
    fun toListElement(): ListElement = value.map { it.toDataElement() }.toDataElement()
}

typealias DataElementIdentifier = String

@JvmInline
value class DataElementsArray(val value: NonEmptyList<DataElementIdentifier>) {
    constructor(first: DataElementIdentifier, vararg rest: DataElementIdentifier) : this(nonEmptyListOf(first, *rest))

    fun toCbor(cbor: Cbor = myCbor): ByteArray = cbor.encodeToByteArray(toListElement())
    fun toCborHex(cbor: Cbor = myCbor): String = cbor.encodeToHexString(toListElement())
    fun toListElement(): ListElement = value.map { it.toDataElement() }.toDataElement()
}

@JvmInline
value class AuthorizedDataElements(val value: Map<NameSpace, DataElementsArray>) {
    constructor(
        first: Pair<NameSpace, DataElementsArray>,
        vararg rest: Pair<NameSpace, DataElementsArray>,
    ) : this(mapOf(first, *rest))

    init {
        require(value.isNotEmpty()) { "AuthorizedDataElements must contain at least one NameSpace" }
    }

    fun toCbor(cbor: Cbor = myCbor): ByteArray = cbor.encodeToByteArray(toMapElement())
    fun toCborHex(cbor: Cbor = myCbor): String = cbor.encodeToHexString(toMapElement())
    fun toMapElement(): MapElement =
        buildMap {
            value.forEach { (nameSpace, dataElements) -> put(nameSpace.toDataElement(), dataElements.toListElement()) }
        }.toDataElement()
}

data class KeyAuthorizations(val nameSpaces: AuthorizedNameSpaces? = null, val dataElements: AuthorizedDataElements? = null) {
    constructor(
        first: NameSpace,
        vararg rest: NameSpace,
    ) : this(nameSpaces = AuthorizedNameSpaces(first, *rest), dataElements = null)

    constructor(
        first: Pair<NameSpace, DataElementsArray>,
        vararg rest: Pair<NameSpace, DataElementsArray>,
    ) : this(nameSpaces = null, dataElements = AuthorizedDataElements(first, *rest))

    init {
        require(null != nameSpaces || null != dataElements) {
            "KeyAuthorizations must contain either AuthorizedNameSpaces or AuthorizedDataElements"
        }
        if (null != nameSpaces && null != dataElements) {
            val commonNameSpaces = nameSpaces.value.toSet().intersect(dataElements.value.keys.toSet())
            require(commonNameSpaces.isEmpty()) {
                "NameSpaces included in AuthorizedNameSpaces must not be included in AuthorizedDataElements. " +
                    "Non-compliant NameSpaces: ${commonNameSpaces.joinToString()}"
            }
        }
    }

    fun toCbor(cbor: Cbor = myCbor): ByteArray = cbor.encodeToByteArray(toMapElement())
    fun toCborHex(cbor: Cbor = myCbor): String = cbor.encodeToHexString(toMapElement())
    fun toMapElement(): MapElement =
        buildMap {
            if (null != nameSpaces) {
                put(Iso180135.KEY_AUTHORIZATIONS_NAMESPACES.toDataElement(), nameSpaces.toListElement())
            }

            if (null != dataElements) {
                put(Iso180135.KEY_AUTHORIZATIONS_DATA_ELEMENTS.toDataElement(), dataElements.toMapElement())
            }
        }.toDataElement()
}
