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
package eu.europa.ec.eudi.pidissuer.port.input

import arrow.core.Either
import arrow.core.raise.either
import eu.europa.ec.eudi.sdjwt.vc.SdJwtVcTypeMetadata
import eu.europa.ec.eudi.sdjwt.vc.Vct
import kotlinx.serialization.Serializable
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.decodeFromStream
import org.springframework.core.io.Resource

@Serializable
data class GetTypeMetadataError(val error: String) {
    companion object {
        val InvalidVct = GetTypeMetadataError("vct is not valid")
        val UnknownVct = GetTypeMetadataError("unknown Vct")
    }
}

class GetTypeMetadata(
    private val knownVct: Map<Vct, Resource>,
) {
    operator fun invoke(vct: String): Either<GetTypeMetadataError, SdJwtVcTypeMetadata> = either {
        val vct = runCatching { Vct(vct) }.getOrElse { raise(GetTypeMetadataError.InvalidVct) }
        val typeMetadataResource = knownVct.getOrElse(vct) { raise(GetTypeMetadataError.UnknownVct) }
        typeMetadataResource.inputStream.use {
            Json.decodeFromStream<SdJwtVcTypeMetadata>(it)
        }
    }
}
