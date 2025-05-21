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
import arrow.core.raise.Raise
import arrow.core.raise.catch
import arrow.core.raise.either
import eu.europa.ec.eudi.sdjwt.vc.SdJwtVcTypeMetadata
import eu.europa.ec.eudi.sdjwt.vc.Vct
import kotlinx.serialization.Serializable
import kotlinx.serialization.json.Json
import org.springframework.core.io.ClassPathResource
import java.nio.charset.Charset

// Sealed interface may be not needed here and subject to removal
sealed interface MetadataSuccessResponse {
    @Serializable
    data class Metadata(
        val metadata: SdJwtVcTypeMetadata,
    ) : MetadataSuccessResponse
}

@Serializable
data class GetTypeMetadataError(val error: String) {
    companion object {
        val InvalidVct = GetTypeMetadataError("Provided string could not be converted to VCT")
        val UnrecognisedVct = GetTypeMetadataError("Domain does not recognise VCT")
        val MetadataIncorrectFormat = GetTypeMetadataError("Metadata incorrect format")
    }
}

class GetTypeMetadata(
    private val knownVct: Map<Vct, ClassPathResource>,
) {
    operator fun invoke(vct: String): Either<GetTypeMetadataError, MetadataSuccessResponse> = either {
        val vct = convertToVct(vct)
        val knownClassPath = knownVct.getOrElse(vct) { raise(GetTypeMetadataError.UnrecognisedVct) }
        val convertedMetadata: SdJwtVcTypeMetadata = convertMetadataToSdJwtVcTypeMetadata(knownClassPath)

        MetadataSuccessResponse.Metadata(convertedMetadata)
    }

    fun Raise<GetTypeMetadataError>.convertToVct(vct: String): Vct =
        catch({ Vct(vct) }) {
            raise(GetTypeMetadataError.InvalidVct)
        }

    fun Raise<GetTypeMetadataError>.convertMetadataToSdJwtVcTypeMetadata(knownClassPath: ClassPathResource): SdJwtVcTypeMetadata =
        catch({
            val metadata = knownClassPath.getContentAsString(Charset.defaultCharset())
            Json.decodeFromString(SdJwtVcTypeMetadata.serializer(), metadata)
        }) {
            raise(GetTypeMetadataError.MetadataIncorrectFormat)
        }
}
