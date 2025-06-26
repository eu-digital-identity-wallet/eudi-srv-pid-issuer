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
package eu.europa.ec.eudi.pidissuer.port.out.qr

import arrow.core.Either
import java.net.URI

enum class Format {
    JPG,
    GIF,
    PNG,
    BMP,
}

@JvmInline
value class Pixels(val value: UInt)

data class Dimensions(val width: Pixels, val height: Pixels)

/**
 * Generates a QR Code.
 */
fun interface GenerateQqCode {

    /**
     * Generates a new QR Code.
     *
     * @param content the content of the QR Code
     * @param format the image format to use
     * @param dimensions the dimensions of the generated QR Code
     */
    operator fun invoke(content: URI, format: Format, dimensions: Dimensions): Either<Throwable, ByteArray>
}
