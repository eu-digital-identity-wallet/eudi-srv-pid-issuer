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
package eu.europa.ec.eudi.pidissuer.adapter.out.qr

import arrow.core.raise.result
import com.google.zxing.qrcode.decoder.ErrorCorrectionLevel
import eu.europa.ec.eudi.pidissuer.port.out.qr.Dimensions
import eu.europa.ec.eudi.pidissuer.port.out.qr.Format
import eu.europa.ec.eudi.pidissuer.port.out.qr.GenerateQqCode
import net.glxn.qrgen.core.image.ImageType
import net.glxn.qrgen.javase.QRCode

/**
 * [GenerateQqCode] implementation using QRGen.
 */
class DefaultGenerateQrCode : GenerateQqCode {

    override fun invoke(content: String, format: Format, dimensions: Dimensions): Result<ByteArray> =
        result {
            val imageType =
                when (format) {
                    Format.JPG -> ImageType.JPG
                    Format.GIF -> ImageType.GIF
                    Format.PNG -> ImageType.PNG
                    Format.BMP -> ImageType.BMP
                }

            QRCode.from(content)
                .to(imageType)
                .withSize(dimensions.width.value.toInt(), dimensions.height.value.toInt())
                .withCharset(Charsets.UTF_8.name())
                .withErrorCorrection(ErrorCorrectionLevel.H)
                .stream()
                .toByteArray()
        }
}
