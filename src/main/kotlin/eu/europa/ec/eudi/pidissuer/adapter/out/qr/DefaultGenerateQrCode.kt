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
package eu.europa.ec.eudi.pidissuer.adapter.out.qr

import com.google.zxing.BarcodeFormat
import com.google.zxing.EncodeHintType
import com.google.zxing.client.j2se.MatrixToImageConfig
import com.google.zxing.client.j2se.MatrixToImageWriter
import com.google.zxing.common.BitMatrix
import com.google.zxing.qrcode.QRCodeWriter
import com.google.zxing.qrcode.decoder.ErrorCorrectionLevel
import eu.europa.ec.eudi.pidissuer.port.out.qr.Dimensions
import eu.europa.ec.eudi.pidissuer.port.out.qr.Format
import eu.europa.ec.eudi.pidissuer.port.out.qr.GenerateQqCode
import eu.europa.ec.eudi.pidissuer.port.out.qr.Pixels
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import java.io.ByteArrayOutputStream
import java.net.URI

/**
 * [GenerateQqCode] implementation using QRGen.
 */
class DefaultGenerateQrCode : GenerateQqCode {
    private val config = MatrixToImageConfig()

    private fun Pixels.toInt() = value.toInt()

    private val hints =
        mapOf(
            EncodeHintType.CHARACTER_SET to Charsets.UTF_8.name(),
            EncodeHintType.ERROR_CORRECTION to ErrorCorrectionLevel.H,
        )

    private fun matrix(
        content: URI,
        dimensions: Dimensions,
    ): BitMatrix =
        QRCodeWriter().encode(
            content.toString(),
            BarcodeFormat.QR_CODE,
            dimensions.width.toInt(),
            dimensions.height.toInt(),
            hints,
        )

    override suspend fun invoke(
        content: URI,
        format: Format,
        dimensions: Dimensions,
    ): ByteArray =
        withContext(Dispatchers.IO) {
            val matrix = matrix(content, dimensions)
            ByteArrayOutputStream().use {
                MatrixToImageWriter.writeToStream(matrix, format.name, it, config)
                it.toByteArray()
            }
        }
}
