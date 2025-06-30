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
package eu.europa.ec.eudi.pidissuer.adapter.out.jose

import com.nimbusds.jose.jwk.JWK
import eu.europa.ec.eudi.pidissuer.adapter.out.util.getOrThrow
import org.junit.jupiter.api.assertDoesNotThrow
import java.net.URI
import kotlin.test.Test
import kotlin.test.assertEquals

/**
 * Test cases for [resolveDidUrl]
 */
internal class ResolveDidUrlTest {

    @Test
    fun `verify did key method resolution success`() {
        testData.forEach { (did, jwk) ->
            val resolved = assertDoesNotThrow { resolveDidUrl(URI.create(did)).getOrThrow() }
            assertEquals(jwk, resolved)
        }
    }

    /**
     * Test data taken from:
     *
     * 1. [https://w3c-ccg.github.io/did-method-key/](https://w3c-ccg.github.io/did-method-key/)
     * 2. [https://github.com/quartzjer/did-jwk/blob/main/spec.md](https://github.com/quartzjer/did-jwk/blob/main/spec.md)
     *
     * and resolved using [https://dev.uniresolver.io/](https://dev.uniresolver.io/).
     */
    private val testData = mapOf(
        "did:key:z6MkiTBz1ymuepAQ4HEHYSF1H8quG5GLVVQR3djdX3mDooWp" to
            """
                {
                    "kty": "OKP",
                    "crv": "Ed25519",
                    "x": "O2onvM62pC1io6jQKm8Nc2UyFXcd4kOmOsBIoYtZ2ik"
                }
            """.trimIndent(),
        "did:key:z6MkjchhfUsD6mmvni8mCdXHw216Xrm9bQe2mBH1P5RDjVJG" to
            """
                {
                    "kty": "OKP",
                    "crv": "Ed25519",
                    "x": "TLWr9q15-_WrvMr8wmnYXNJlHtS4hbWGnyQa7fCluik"
                }
            """.trimIndent(),
        "did:key:z6MknGc3ocHs3zdPiJbnaaqDi58NGb4pk1Sp9WxWufuXSdxf" to
            """
                {
                    "kty": "OKP",
                    "crv": "Ed25519",
                    "x": "dCK5iHWYBo4yxESKlJrbKQ0PTjW54BsO5fGh5gD-JnQ"
                }
            """.trimIndent(),
        "did:key:z6LShs9GGnqk85isEBzzshkuVWrVKsRp24GnDuHk8QWkARMW" to
            """
                {
                    "kty": "OKP",
                    "crv": "X25519",
                    "x": "W_Vcc7guviK-gPNDBmevVw-uJVamQV5rMNQGUwCqlH0"
                }
            """.trimIndent(),
        "did:key:zQ3shokFTS3brHcDQrn82RUDfCZESWL1ZdCEJwekUDPQiYBme" to
            """
                {
                    "kty": "EC",
                    "crv": "secp256k1",
                    "x": "h0wVx_2iDlOcblulc8E5iEw1EYh5n1RYtLQfeSTyNc0",
                    "y": "O2EATIGbu6DezKFptj5scAIRntgfecanVNXxat1rnwE"
                }
            """.trimIndent(),
        "did:key:zQ3shtxV1FrJfhqE1dvxYRcCknWNjHc3c5X1y3ZSoPDi2aur2" to
            """
                {
                    "kty": "EC",
                    "crv": "secp256k1",
                    "x": "1LjPGVO9OOqfeaUcT9S-Ml_5wQOybbSQ0SGgMgG9U0M",
                    "y": "aq-OS5tX6WqaY6fDHtATYwbIUijr8PvcGWd-FnCNQBM"
                }
            """.trimIndent(),
        "did:key:zQ3shZc2QzApp2oymGvQbzP8eKheVshBHbU4ZYjeXqwSKEn6N" to
            """
                {
                    "kty": "EC",
                    "crv": "secp256k1",
                    "x": "tS0TJpT9-UUpJvjMZUyA0C0oI9l7VW8d2ADptYRJVdM",
                    "y": "RQEb5Z7oO52oHNpYk9lbbuwZmA_GFNenqSjX4joDh-A"
                }
            """.trimIndent(),
        "did:key:zDnaerDaTF5BXEavCrfRZEk316dpbLsfPDZ3WJ5hRTPFU2169" to
            """
                {
                    "kty": "EC",
                    "crv": "P-256",
                    "x": "fyNYMN0976ci7xqiSdag3buk-ZCwgXU4kz9XNkBlNUI",
                    "y": "hW2ojTNfH7Jbi8--CJUo3OCbH3y5n91g-IMA9MLMbTU"
                }
            """.trimIndent(),
        "did:key:zDnaerx9CtbPJ1q36T5Ln5wYt3MQYeGRG5ehnPAmxcf5mDZpv" to
            """
                {
                    "kty": "EC",
                    "crv": "P-256",
                    "x": "igrFmi0whuihKnj9R3Om1SoMph72wUGeFaBbzG2vzns",
                    "y": "efsX5b10x8yjyrj4ny3pGfLcY7Xby1KzgqOdqnsrJIM"
                }
            """.trimIndent(),
        "did:key:z82Lm1MpAkeJcix9K8TMiLd5NMAhnwkjjCBeWHXyu3U4oT2MVJJKXkcVBgjGhnLBn2Kaau9" to
            """
                {
                    "kty": "EC",
                    "crv": "P-384",
                    "x": "lInTxl8fjLKp_UCrxI0WDklahi-7-_6JbtiHjiRvMvhedhKVdHBfi2HCY8t_QJyc",
                    "y": "y6N1IC-2mXxHreETBW7K3mBcw0qGr3CWHCs-yl09yCQRLcyfGv7XhqAngHOu51Zv"
                }
            """.trimIndent(),
        "did:key:z82LkvCwHNreneWpsgPEbV3gu1C6NFJEBg4srfJ5gdxEsMGRJUz2sG9FE42shbn2xkZJh54" to
            """
                {
                    "kty": "EC",
                    "crv": "P-384",
                    "x": "CA-iNoHDg1lL8pvX3d1uvExzVfCz7Rn6tW781Ub8K5MrDf2IMPyL0RTDiaLHC1JT",
                    "y": "Kpnrn8DkXUD3ge4mFxi-DKr0DYO2KuJdwNBrhzLRtfMa3WFMZBiPKUPfJj8dYNl_"
                }
            """.trimIndent(),
        "did:key:z2J9gaYxrKVpdoG9A4gRnmpnRCcxU6agDtFVVBVdn1JedouoZN7SzcyREXXzWgt3gGiwpoHq7K68X4m32D8HgzG8wv3sY5j7" to
            """
                {
                    "kty": "EC",
                    "crv": "P-521",
                    "x": "ASUHPMyichQ0QbHZ9ofNx_l4y7luncn5feKLo3OpJ2nSbZoC7mffolj5uy7s6KSKXFmnNWxGJ42IOrjZ47qqwqyS",
                    "y": "AW9ziIC4ZQQVSNmLlp59yYKrjRY0_VqO-GOIYQ9tYpPraBKUloEId6cI_vynCzlZWZtWpgOM3HPhYEgawQ703RjC"
                }
            """.trimIndent(),
        "did:key:z2J9gcGdb2nEyMDmzQYv2QZQcM1vXktvy1Pw4MduSWxGabLZ9XESSWLQgbuPhwnXN7zP7HpTzWqrMTzaY5zWe6hpzJ2jnw4f" to
            """
                {
                    "kty": "EC",
                    "crv": "P-521",
                    "x": "AQgyFy6EwH3_u_KXPw8aTXTY7WSVytmbuJeFpq4U6LipxtSmBJe_jjRzms9qubnwm_fGoHMQlvQ1vzS2YLusR2V0",
                    "y": "Ab06MCcgoG7dM2I-VppdLV1k3lDoeHMvyYqHVfP05Ep2O7Zu0Qwd6IVzfZi9K0KMDud22wdnGUpUtFukZo0EeO15"
                }
            """.trimIndent(),
        "did:key:${"z4MXj1wBzi9jUstyPMS4jQqB6KdJaiatPkAtVtGc6bQEQEEsKTic4G7Rou3iBf9vPmT5dbkm9qsZsuVNjq8HCuW1w24nhBFGkR" +
            "E4cd2Uf2tfrB3N7h4mnyPp1BF3ZttHTYv3DLUPi1zMdkULiow3M1GfXkoC6DoxDUm1jmN6GBj22SjVsr6dxezRVQc7aj9TxE7JLbMH1" +
            "wh5X3kA58H3DFW8rnYMakFGbca5CB2Jf6CnGQZmL7o5uJAdTwXfy2iiiyPxXEGerMhHwhjTA1mKYobyk2CpeEcmvynADfNZ5MBvcCS7" +
            "m3XkFCMNUYBS9NQ3fze6vMSUPsNa6GVYmKx2x6JrdEjCk3qRMMmyjnjCMfR4pXbRMZa3i"}" to
            """
                {
                    "kty": "RSA",
                    "n": "${"sbX82NTV6IylxCh7MfV4hlyvaniCajuP97GyOqSvTmoEdBOflFvZ06kR_9D6ctt45Fk6hskfnag2GG69NALVH2o4R" +
                "CR6tQiLRpKcMRtDYE_thEmfBvDzm_VVkOIYfxu-Ipuo9J_S5XDNDjczx2v-3oDh5-CIHkU46hvFeCvpUS-L8TJSbgX0kjV" +
                "k_m4eIb9wh63rtmD6Uz_KBtCo5mmR4TEtcLZKYdqMp3wCjN-TlgHiz_4oVXWbHUefCEe8rFnX1iQnpDHU49_SaXQoud1jCa" +
                "exFn25n-Aa8f8bc5Vm-5SeRwidHa6ErvEhTvf1dz6GoNPp2iRvm-wJ1gxwWJEYPQ"}",
                    "e": "AQAB"
                }
            """.trimIndent(),
        "did:key:${"zgghBUVkqmWS8e1ioRVp2WN9Vw6x4NvnE9PGAyQsPqM3fnfPf8EdauiRVfBTcVDyzhqM5FFC7ekAvuV1cJHawtfgB9wDcru1hPD" +
            "obk3hqyedijhgWmsYfJCmodkiiFnjNWATE7PvqTyoCjcmrc8yMRXmFPnoASyT5beUd4YZxTE9VfgmavcPy3BSouNmASMQ8xUXeiRw" +
            "jb7xBaVTiDRjkmyPD7NYZdXuS93gFhyDFr5b3XLg7Rfj9nHEqtHDa7NmAX7iwDAbMUFEfiDEf9hrqZmpAYJracAjTTR8Cvn6mnDXML" +
            "wayNG8dcsXFodxok2qksYF4D8ffUxMRmyyQVQhhhmdSi4YaMPqTnC1J6HTG9Yfb98yGSVaWi4TApUhLXFow2ZvB6vqckCNhjCRL2R4M" +
            "DUSk71qzxWHgezKyDeyThJgdxydrn1osqH94oSeA346eipkJvKqYREXBKwgB5VL6WF4qAK6sVZxJp2dQBfCPVZ4EbsBQaJXaVK7cNcW" +
            "G8tZBFWZ79gG9Cu6C4u8yjBS8Ux6dCcJPUTLtixQu4z2n5dCsVSNdnP1EEs8ZerZo5pBgc68w4Yuf9KL3xVxPnAB1nRCBfs9cMU6oL1" +
            "EdyHbqrTfnjE8HpY164akBqe92LFVsk8RusaGsVPrMekT8emTq5y8v8CabuZg5rDs3f9NPEtogjyx49wiub1FecM5B7QqEcZSYiKHgF" +
            "4mfkteT2"}" to
            """
                {
                    "kty": "RSA",
                    "n": "${"qMCkFFRFWtzUyZeK8mgJdyM6SEQcXC5E6JwCRVDld-jlJs8sXNOE_vliexq34wZRQ4hk53-JPFlvZ_QjRgIxdUxS" +
                "MiZ3S5hlNVvvRaue6SMakA9ugQhnfXaWORro0UbPuHLms-bg5StDP8-8tIezu9c1H1FjwPcdbV6rAvKhyhnsM10qP3v2CP" +
                "bdE0q3FOsihoKuTelImtO110E7N6fLn4U3EYbC4OyViqlrP1o_1M-R-tiM1cb4pD7XKJnIs6ryZdfOQSPBJwjNqSdN6Py_" +
                "tdrFgPDTyacSSdpTVADOM2IMAoYbhV1N5APhnjOHBRFyKkF1HffQKpmXQLBqvUNNjuhmpVKWBtrTdcCKrglFXiw0cKGHKx" +
                "IirjmiOlB_HYHg5UdosyE3_1Txct2U7-WBB6QXak1UgxCzgKYBDI8UPA0RlkUuHHP_Zg0fVXrXIInHO04MYxUeSps5qqyP" +
                "6dJBu_v_BDn3zUq6LYFwJ_-xsU7zbrKYB4jaRlHPoCj_eDC-rSA2uQ4KXHBB8_aAqNFC9ukWxc26Ifz9dF968DLuL30bi-Z" +
                "Aa2oUh492Pw1bg89J7i4qTsOOfpQvGyDV7TGhKuUG3Hbumfr2w16S-_3EI2RIyd1nYsflE6ZmCkZQMG_lwDAFXaqfyGKEDo" +
                "uJuja4XH8r4fGWeGTrozIoniXT1HU"}",
                    "e": "AQAB"
                }
            """.trimIndent(),
        "did:jwk:${"eyJjcnYiOiJQLTI1NiIsImt0eSI6IkVDIiwieCI6ImFjYklRaXVNczNpOF91c3pFakoydHBUdFJNNEVVM3l6OTFQSDZDZEgy" +
            "VjAiLCJ5IjoiX0tjeUxqOXZXTXB0bm1LdG00NkdxRHo4d2Y3NEk1TEtncmwyR3pIM25TRSJ9#0"}" to
            """
                {
                    "crv": "P-256",
                    "kty": "EC",
                    "x": "acbIQiuMs3i8_uszEjJ2tpTtRM4EU3yz91PH6CdH2V0",
                    "y": "_KcyLj9vWMptnmKtm46GqDz8wf74I5LKgrl2GzH3nSE"
                }
            """.trimIndent(),
        "did:jwk:${"eyJrdHkiOiJPS1AiLCJjcnYiOiJYMjU1MTkiLCJ1c2UiOiJlbmMiLCJ4IjoiM3A3YmZYdDl3YlRUVzJIQzdPUTFOei1EUThoYm" +
            "VHZE5yZngtRkctSUswOCJ9#0"}" to
            """
                {
                    "kty": "OKP",
                    "crv": "X25519",
                    "use": "enc",
                    "x": "3p7bfXt9wbTTW2HC7OQ1Nz-DQ8hbeGdNrfx-FG-IK08"
                }
            """.trimIndent(),
    ).mapValues { (_, value) -> JWK.parse(value) }
}
