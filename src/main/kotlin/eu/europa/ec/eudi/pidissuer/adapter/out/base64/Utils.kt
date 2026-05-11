package eu.europa.ec.eudi.pidissuer.adapter.out.base64

import kotlin.io.encoding.Base64

internal val base64UrlSafeNoPadding = Base64.UrlSafe.withPadding(Base64.PaddingOption.ABSENT)