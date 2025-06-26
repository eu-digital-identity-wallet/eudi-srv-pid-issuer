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
package eu.europa.ec.eudi.pidissuer.adapter.out.ehic

import java.time.ZonedDateTime

@JvmInline
value class PersonalAdministrativeNumber(val value: String) {
    init {
        require(value.length in 4..50)
    }

    override fun toString(): String = value
}

@JvmInline
value class Name(val value: String) {
    init {
        require(value.length in 1..100)
    }

    override fun toString(): String = value
}

data class IssuingAuthority(
    val id: Id,
    val name: Name,
) {

    @JvmInline
    value class Id(val value: String) {
        init {
            require(value.length in 1..20)
        }

        override fun toString(): String = value
    }
}

@JvmInline
value class IssuingCountry(val value: String) {
    init {
        require(Regex("^[A-Z]{2}$").matches(value))
    }

    override fun toString(): String = value
}

data class AuthenticSource(
    val id: Id,
    val name: Name,
) {
    @JvmInline
    value class Id(val value: String) {
        init {
            require(value.length in 1..20)
        }

        override fun toString(): String = value
    }
}

@JvmInline
value class DocumentNumber(val value: String) {
    init {
        require(value.length in 4..50)
    }

    override fun toString(): String = value
}

data class EuropeanHealthInsuranceCard(
    val personalAdministrativeNumber: PersonalAdministrativeNumber,
    val issuingAuthority: IssuingAuthority,
    val issuingCountry: IssuingCountry,
    val authenticSource: AuthenticSource,
    val endingDate: ZonedDateTime?,
    val startingDate: ZonedDateTime?,
    val documentNumber: DocumentNumber,
) {
    init {
        endingDate?.let {
            require(null == startingDate || it >= startingDate)
        }
    }
}
