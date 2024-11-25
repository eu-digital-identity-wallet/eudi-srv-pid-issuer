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
package eu.europa.ec.eudi.pidissuer.adapter.out.mdl

import arrow.core.Either
import arrow.core.nonEmptySetOf
import arrow.core.raise.Raise
import arrow.core.raise.catch
import arrow.core.raise.either
import arrow.core.raise.ensureNotNull
import eu.europa.ec.eudi.pidissuer.adapter.out.mdl.DrivingPrivilege.Restriction.GenericRestriction
import eu.europa.ec.eudi.pidissuer.adapter.out.mdl.DrivingPrivilege.Restriction.ParameterizedRestriction
import eu.europa.ec.eudi.pidissuer.port.input.AuthorizationContext
import eu.europa.ec.eudi.pidissuer.port.input.IssueCredentialError
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import org.slf4j.LoggerFactory
import java.time.LocalDate
import java.time.Month

/**
 * Mock implementation for [GetMobileDrivingLicenceData].
 */
class GetMobileDrivingLicenceDataMock : GetMobileDrivingLicenceData {

    override suspend fun invoke(context: AuthorizationContext): Either<IssueCredentialError.Unexpected, MobileDrivingLicence> = either {
        log.info("Getting mock data for Mobile Driving Licence")

        val driver = Driver(
            Latin150AndUtf8(Latin150("Georgiou"), "Γεωργίου"),
            Latin150AndUtf8(Latin150("Georgios"), "Γεώργιος"),
            LocalDate.of(1948, Month.MAY, 30),
            Portrait(Image.Jpeg(loadResource("/eu/europa/ec/eudi/pidissuer/adapter/out/mdl/Portrait.jpg"))),
            Sex.MALE,
            175u.cm(),
            80u.kg(),
            EyeColour.BROWN,
            HairColour.GREY,
            null,
            Age(79u.natural(), 1948u.natural()),
            IsoAlpha2CountryCode("GR"),
            Residence(
                IsoAlpha2CountryCode("GR"),
            ),
            Image.Jpeg(loadResource("/eu/europa/ec/eudi/pidissuer/adapter/out/mdl/Signature.jpg")),
        )

        val issuer = Issuer(
            IssuingCountry(IsoAlpha2CountryCode("GR"), DistinguishingSign("GR")),
            Latin150("Ministry of Infrastructure and Transportation"),
        )

        val privileges = setOf(
            DrivingPrivilege(
                VehicleCategory.LIGHT_VEHICLE,
                IssueAndExpiry(LocalDate.of(2000, Month.JANUARY, 1), LocalDate.of(2040, Month.DECEMBER, 31)),
                nonEmptySetOf(
                    GenericRestriction.VEHICLE_WITH_AUTOMATIC_TRANSMISSION,
                    ParameterizedRestriction.VehicleAuthorizedPassengerSeats(Sign.LessThanOrEqualTo(5u.natural())),
                ),
            ),
            DrivingPrivilege(
                VehicleCategory.MOTORCYCLE,
                IssueAndExpiry(LocalDate.of(2000, Month.JANUARY, 1), LocalDate.of(2040, Month.DECEMBER, 31)),
                nonEmptySetOf(
                    ParameterizedRestriction.VehicleCylinderCapacity(Sign.LessThanOrEqualTo(125u.cm3())),
                ),
            ),
        )

        MobileDrivingLicence(
            driver,
            IssueAndExpiry(LocalDate.of(2000, Month.JANUARY, 1), LocalDate.of(2040, Month.DECEMBER, 31)),
            issuer,
            Latin150("A123-4567-8900"),
            privileges,
            Latin150("12345678900"),
        )
    }

    companion object {

        private val log = LoggerFactory.getLogger(GetMobileDrivingLicenceDataMock::class.java)

        private suspend fun Raise<IssueCredentialError.Unexpected>.loadResource(path: String): ByteArray =
            withContext(Dispatchers.IO) {
                val portrait =
                    ensureNotNull(Companion::class.java.getResourceAsStream(path)) {
                        IssueCredentialError.Unexpected("Unable to load resource $path")
                    }

                portrait.use {
                    catch({ it.readAllBytes() }) {
                        raise(IssueCredentialError.Unexpected("Unable to read $path", it))
                    }
                }
            }
    }
}
