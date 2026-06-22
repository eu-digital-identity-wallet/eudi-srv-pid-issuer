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
package eu.europa.ec.eudi.pidissuer.adapter.out.mdl

import arrow.core.nonEmptySetOf
import arrow.core.raise.Raise
import eu.europa.ec.eudi.pidissuer.adapter.out.mdl.DrivingPrivilege.Restriction.GenericRestriction
import eu.europa.ec.eudi.pidissuer.adapter.out.mdl.DrivingPrivilege.Restriction.ParameterizedRestriction
import eu.europa.ec.eudi.pidissuer.adapter.out.util.loadResource
import eu.europa.ec.eudi.pidissuer.port.input.AuthorizationContext
import eu.europa.ec.eudi.pidissuer.port.input.IssueCredentialError
import eu.europa.ec.eudi.pidissuer.port.out.attestation.GetAttestationAttributes
import kotlinx.coroutines.async
import kotlinx.coroutines.coroutineScope
import org.slf4j.LoggerFactory
import java.time.LocalDate
import java.time.Month

private val log = LoggerFactory.getLogger(GetMobileDrivingLicenceDataMock::class.java)

/**
 * Mock implementation
 */
class GetMobileDrivingLicenceDataMock : GetAttestationAttributes<MobileDrivingLicence> {
    context(_: Raise<IssueCredentialError.AttestationDatasetNotFound>, authorizationContext: AuthorizationContext)
    override suspend fun invoke(): MobileDrivingLicence =
        coroutineScope {
            log.info("Getting mock data for Mobile Driving Licence")

            val portrait =
                async {
                    imageFromResource("/eu/europa/ec/eudi/pidissuer/adapter/out/mdl/Portrait.jpg")
                        ?.let(::Portrait)
                }
            val signature =
                async {
                    imageFromResource("/eu/europa/ec/eudi/pidissuer/adapter/out/mdl/Signature.jpg")
                }

            MobileDrivingLicence(
                Driver(
                    familyName = Latin150AndUtf8(Latin150("Georgiou"), "Γεωργίου"),
                    givenName = Latin150AndUtf8(Latin150("Georgios"), "Γεώργιος"),
                    birthDate = LocalDate.of(1948, Month.MAY, 30),
                    portrait = portrait.await() ?: error("Portrait not found"),
                    Sex.MALE,
                    height = 175u.cm(),
                    weight = 80u.kg(),
                    EyeColour.BROWN,
                    HairColour.GREY,
                    birthPlace = null,
                    Age(79u.natural(), 1948u.natural()),
                    nationality = IsoAlpha2CountryCode("GR"),
                    Residence(IsoAlpha2CountryCode("GR")),
                    signature = signature.await(),
                ),
                IssueAndExpiry(
                    issuedAt = LocalDate.of(2000, Month.JANUARY, 1),
                    expiresAt = LocalDate.of(2040, Month.DECEMBER, 31),
                ),
                Issuer(
                    country =
                        IssuingCountry(
                            countryCode = IsoAlpha2CountryCode("GR"),
                            distinguishingSign = DistinguishingSign("GR"),
                        ),
                    authority = Latin150("Ministry of Infrastructure and Transportation"),
                ),
                documentNumber = Latin150("A123-4567-8900"),
                privileges =
                    setOf(
                        DrivingPrivilege(
                            VehicleCategory.LIGHT_VEHICLE,
                            IssueAndExpiry(
                                issuedAt = LocalDate.of(2000, Month.JANUARY, 1),
                                expiresAt = LocalDate.of(2040, Month.DECEMBER, 31),
                            ),
                            restrictions =
                                nonEmptySetOf(
                                    GenericRestriction.VEHICLE_WITH_AUTOMATIC_TRANSMISSION,
                                    ParameterizedRestriction.VehicleAuthorizedPassengerSeats(Sign.LessThanOrEqualTo(5u.natural())),
                                ),
                        ),
                        DrivingPrivilege(
                            VehicleCategory.MOTORCYCLE,
                            IssueAndExpiry(
                                issuedAt = LocalDate.of(2000, Month.JANUARY, 1),
                                expiresAt = LocalDate.of(2040, Month.DECEMBER, 31),
                            ),
                            restrictions =
                                nonEmptySetOf(
                                    ParameterizedRestriction.VehicleCylinderCapacity(Sign.LessThanOrEqualTo(125u.cm3())),
                                ),
                        ),
                    ),
                administrativeNumber = Latin150("12345678900"),
            )
        }

    private suspend fun imageFromResource(path: String): Image? = loadResource(path)?.let { Image.Jpeg(it) }
}
