package eu.europa.ec.eudi.pidissuer.port.out.pid

import eu.europa.ec.eudi.pidissuer.domain.pid.Pid

interface GetPidData {
    suspend operator fun invoke(accessToken: String): Pid?
}