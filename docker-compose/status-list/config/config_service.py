# coding: latin-1
###############################################################################
# Copyright (c) 2023 European Commission
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#    http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#
###############################################################################
import logging
from logging.handlers import TimedRotatingFileHandler
import os


class ConfService:

    service_url = "https://localhost/"
    # Token status list size (Bytes)
    token_status_list_size = 10000

    status_list_dir = "/var/opt/status_lists"

    backup_dir = "/var/opt/status_list_backup"

    countries = {
        "FC":{
            "privKey":"/status-list/certs/key.pem",
            "privkey_passwd": None,
            "cert":"/status-list/certs/cert.der"
        }
    }

    ALLOWED_DOCTYPES = {
        "urn:eudi:pid:1",
        "eu.europa.ec.eudi.pid.1",
        "org.iso.18013.5.1.mDL",
        "urn:eudi:ehic:1",
        "urn:eu.europa.ec.eudi:learning:credential:1",
        "key-attestation+jwt",
        "oauth-client-attestation+jwt",
    }

    # ------------------------------------------------------------------------------------------------
    # LOGS

    log_dir = "/tmp/status_lists"
    # log_dir = "../../log"
    log_file_info = "status_lists.log"

    backup_count = 7

    try:
        os.makedirs(log_dir)
    except FileExistsError:
        pass

    log_handler_info = TimedRotatingFileHandler(
        filename=f"{log_dir}/{log_file_info}",
        when="midnight",  # Rotation midnight
        interval=1,  # new file each day
        backupCount=backup_count,
    )


    console_handler = logging.StreamHandler()
    console_handler.setFormatter(logging.Formatter("%(asctime)s %(name)s %(levelname)s %(message)s"))
    log_handler_info.setFormatter(logging.Formatter("%(asctime)s %(name)s %(levelname)s %(message)s"))

    app_logger = logging.getLogger("revocation_app_logger")
    app_logger.addHandler(log_handler_info)
    app_logger.addHandler(console_handler)
    app_logger.setLevel(logging.INFO)