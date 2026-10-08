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
(function () {
    "use strict";

    function initCredentialsOfferForm() {
        const generateButton = document.getElementById("generateButton");
        if (!generateButton) {
            return;
        }
        const credentialConfigurationIds = Array.from(document.querySelectorAll(".credential-configuration-id"));
        const errorModal = new bootstrap.Modal(document.getElementById("multipleAttestationCategoriesWarningModal"));

        function onSelectedCredentialConfigurationIdsChanged() {
            const attestationCategories = new Set(
                credentialConfigurationIds
                    .filter(checkbox => checkbox.checked)
                    .map(checkbox => checkbox.dataset.category)
            );

            if (1 === attestationCategories.size) {
                generateButton.disabled = false;
                generateButton.classList.remove("btn-danger");
                generateButton.classList.add("btn-primary");
                errorModal.hide();

            } else if (0 === attestationCategories.size) {
                generateButton.disabled = true;
                generateButton.classList.remove("btn-primary");
                generateButton.classList.add("btn-danger");
                errorModal.hide();

            } else {
                generateButton.disabled = true;
                generateButton.classList.remove("btn-primary");
                generateButton.classList.add("btn-danger");
                errorModal.show();

            }
        }

        credentialConfigurationIds.forEach(cb => cb.addEventListener("change", onSelectedCredentialConfigurationIdsChanged));
        onSelectedCredentialConfigurationIdsChanged();
    }

    document.addEventListener("DOMContentLoaded", () => {
        initCredentialsOfferForm();
    });
})();
