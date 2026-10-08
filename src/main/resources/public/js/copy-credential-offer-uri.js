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

    function initCopyCredentialOfferUri() {
        const copyButton = document.getElementById("copyOfferUri");
        const copyHint = document.getElementById("copyOfferUriHint");

        if (!window.isSecureContext || !navigator.clipboard) {
            return;
        }

        copyButton.classList.remove("d-none");
        copyHint.classList.remove("d-none");

        const uriElement = document.querySelector(".credentials-offer-uri");
        const icon = copyButton.querySelector(".bi");
        const label = copyButton.querySelector(".copy-button-label");
        const liveRegion = document.querySelector("[aria-live='polite']");
        const originalLabel = copyButton.dataset.label;
        const copiedLabel = copyButton.dataset.copied;
        let timer = null;

        function hideCopyButton() {
            copyButton.classList.add("d-none");
            copyHint.classList.add("d-none");
        }

        function showCopiedFeedback() {
            icon.classList.replace("bi-clipboard", "bi-clipboard-check");
            label.textContent = copiedLabel;
            liveRegion.textContent = copiedLabel;
            if (timer !== null) {
                clearTimeout(timer);
            }
            timer = setTimeout(() => {
                icon.classList.replace("bi-clipboard-check", "bi-clipboard");
                label.textContent = originalLabel;
                liveRegion.textContent = "";
                timer = null;
            }, 2000);
        }

        async function copy() {
            const text = uriElement.textContent.trim();
            try {
                await navigator.clipboard.writeText(text);
            } catch (e) {
                hideCopyButton();
                return;
            }
            showCopiedFeedback();
        }

        copyButton.addEventListener("click", () => copy());
    }

    document.addEventListener("DOMContentLoaded", () => {
        initCopyCredentialOfferUri();
    });
})();
