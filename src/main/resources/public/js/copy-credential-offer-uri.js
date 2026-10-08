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
        const uriElement = document.querySelector(".credentials-offer-uri");
        const icon = copyButton.querySelector(".bi");
        const label = copyButton.querySelector(".copy-button-label");
        const liveRegion = document.querySelector("[aria-live='polite']");
        const originalLabel = copyButton.dataset.label;
        const copiedLabel = copyButton.dataset.copied;
        let timer = null;

        function legacyCopy(text) {
            const textarea = document.createElement("textarea");
            textarea.value = text;
            textarea.setAttribute("readonly", "");
            textarea.style.position = "absolute";
            textarea.style.left = "-9999px";
            document.body.appendChild(textarea);
            textarea.select();
            let copied = false;
            try {
                copied = document.execCommand("copy");
            } catch (e) {
                copied = false;
            }
            document.body.removeChild(textarea);
            return copied;
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
            let copied = false;
            if (window.isSecureContext && navigator.clipboard) {
                try {
                    await navigator.clipboard.writeText(text);
                    copied = true;
                } catch (e) {
                    copied = false;
                }
            }
            if (!copied) {
                copied = legacyCopy(text);
            }
            if (copied) {
                showCopiedFeedback();
            }
        }

        copyButton.addEventListener("click", () => copy());
    }

    document.addEventListener("DOMContentLoaded", () => {
        initCopyCredentialOfferUri();
    });
})();
