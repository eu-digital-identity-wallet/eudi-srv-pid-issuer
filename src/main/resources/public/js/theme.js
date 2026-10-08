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

    const STORAGE_KEY = "theme";
    const LIGHT_THEME_COLOR = "#0048d2";
    const DARK_THEME_COLOR = "#12151c";
    const mediaQuery = window.matchMedia("(prefers-color-scheme: dark)");

    function storedTheme() {
        try {
            const stored = window.localStorage.getItem(STORAGE_KEY);
            return stored === "light" || stored === "dark" ? stored : null;
        } catch (e) {
            return null;
        }
    }

    function storeTheme(theme) {
        try {
            window.localStorage.setItem(STORAGE_KEY, theme);
        } catch (e) {
            // Ignore storage failures (e.g. private browsing mode)
        }
    }

    function systemTheme() {
        return mediaQuery.matches ? "dark" : "light";
    }

    function currentTheme() {
        return storedTheme() || systemTheme();
    }

    function applyTheme(theme) {
        document.documentElement.setAttribute("data-bs-theme", theme);
        document.querySelector('meta[name="theme-color"]').setAttribute("content", theme === "dark" ? DARK_THEME_COLOR : LIGHT_THEME_COLOR);
    }

    // Apply the theme before first paint. This script is loaded synchronously in <head>,
    // before the stylesheets, so the correct theme is in place when the page renders.
    applyTheme(currentTheme());

    document.addEventListener("DOMContentLoaded", () => {
        const themeToggle = document.getElementById("themeToggle");
        const icon = themeToggle.querySelector(".bi");

        function syncToggle() {
            const isDark = document.documentElement.getAttribute("data-bs-theme") === "dark";
            icon.classList.toggle("bi-moon-stars-fill", !isDark);
            icon.classList.toggle("bi-sun-fill", isDark);
            themeToggle.setAttribute("aria-pressed", String(isDark));
        }

        syncToggle();

        themeToggle.addEventListener("click", () => {
            const isDark = document.documentElement.getAttribute("data-bs-theme") === "dark";
            const theme = isDark ? "light" : "dark";
            storeTheme(theme);
            applyTheme(theme);
            syncToggle();
        });

        // Follow the system theme while the user has not made an explicit choice
        mediaQuery.addEventListener("change", () => {
            if (storedTheme() === null) {
                applyTheme(systemTheme());
                syncToggle();
            }
        });
    });
})();
