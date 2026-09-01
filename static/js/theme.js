/*
 * theme.js - Dark/Light Mode kwa GariFix
 * Faili hili LAZIMA lipakiwe MAPEMA kabisa ndani ya <head> (kabla ya CSS
 * kupakiwa) ili kuzuia "flash" ya rangi isiyo sahihi wakati ukurasa
 * unapofunguka.
 *
 * TABIA: Mara ya kwanza (kabla mtumiaji hajawahi kubofya kitufe cha
 * dark/light), mfumo unafuata mpangilio wa KIFAA/BROWSER yenyewe
 * (prefers-color-scheme). Mtumiaji akishabofya kitufe mara moja, chaguo
 * lake linahifadhiwa (localStorage) na halibadiliki tena hata kifaa
 * kikibadilisha mpangilio wake.
 */

function getGariFixPreferredTheme() {
    var saved = localStorage.getItem("garifix-theme");
    if (saved === "light" || saved === "dark") {
        return saved;
    }
    // Hakuna chaguo la mtumiaji bado - fuata mpangilio wa kifaa/browser
    if (window.matchMedia && window.matchMedia("(prefers-color-scheme: dark)").matches) {
        return "dark";
    }
    return "light";
}

function applyGariFixTheme(theme, persist) {
    document.documentElement.setAttribute("data-bs-theme", theme);
    if (persist) {
        localStorage.setItem("garifix-theme", theme);
    }
}

function toggleGariFixTheme() {
    var current = document.documentElement.getAttribute("data-bs-theme") || "light";
    applyGariFixTheme(current === "dark" ? "light" : "dark", true);
    syncGariFixThemeIcons();
}

function syncGariFixThemeIcons() {
    var theme = document.documentElement.getAttribute("data-bs-theme") || "light";
    document.querySelectorAll(".theme-toggle-icon").forEach(function (el) {
        el.classList.remove("fa-sun", "fa-moon");
        el.classList.add(theme === "dark" ? "fa-sun" : "fa-moon");
    });
}

// Weka theme mara moja (kabla ya CSS kuchorwa) - "auto" kulingana na
// kifaa mpaka mtumiaji achague mwenyewe.
applyGariFixTheme(getGariFixPreferredTheme(), false);

// Kama mtumiaji hajawahi kuchagua mwenyewe, endelea kufuatilia mabadiliko
// ya mpangilio wa kifaa/browser wakati ukurasa uko wazi (mfano akibadilisha
// "dark mode" ya simu yake wakati GariFix iko wazi).
if (window.matchMedia) {
    window.matchMedia("(prefers-color-scheme: dark)").addEventListener("change", function (e) {
        if (!localStorage.getItem("garifix-theme")) {
            applyGariFixTheme(e.matches ? "dark" : "light", false);
            syncGariFixThemeIcons();
        }
    });
}

document.addEventListener("DOMContentLoaded", syncGariFixThemeIcons);

