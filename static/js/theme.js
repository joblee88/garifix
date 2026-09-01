/*
 * theme.js - Dark/Light Mode kwa GariFix
 * Faili hili LAZIMA lipakiwe MAPEMA kabisa ndani ya <head> (kabla ya CSS
 * kupakiwa) ili kuzuia "flash" ya rangi isiyo sahihi wakati ukurasa
 * unapofunguka.
 */

function applyGariFixTheme(theme) {
    document.documentElement.setAttribute("data-bs-theme", theme);
    localStorage.setItem("garifix-theme", theme);
}

function toggleGariFixTheme() {
    var current = document.documentElement.getAttribute("data-bs-theme") || "light";
    applyGariFixTheme(current === "dark" ? "light" : "dark");
    syncGariFixThemeIcons();
}

function syncGariFixThemeIcons() {
    var theme = document.documentElement.getAttribute("data-bs-theme") || "light";
    document.querySelectorAll(".theme-toggle-icon").forEach(function (el) {
        el.classList.remove("fa-sun", "fa-moon");
        el.classList.add(theme === "dark" ? "fa-sun" : "fa-moon");
    });
}

// Weka theme mara moja (kabla ya CSS kuchorwa) - inasoma chaguo lililohifadhiwa
// awali (localStorage), au "light" kama ni mara ya kwanza kufungua.
applyGariFixTheme(localStorage.getItem("garifix-theme") || "light");

document.addEventListener("DOMContentLoaded", syncGariFixThemeIcons);
