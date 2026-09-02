/*
 * sidebar.js - Kupanua/Kupunguza Sidebar (Expand/Minimize) kwa dashboard za
 * GariFix (Customer, Mechanic, Seller, Admin).
 *
 * Ukiwa "minimized", ni icons pekee zinazoonekana; maandishi yanafichwa.
 * Chaguo la mtumiaji linahifadhiwa (localStorage) hivyo halibadiliki
 * akifunga na kufungua tena ukurasa.
 */

function toggleGariFixSidebar() {
    var wrapper = document.querySelector(".app-wrapper");
    if (!wrapper) return;

    wrapper.classList.toggle("sidebar-minimized");
    var isMinimized = wrapper.classList.contains("sidebar-minimized");
    localStorage.setItem("garifix-sidebar-minimized", isMinimized ? "1" : "0");
}

document.addEventListener("DOMContentLoaded", function () {
    var wrapper = document.querySelector(".app-wrapper");
    if (!wrapper) return;

    if (localStorage.getItem("garifix-sidebar-minimized") === "1") {
        wrapper.classList.add("sidebar-minimized");
    }
});
