/*
 * sidebar.js - Kupanua/Kupunguza Sidebar (Expand/Minimize) kwa dashboard za
 * GariFix (Customer, Mechanic, Seller, Admin) - DESKTOP.
 *
 * Pia inashughulikia kufungua/kufunga sidebar kwenye SIMU (mobile overlay),
 * ikiwemo backdrop inayofungwa ukibonyeza nje ya sidebar.
 */

function toggleGariFixSidebar() {
    var wrapper = document.querySelector(".app-wrapper");
    if (!wrapper) return;

    wrapper.classList.toggle("sidebar-minimized");
    var isMinimized = wrapper.classList.contains("sidebar-minimized");
    localStorage.setItem("garifix-sidebar-minimized", isMinimized ? "1" : "0");
}

function openGariFixMobileSidebar() {
    var sidebar = document.querySelector(".app-sidebar");
    var backdrop = document.querySelector(".sidebar-backdrop");
    if (sidebar) sidebar.classList.add("show");
    if (backdrop) backdrop.classList.add("show");
}

function closeGariFixMobileSidebar() {
    var sidebar = document.querySelector(".app-sidebar");
    var backdrop = document.querySelector(".sidebar-backdrop");
    if (sidebar) sidebar.classList.remove("show");
    if (backdrop) backdrop.classList.remove("show");
}

function toggleGariFixMobileSidebar() {
    var sidebar = document.querySelector(".app-sidebar");
    if (!sidebar) return;
    if (sidebar.classList.contains("show")) {
        closeGariFixMobileSidebar();
    } else {
        openGariFixMobileSidebar();
    }
}

document.addEventListener("DOMContentLoaded", function () {
    var wrapper = document.querySelector(".app-wrapper");
    if (!wrapper) return;

    if (localStorage.getItem("garifix-sidebar-minimized") === "1") {
        wrapper.classList.add("sidebar-minimized");
    }

    // Ukibonyeza kiungo chochote ndani ya sidebar kwenye simu, ifunge
    // kiotomatiki (badala ya kubaki wazi ikifunika ukurasa mpya).
    var sidebarLinks = document.querySelectorAll(".app-sidebar nav a");
    sidebarLinks.forEach(function (link) {
        link.addEventListener("click", function () {
            if (window.innerWidth < 992) {
                closeGariFixMobileSidebar();
            }
        });
    });
});

