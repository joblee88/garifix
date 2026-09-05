/*
 * notifications-dropdown.js - Inapakia orodha ya arifa (kupitia AJAX)
 * kila mtumiaji anapofungua "dropdown" ya bell icon, ili orodha iwe
 * mpya kila wakati (bila kuhitaji "refresh" ya ukurasa mzima).
 */
function loadGariFixNotifications(btn) {
    var dropdown = btn.parentElement.querySelector(".dropdown-menu");
    if (!dropdown) return;
    var container = dropdown.querySelector(".notif-list-container");
    if (!container) return;

    container.innerHTML = '<p class="text-center text-muted small py-3">Inapakia...</p>';

    fetch("/notifications/dropdown")
        .then(function (res) { return res.text(); })
        .then(function (html) {
            container.innerHTML = html;
        })
        .catch(function () {
            container.innerHTML = '<p class="text-center text-danger small py-3">Hitilafu ya kupakia arifa.</p>';
        });
}
