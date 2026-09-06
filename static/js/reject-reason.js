/*
 * reject-reason.js - Kabla ya kutuma fomu yoyote yenye class "gfx-reject-form"
 * (Kukataa Fundi/Muuzaji), inauliza admin sababu (hiari) kupitia prompt(),
 * na kuiweka kwenye uga wa "reason" uliofichwa kabla ya kutuma.
 */
document.addEventListener("DOMContentLoaded", function () {
    document.querySelectorAll(".gfx-reject-form").forEach(function (form) {
        form.addEventListener("submit", function (e) {
            if (form.dataset.reasonAsked === "1") {
                return; // tayari imeulizwa, ruhusu kutuma
            }
            e.preventDefault();
            var reason = prompt("Sababu ya kukataa ombi hili (hiari - unaweza kuacha wazi):", "");
            if (reason === null) {
                return; // admin amebofya "Cancel" - usitume kabisa
            }
            var reasonField = form.querySelector(".gfx-reason-field");
            if (reasonField) {
                reasonField.value = reason;
            }
            form.dataset.reasonAsked = "1";
            form.submit();
        });
    });
});
