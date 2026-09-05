/*
 * password-hint.js - Inaonyesha ujumbe wa "angalau herufi 6" chini ya uga
 * wa password, na kubadilisha rangi (nyekundu/kijani) mtumiaji anapoandika,
 * ili aone MARA MOJA kama password yake inatosheleza kabla ya ku-submit.
 */
function setupGariFixPasswordHint(passwordInputId, hintId) {
    var input = document.getElementById(passwordInputId);
    var hint = document.getElementById(hintId);
    if (!input || !hint) return;

    function check() {
        if (input.value.length === 0) {
            hint.textContent = "Angalau herufi 6";
            hint.className = "form-text text-muted";
        } else if (input.value.length < 6) {
            hint.textContent = "Bado - unahitaji herufi " + (6 - input.value.length) + " zaidi";
            hint.className = "form-text text-danger fw-semibold";
        } else {
            hint.textContent = "✓ Sawa - urefu unatosha";
            hint.className = "form-text text-success fw-semibold";
        }
    }

    input.addEventListener("input", check);
    check();
}
