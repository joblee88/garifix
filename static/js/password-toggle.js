/*
 * password-toggle.js - Inaongeza kitufe cha "jicho" (eye icon) kwenye uga
 * wowote wa password wenye class "gfx-toggle-password", kinachobadilisha
 * kuonyesha/kuficha maandishi ya password mtumiaji anapobofya.
 */
function toggleGariFixPasswordVisibility(btn) {
    var wrapper = btn.closest(".gfx-password-wrapper");
    if (!wrapper) return;
    var input = wrapper.querySelector("input");
    var icon = btn.querySelector("i");
    if (!input || !icon) return;

    if (input.type === "password") {
        input.type = "text";
        icon.classList.remove("fa-eye");
        icon.classList.add("fa-eye-slash");
    } else {
        input.type = "password";
        icon.classList.remove("fa-eye-slash");
        icon.classList.add("fa-eye");
    }
}
