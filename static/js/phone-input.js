/*
 * phone-input.js - Inasaidia uga wa "Namba ya Simu" wenye "+255" iliyowekwa
 * mbele (fixed prefix), ambapo mtumiaji anaandika tarakimu 9 tu
 * zinazofuata (mfano 712345678 kwa namba 0712345678).
 *
 * Thamani halisi inayotumwa kwa server (name="phone") inabaki kwenye
 * muundo wa zamani "0XXXXXXXXX" ili kuendana na akaunti zilizopo tayari.
 */
function syncGariFixPhone(digitsInput, hiddenInputId) {
    var digits = digitsInput.value.replace(/[^0-9]/g, "").slice(0, 9);
    digitsInput.value = digits;
    var hidden = document.getElementById(hiddenInputId);
    if (hidden) {
        hidden.value = digits ? "0" + digits : "";
    }
}
