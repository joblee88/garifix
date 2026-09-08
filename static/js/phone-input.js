/*
 * phone-input.js - Inasaidia uga wa "Namba ya Simu" ambapo mtumiaji
 * anaandika namba KAMILI ya ndani (mfano 0712345678 - tarakimu 10,
 * ikiwemo "0" mwanzoni), sawa na jinsi watu wanavyoandika namba zao
 * kawaida (bila kuhitaji kujua/kuandika +255).
 */
function syncGariFixPhone(digitsInput, hiddenInputId) {
    var digits = digitsInput.value.replace(/[^0-9]/g, "").slice(0, 10);
    digitsInput.value = digits;
    var hidden = document.getElementById(hiddenInputId);
    if (hidden) {
        hidden.value = digits;
    }
}
