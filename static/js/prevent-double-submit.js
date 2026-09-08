/*
 * prevent-double-submit.js - Inazuia mtu kubofya kitufe cha "Jisajili"
 * (au fomu nyingine yoyote) mara mbili haraka haraka, jambo linalosababisha
 * ombi mbili kutumwa serverini - la kwanza likifanikiwa (na kuunda akaunti),
 * la pili likionekana kama "namba tayari imesajiliwa" (kwa kuwa la kwanza
 * lilishatimia). Kubofya mara moja tu sasa kunatosha.
 */
function gfxPreventDoubleSubmit(form, buttonId) {
    if (form.dataset.gfxSubmitted === "1") {
        return false; // tayari imetumwa mara moja - zuia hii ya pili
    }
    form.dataset.gfxSubmitted = "1";

    var btn = document.getElementById(buttonId);
    if (btn) {
        btn.disabled = true;
        btn.dataset.gfxOriginalHtml = btn.innerHTML;
        btn.innerHTML = '<span class="spinner-border spinner-border-sm me-2"></span> Inatuma...';
    }
    return true; // ruhusu fomu itumwe mara HII PEKEE
}
