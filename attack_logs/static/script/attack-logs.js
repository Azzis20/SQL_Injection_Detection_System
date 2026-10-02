document.addEventListener("DOMContentLoaded", function () {
    const form = document.getElementById("block-source-ip-form");
    const trigger = document.getElementById("add-ip-blocklist-btn");
    const overlay = document.getElementById("block-ip-confirm-overlay");
    const cancelButton = document.getElementById("cancel-block-ip");
    const confirmButton = document.getElementById("confirm-block-ip");

    if (!form || !trigger || !overlay) return;

    function closeModal() {
        overlay.classList.remove("open");
        overlay.setAttribute("aria-hidden", "true");
        trigger.focus();
    }

    trigger.addEventListener("click", function (event) {
        event.preventDefault();
        overlay.classList.add("open");
        overlay.setAttribute("aria-hidden", "false");
        cancelButton.focus();
    });

    cancelButton.addEventListener("click", closeModal);

    overlay.addEventListener("click", function (event) {
        if (event.target === overlay) closeModal();
    });

    document.addEventListener("keydown", function (event) {
        if (event.key === "Escape" && overlay.classList.contains("open")) closeModal();
    });

    confirmButton.addEventListener("click", function () {
        confirmButton.disabled = true;
        form.submit();
    });
});