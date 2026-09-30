
document.addEventListener('DOMContentLoaded', function () {
    const trigger = document.getElementById('logout-trigger');
    const overlay = document.getElementById('logout-modal-overlay');
    const cancelBtn = document.getElementById('logout-cancel');

    const openModal = () => overlay.classList.add('open');
    const closeModal = () => overlay.classList.remove('open');

    trigger.addEventListener('click', openModal);
    cancelBtn.addEventListener('click', closeModal);

    // Close on overlay click (but not when clicking the modal box itself)
    overlay.addEventListener('click', function (e) {
        if (e.target === overlay) closeModal();
    });

    // Close on Escape key
    document.addEventListener('keydown', function (e) {
        if (e.key === 'Escape' && overlay.classList.contains('open')) closeModal();
    });
});
