(() => {
    const setupToggle = (button, menu) => {
        if (!button || !menu) return;
        button.addEventListener('click', () => {
            const open = menu.classList.toggle('open');
            button.setAttribute('aria-expanded', String(open));
        });
    };

    document.querySelectorAll('.nav-toggle').forEach((button) => {
        setupToggle(button, document.getElementById(button.getAttribute('aria-controls')));
    });
    setupToggle(document.querySelector('.utility-toggle'), document.getElementById('utility-links'));

    document.querySelectorAll('.dropdown-toggle').forEach((button) => {
        button.addEventListener('click', () => {
            const parent = button.closest('.has-dropdown');
            const open = parent.classList.toggle('open');
            button.setAttribute('aria-expanded', String(open));
        });
    });

    document.addEventListener('keydown', (event) => {
        if (event.key !== 'Escape') return;
        document.querySelectorAll('.has-dropdown.open').forEach((item) => item.classList.remove('open'));
        document.querySelectorAll('.dropdown-toggle[aria-expanded="true"]').forEach((item) => item.setAttribute('aria-expanded', 'false'));
    });
})();
