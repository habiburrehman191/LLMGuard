(() => {
    const slides = [...document.querySelectorAll('[data-slide]')];
    if (!slides.length) return;
    let current = 0;
    const show = (index) => {
        slides[current].classList.remove('active');
        current = (index + slides.length) % slides.length;
        slides[current].classList.add('active');
    };
    document.querySelector('[data-slider-next]')?.addEventListener('click', () => show(current + 1));
    document.querySelector('[data-slider-prev]')?.addEventListener('click', () => show(current - 1));
    const timer = window.setInterval(() => show(current + 1), 6500);
    document.addEventListener('visibilitychange', () => { if (document.hidden) window.clearInterval(timer); }, { once: true });

    const modal = document.querySelector('[data-announcement-modal]');
    const closeButton = document.querySelector('[data-announcement-close]');
    closeButton?.addEventListener('click', () => {
        modal.hidden = true;
        document.querySelector('.main-nav a')?.focus();
    });
})();
