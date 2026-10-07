// Progressive enhancement only; every filter still submits through the GET form.
const securityEventFilters = document.querySelector('[data-security-events] [data-security-event-filters]');
if (securityEventFilters) {
    const toggle = securityEventFilters.querySelector('[data-more-filters]');
    const secondary = securityEventFilters.querySelector('.se-advanced-filters');
    const hasSecondaryFilter = Array.from(secondary.querySelectorAll('select')).some(select => select.value);
    securityEventFilters.classList.add('se-enhanced-filters');
    securityEventFilters.classList.toggle('show-advanced-filters', hasSecondaryFilter);
    toggle.hidden = false;
    toggle.setAttribute('aria-expanded', String(hasSecondaryFilter));
    toggle.textContent = hasSecondaryFilter ? 'Fewer filters' : 'More filters';
}
