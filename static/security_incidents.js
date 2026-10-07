// Keep native server-side GET filtering. Optional enum filters must be omitted
// when blank: an empty incident_status is not a supported backend enum value.
document.querySelector('[data-incident-filters]')?.addEventListener('formdata', (event) => {
    for (const name of ['application_id', 'incident_status', 'severity', 'category']) {
        if (event.formData.get(name) === '') event.formData.delete(name);
    }
});
