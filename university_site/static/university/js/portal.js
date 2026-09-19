(() => {
    const username = document.getElementById('username');
    const password = document.getElementById('password');
    document.querySelectorAll('[data-demo-user]').forEach((button) => {
        button.addEventListener('click', () => {
            username.value = button.dataset.demoUser;
            password.value = button.dataset.demoPassword;
            password.focus();
        });
    });
})();
