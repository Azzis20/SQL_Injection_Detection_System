 // Show / hide password
const toggleBtn = document.getElementById('toggle-password');
const passwordInput = document.getElementById('id_password');

toggleBtn.addEventListener('click', () => {
    const isHidden = passwordInput.type === 'password';
    passwordInput.type = isHidden ? 'text' : 'password';
    toggleBtn.setAttribute('aria-label', isHidden ? 'Hide password' : 'Show password');
 });

 document.getElementById('login-as-admin').addEventListener('click', function () {
    window.location.href = '/admin/login';
});