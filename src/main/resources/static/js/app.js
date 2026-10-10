// Loaded as a separate file because the Content Security Policy forbids inline scripts.

document.addEventListener('DOMContentLoaded', () => {

  // Show / hide a password field
  document.querySelectorAll('[data-toggle]').forEach((button) => {
    button.addEventListener('click', () => {
      const input = document.getElementById(button.dataset.toggle);
      const reveal = input.type === 'password';
      input.type = reveal ? 'text' : 'password';
      button.textContent = reveal ? 'Hide' : 'Show';
    });
  });

  // Copy to clipboard, then clear the clipboard 30 seconds later
  document.querySelectorAll('[data-copy]').forEach((button) => {
    button.addEventListener('click', async () => {
      const input = document.getElementById(button.dataset.copy);
      try {
        await navigator.clipboard.writeText(input.value);
        button.textContent = 'Copied';
        setTimeout(() => { button.textContent = 'Copy'; }, 1500);
        setTimeout(() => { navigator.clipboard.writeText('').catch(() => {}); }, 30000);
      } catch (e) {
        button.textContent = 'Copy failed';
      }
    });
  });

  // Generate a strong random password using the browser's cryptographic random generator
  document.querySelectorAll('[data-generate]').forEach((button) => {
    button.addEventListener('click', () => {
      const chars = 'ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz23456789!@#$%^&*-_=+';
      const values = new Uint32Array(20);
      crypto.getRandomValues(values);
      const password = Array.from(values, (v) => chars[v % chars.length]).join('');
      const input = document.getElementById(button.dataset.generate);
      input.value = password;
      input.type = 'text';
    });
  });

  // Ask before destructive actions
  document.querySelectorAll('form[data-confirm]').forEach((form) => {
    form.addEventListener('submit', (event) => {
      if (!window.confirm(form.dataset.confirm)) {
        event.preventDefault();
      }
    });
  });
});
