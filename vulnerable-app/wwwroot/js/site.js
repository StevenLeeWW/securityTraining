// Client-side JavaScript for the vulnerable web application
// This file intentionally contains some vulnerable code for demonstration purposes

// Wait for the document to be loaded
document.addEventListener('DOMContentLoaded', function () {
    // Log when the application has been loaded
    console.log("Vulnerable Web Application initialized");

    // VULNERABILITY: Insecure way to get and store user data from URL parameters
    function getParameterByName(name) {
        const url = window.location.href;
        name = name.replace(/[\[\]]/g, '\\$&');
        const regex = new RegExp('[?&]' + name + '(=([^&#]*)|&|#|$)');
        const results = regex.exec(url);
        if (!results) return null;
        if (!results[2]) return '';
        return decodeURIComponent(results[2].replace(/\+/g, ' '));
    }

    // VULNERABILITY: Storing sensitive info in localStorage
    const username = getParameterByName('user');
    if (username) {
        localStorage.setItem('currentUser', username);
        // VULNERABILITY: Inserting unsanitized content from URL
        if (document.getElementById('welcome-message')) {
            document.getElementById('welcome-message').innerHTML = 'Welcome, ' + username;
        }
    }

    // VULNERABILITY: Eval execution of input
    function calculateFromInput() {
        const formula = document.getElementById('calc-input');
        if (formula && formula.value) {
            try {
                // VULNERABILITY: Never use eval with user input
                const result = eval(formula.value);
                document.getElementById('calc-result').textContent = result;
            } catch (e) {
                document.getElementById('calc-result').textContent = 'Error in calculation';
            }
        }
    }

    // Set up calculator if it exists on the page
    const calcButton = document.getElementById('calc-button');
    if (calcButton) {
        calcButton.addEventListener('click', calculateFromInput);
    }

    // Search form validation (insufficient)
    const searchForm = document.querySelector('form[action*="Products"]');
    if (searchForm) {
        searchForm.addEventListener('submit', function (event) {
            const searchInput = document.querySelector('input[name="search"]');
            // VULNERABILITY: Weak client-side validation that can be bypassed
            if (searchInput.value.includes('--') || searchInput.value.includes(';')) {
                alert('Invalid characters detected in search!');
                event.preventDefault();
            }
        });
    }

    // Set up command execution form
    const commandForm = document.getElementById('command-form');
    if (commandForm) {
        commandForm.addEventListener('submit', function (event) {
            // VULNERABILITY: Weak command validation
            const commandInput = document.getElementById('command');
            const dangerousCommands = ['rm', 'del', 'format', 'drop'];

            for (const cmd of dangerousCommands) {
                if (commandInput.value.toLowerCase().includes(cmd)) {
                    const confirm = window.confirm('This command may be dangerous. Run anyway?');
                    if (!confirm) {
                        event.preventDefault();
                        return;
                    }
                    break;
                }
            }
        });
    }

    // Remember me feature for login
    const rememberCheckbox = document.getElementById('rememberMe');
    const usernameInput = document.getElementById('username');

    if (rememberCheckbox && usernameInput) {
        // VULNERABILITY: Using localStorage for sensitive data
        if (localStorage.getItem('rememberedUser')) {
            usernameInput.value = localStorage.getItem('rememberedUser');
            rememberCheckbox.checked = true;
        }

        rememberCheckbox.addEventListener('change', function () {
            if (this.checked && usernameInput.value) {
                localStorage.setItem('rememberedUser', usernameInput.value);
            } else {
                localStorage.removeItem('rememberedUser');
            }
        });
    }
});