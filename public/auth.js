const TOKEN_KEY = "cloud_scanner_token";
const USER_KEY = "cloud_scanner_user";

const loginForm = document.getElementById("loginForm");
const registerForm = document.getElementById("registerForm");
const showLoginBtn = document.getElementById("showLoginBtn");
const showRegisterBtn = document.getElementById("showRegisterBtn");

showLoginBtn.addEventListener("click", () => switchMode("login"));
showRegisterBtn.addEventListener("click", () => switchMode("register"));

validateExistingSession();

async function validateExistingSession() {
    const token = localStorage.getItem(TOKEN_KEY);
    if (!token) {
        return;
    }

    try {
        const response = await fetch("/api/session", {
            headers: {
                "Authorization": `Bearer ${token}`
            }
        });

        if (!response.ok) {
            throw new Error("Session expired");
        }

        window.location.href = "/dashboard.html";
    } catch {
        localStorage.removeItem(TOKEN_KEY);
        localStorage.removeItem(USER_KEY);
    }
}

function switchMode(mode) {
    const isLogin = mode === "login";
    loginForm.classList.toggle("hidden", !isLogin);
    registerForm.classList.toggle("hidden", isLogin);
    showLoginBtn.classList.toggle("active", isLogin);
    showRegisterBtn.classList.toggle("active", !isLogin);
}

document.getElementById("loginForm").addEventListener("submit", async event => {
    event.preventDefault();

    const username = document.getElementById("loginUsername").value.trim();
    const password = document.getElementById("loginPassword").value.trim();
    const message = document.getElementById("loginMessage");

    message.textContent = "Signing in...";

    try {
        const response = await fetch("/api/login", {
            method: "POST",
            headers: {
                "Content-Type": "application/json"
            },
            body: JSON.stringify({ username, password })
        });

        const data = await response.json();
        if (!response.ok) {
            throw new Error(data.error || "Login failed");
        }

        localStorage.setItem(TOKEN_KEY, data.token);
        localStorage.setItem(USER_KEY, JSON.stringify(data.user));
        window.location.href = "/dashboard.html";
    } catch (error) {
        message.textContent = error.message;
    }
});

document.getElementById("registerForm").addEventListener("submit", async event => {
    event.preventDefault();

    const name = document.getElementById("registerName").value.trim();
    const username = document.getElementById("registerUsername").value.trim();
    const password = document.getElementById("registerPassword").value.trim();
    const confirmPassword = document.getElementById("registerConfirmPassword").value.trim();
    const message = document.getElementById("registerMessage");

    if (password.length < 8) {
        message.textContent = "Password must be at least 8 characters long.";
        return;
    }

    if (password !== confirmPassword) {
        message.textContent = "Password and confirm password must match.";
        return;
    }

    message.textContent = "Creating admin account...";

    try {
        const response = await fetch("/api/register", {
            method: "POST",
            headers: {
                "Content-Type": "application/json"
            },
            body: JSON.stringify({ name, username, password })
        });

        const data = await response.json();
        if (!response.ok) {
            throw new Error(data.error || "Registration failed");
        }

        localStorage.setItem(TOKEN_KEY, data.token);
        localStorage.setItem(USER_KEY, JSON.stringify(data.user));
        window.location.href = "/dashboard.html";
    } catch (error) {
        message.textContent = error.message;
    }
});
