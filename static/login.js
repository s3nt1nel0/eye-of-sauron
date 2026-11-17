"use strict";

(function () {
  const form = document.getElementById("loginForm");
  const errorEl = document.getElementById("loginError");

  try {
    const theme = localStorage.getItem("fw-theme");
    if (theme === "dark" || theme === "light") document.documentElement.dataset.theme = theme;
  } catch (_) { /* storage unavailable */ }

  form.addEventListener("submit", async (event) => {
    event.preventDefault();
    errorEl.textContent = "";
    const button = form.querySelector("button[type=submit]");
    button.disabled = true;
    try {
      const res = await fetch("/api/v1/auth/login", {
        method: "POST",
        credentials: "same-origin",
        headers: { "Content-Type": "application/json", "Accept": "application/json" },
        body: JSON.stringify({ username: form.username.value.trim(), password: form.password.value }),
      });
      if (res.ok) {
        window.location.replace("/");
        return;
      }
      if (res.status === 429) errorEl.textContent = "Too many failed attempts. Please wait and try again.";
      else if (res.status === 422) errorEl.textContent = "Please enter a valid username and password.";
      else errorEl.textContent = "Invalid username or password.";
    } catch (_) {
      errorEl.textContent = "Cannot reach the server.";
    } finally {
      form.password.value = "";
      button.disabled = false;
    }
  });
})();
