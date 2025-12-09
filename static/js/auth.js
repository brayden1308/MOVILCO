const API_URL = "https://movilco.onrender.com"; 

document.getElementById("loginForm").addEventListener("submit", async (e) => {
    e.preventDefault();
    
    const email = document.getElementById("loginEmail").value;
    const password = document.getElementById("loginPassword").value;

    const res = await fetch(`${API_URL}/login`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ email, password }),
    });

    const data = await res.json();
    const msg = document.getElementById("message");

    if (res.ok) {
        localStorage.setItem("token", data.token);
        msg.textContent = "Inicio exitoso ✔";
        msg.style.color = "green";

        setTimeout(() => {
            window.location.href = "/panel";
        }, 800);
    } else {
        msg.textContent = "❌ " + data.detail;
    }
});
