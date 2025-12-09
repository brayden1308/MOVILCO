const API = "https://movilco.onrender.com";
document.getElementById("loginForm").addEventListener("submit", async e => {
  e.preventDefault();
  const email = document.getElementById("email").value;
  const password = document.getElementById("password").value;
  const res = await fetch(`${API}/login`, {
    method: "POST",
    headers: {"Content-Type": "application/json"},
    body: JSON.stringify({email, password})
  });
  if (!res.ok) {
    document.getElementById("error").innerText = "Credenciales inválidas";
    return;
  }
  const data = await res.json();
  localStorage.setItem("token", data.token);
  // store user payload as well for quick access
  localStorage.setItem("user", JSON.stringify(data.user));
  // redirect by role
  const role = data.user.role;
  if (role === "admin_distrital" || role === "misionera") {
    // redirect to panel and open metas of their district
    window.location.href = "/panel";
  } else {
    // admin_nacional etc
    window.location.href = "/panel";
  }
});
