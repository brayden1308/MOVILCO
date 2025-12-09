const API = "https://movilco.onrender.com";
const token = localStorage.getItem("token");
console.log("DEBUG: token from localStorage:", token);

if (!token) {
  console.warn("DEBUG: No token found — redirecting to login");
  // no redirigir inmediatamente para ver errores: mostrar aviso visible
  document.body.innerHTML = `
    <div style="padding:30px;text-align:center;">
      <h2>No autenticado</h2>
      <p>No existe token en localStorage. Vuelve al <a href="/">login</a>.</p>
    </div>`;
  throw new Error("No token");
}

let payload = null;
try {
  payload = JSON.parse(atob(token.split(".")[1]));
  console.log("DEBUG: token payload:", payload);
} catch (e) {
  console.error("DEBUG: Error decoding token:", e);
  // mostrar mensaje en pantalla para no redirigir y perder el log
  document.body.innerHTML = `
    <div style="padding:30px;text-align:center;">
      <h2>Token inválido</h2>
      <pre style="color:red;">${e.toString()}</pre>
      <p>Elimina el token manualmente en DevTools → Application → Local Storage</p>
      <a href="/">Volver a login</a>
    </div>`;
  throw e;
}

// Asegura que el contenedor exista en el HTML
if (!document.getElementById("userInfo")) {
  const s = document.createElement("div");
  s.id = "userInfo";
  s.style.margin = "18px";
  document.body.insertBefore(s, document.body.firstChild);
}

document.getElementById("userInfo").innerHTML = `
  <strong>${payload.email}</strong><br>
  ${payload.role || "Rol no definido"} - ${payload.distrito || "Nacional"}
`;

// Aquí ya tenemos token y payload OK — validar /me opcionalmente
(async function validateMe() {
  try {
    const r = await fetch(`${API}/me`, {
      headers: { "Authorization": `Bearer ${token}` }
    });
    console.log("DEBUG: /me status", r.status);
    if (!r.ok) {
      const txt = await r.text();
      console.error("DEBUG: /me response not ok:", r.status, txt);
      // mostramos error en pantalla sin redirigir
      const box = document.createElement("div");
      box.style.padding = "20px";
      box.innerHTML = `<p style="color:red">Error validando token: ${r.status} — revisa consola</p>`;
      document.body.appendChild(box);
      return;
    }
    const me = await r.json();
    console.log("DEBUG: /me payload", me);
    // si quieres mostrar más datos:
    const info = document.getElementById("userInfo");
    info.innerHTML += `<br><small>ID: ${me.id ?? "N/A"}</small>`;
  } catch (err) {
    console.error("DEBUG: fetch /me failed:", err);
    const box = document.createElement("div");
    box.style.padding = "20px";
    box.innerHTML = `<p style="color:red">Error conectando a backend. Revisa logs.</p>`;
    document.body.appendChild(box);
  }
})();

// resto de funciones (regiones/distritos/metas)...
// Para no romper, reinserta el resto de tu código aquí (toggleRegions, loadDistricts, loadMetas, logout)
// pero deja estas funciones sin cambio para depuración.
