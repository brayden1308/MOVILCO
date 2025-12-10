// Base API URL
const API = "https://movilco.onrender.com";

// Leer token
const token = localStorage.getItem("token");
if (!token) window.location.href = "/";

// Decodificar payload del usuario
const payload = JSON.parse(atob(token.split(".")[1]));

document.getElementById("userEmail").textContent = payload.email;
document.getElementById("userDetails").textContent =
  `${payload.role} — ${payload.distrito || 'Sin distrito asignado'}`;


// ===============================
// 📍 REGIONES
// ===============================
async function toggleRegions() {
  const cont = document.getElementById("mainContent");
  cont.innerHTML = "<p>Cargando regiones...</p>";

  const res = await fetch(`${API}/regions`);
  const regions = await res.json();

  cont.innerHTML = "<h3>Regiones</h3>";

  regions.forEach(r => {
    const btn = document.createElement("button");
    btn.className = "btn-option";
    btn.textContent = r.nombre;
    btn.onclick = () => loadDistricts(r.id, r.nombre);
    cont.appendChild(btn);
  });
}


// ===============================
// 🏙️ MI DISTRITO
// ===============================
async function showMyDistrict() {
  if (!payload.distrito) {
    document.getElementById("mainContent").innerHTML =
      "<p>No tienes un distrito asignado 🚫</p>";
    return;
  }

  document.getElementById("mainContent").innerHTML =
    `<h3>Mi Distrito</h3><p>${payload.distrito}</p>`;
}


// ===============================
// 📊 MIS METAS
// ===============================
async function showMyMetas() {
  const cont = document.getElementById("mainContent");

  if (!payload.distrito) {
    cont.innerHTML = "<p>No tienes metas asignadas 🚫</p>";
    return;
  }

  cont.innerHTML = `<h3>Metas - ${payload.distrito}</h3><p>Cargando...</p>`;

  const res = await fetch(`${API}/metas/${payload.distrito}`, {
    headers: { Authorization: `Bearer ${token}` }
  });

  const metas = await res.json();

  if (!metas.length) {
    cont.innerHTML = "<p>No hay metas para este distrito 📉</p>";
    return;
  }

  let html = `
    <h3>Metas - ${payload.distrito}</h3>
    <table class='table'>
      <tr><th>Año</th><th>Mes</th><th>Objetivo</th><th>Alcanzado</th></tr>
  `;

  metas.forEach(m => {
    html += `
      <tr>
        <td>${m.anio}</td>
        <td>${m.mes}</td>
        <td>${m.objetivo}</td>
        <td>${m.alcanzado}</td>
      </tr>
    `;
  });

  html += `</table>`;
  cont.innerHTML = html;
}


// ===============================
// 🚪 LOGOUT
// ===============================
function logout() {
  localStorage.removeItem("token");
  window.location.href = "/";
}
