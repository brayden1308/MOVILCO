// ============================
//  CONFIGURACIÓN BASE
// ============================
const API = "https://movilco.onrender.com";
const token = localStorage.getItem("token");

// Si no hay token: vuelve al login
if (!token) window.location.href = "/";

// Decodificar token
const payload = JSON.parse(atob(token.split(".")[1]));

// Mostrar info del usuario
document.getElementById("userInfo").innerHTML = `
  <strong>${payload.email}</strong><br>
  ${payload.role} - ${payload.distrito || "Nacional"}
`;

// ============================
//  CONTROL POR ROLES
// ============================
if (payload.role === "misionera") {
  document.getElementById("btnRegiones").style.display = "none";
}

if (payload.role === "distrito") {
  document.getElementById("btnRegiones").style.display = "none";
}

// Nacional = todo habilitado (no tocamos nada)


// ============================
//  REGIONES
// ============================
async function toggleRegions() {
  const cont = document.getElementById("regionsList");

  if (cont.innerHTML.trim() !== "") {
    cont.innerHTML = "";
    document.getElementById("mainArea").innerHTML = "<p>Selecciona una región</p>";
    return;
  }

  cont.innerHTML = "<p>Cargando regiones...</p>";

  const res = await fetch(`${API}/regions`);
  const regions = await res.json();

  cont.innerHTML = "";
  regions.forEach(r => {
    const div = document.createElement("div");
    div.className = "region-card";
    div.innerHTML = `
      <p>${r.nombre}</p>
      <button class="btn-small" onclick="loadDistricts(${r.id}, '${r.nombre}')">Ver Distritos</button>
    `;
    cont.appendChild(div);
  });
}


// ============================
//  DISTRITOS
// ============================
async function loadDistricts(region_id, region_name) {
  const box = document.getElementById("mainArea");
  box.innerHTML = `<h3>${region_name}</h3><p>Cargando distritos...</p>`;

  const res = await fetch(`${API}/districts/${region_id}`);
  const districts = await res.json();

  box.innerHTML = `<h3>${region_name}</h3>`;

  if (!districts.length) {
    box.innerHTML += "<p>No hay distritos registrados</p>";
    return;
  }

  districts.forEach(d => {
    const btn = document.createElement("button");
    btn.className = "btn-district";
    btn.textContent = d.nombre;
    btn.onclick = () => loadMetas(d.nombre);
    box.appendChild(btn);
  });
}


// ============================
//  METAS POR DISTRITO
// ============================
async function loadMetas(distrito) {
  const box = document.getElementById("mainArea");
  box.innerHTML = `<h3>Metas - ${distrito}</h3><p>Cargando...</p>`;

  const res = await fetch(`${API}/metas/${encodeURIComponent(distrito)}`, {
    headers: { "Authorization": `Bearer ${token}` }
  });

  if (!res.ok) {
    box.innerHTML = `<p>Error cargando metas 🚫</p>`;
    return;
  }

  const metas = await res.json();

  if (!metas.length) {
    box.innerHTML = `<h3>Metas - ${distrito}</h3><p>No hay metas registradas 📉</p>`;
    return;
  }

  let html = `
    <h3>Metas - ${distrito}</h3>
    <table class="table">
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

  html += "</table>";
  box.innerHTML = html;
}


// ============================
//  MI DISTRITO & MIS METAS
// ============================
function showMyDistrict() {
  if (!payload.distrito) return alert("No tienes distrito asignado");
  loadMetas(payload.distrito);
}

function showMyMetas() {
  if (!payload.distrito) return alert("No tienes distrito asignado");
  loadMetas(payload.distrito);
}


// ============================
//  CERRAR SESIÓN
// ============================
document.getElementById("logoutBtn").addEventListener("click", () => {
  localStorage.removeItem("token");
  window.location.href = "/";
});
