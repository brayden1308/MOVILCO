const API = "https://movilco.onrender.com"; // Backend Render
const token = localStorage.getItem("token");


// ======================
// Mostrar datos del usuario desde el JWT
// ======================
try {
  const payload = JSON.parse(atob(token.split(".")[1]));

  document.getElementById("userInfo").innerHTML = `
    <strong>${payload.email}</strong><br>
    ${payload.role || "Rol no definido"} - ${payload.distrito || "Nacional"}
  `;
} catch (e) {
  console.error("Error decoding token:", e);
  logout();
}

// ======================
// REGIONES
// ======================
async function toggleRegions() {
  const container = document.getElementById("regionsList");

  if (container.innerHTML.trim() !== "") {
    container.innerHTML = "";
    return;
  }

  container.innerHTML = "<em>Cargando regiones...</em>";

  const res = await fetch(`${API}/regions`);
  if (!res.ok) {
    container.innerHTML = "<p>Error cargando regiones</p>";
    return;
  }

  const regions = await res.json();
  container.innerHTML = "";

  regions.forEach(r => {
    const div = document.createElement("div");
    div.className = "region-item";
    div.textContent = r.nombre;
    div.onclick = () => loadDistricts(r.id, r.nombre);
    container.appendChild(div);
  });
}

// ======================
// DISTRITOS
// ======================
async function loadDistricts(region_id, region_name) {
  const res = await fetch(`${API}/districts/${region_id}`);
  const districts = await res.json();

  const box = document.getElementById("mainArea");
  box.innerHTML = `<h3>${region_name}</h3>`;

  if (!districts.length) {
    box.innerHTML += "<p>No hay distritos disponibles</p>";
    return;
  }

  districts.forEach(d => {
    const btn = document.createElement("button");
    btn.className = "btn-secondary";
    btn.textContent = d.nombre;
    btn.onclick = () => loadMetas(d.nombre);
    box.appendChild(btn);
  });
}

// ======================
// METAS
// ======================
async function loadMetas(distrito) {
  const box = document.getElementById("mainArea");
  box.innerHTML = `<h3>Metas - ${distrito}</h3><em>Cargando...</em>`;

  const res = await fetch(`${API}/metas/${encodeURIComponent(distrito)}`, {
    headers: { "Authorization": `Bearer ${token}` }
  });

  if (!res.ok) {
    box.innerHTML = `<p>Error cargando metas: ${res.statusText}</p>`;
    return;
  }

  const metas = await res.json();

  if (!metas.length) {
    box.innerHTML = `<h3>Metas - ${distrito}</h3><p>No hay metas registradas.</p>`;
    return;
  }

  let html = `
    <h3>Metas - ${distrito}</h3>
    <table class="metas-table">
    <tr>
        <th>Año</th>
        <th>Mes</th>
        <th>Objetivo</th>
        <th>Alcanzado</th>
    </tr>
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
  box.innerHTML = html;
}

// ======================
// LOGOUT
// ======================
function logout() {
  localStorage.removeItem("token");
  window.location.href = "/";
}
