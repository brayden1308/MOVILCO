const API = "https://movilco.onrender.com"; // update if needed
const token = localStorage.getItem("token");
if (!token) {
  window.location.href = "/";
}

// show user info from token payload
const payload = JSON.parse(atob(token.split(".")[1]));
document.getElementById("userInfo").innerHTML = `<strong>${payload.email}</strong><br>${payload.role} - ${payload.distrito||'Nacional'}`;

// load regions
async function toggleRegions() {
  const cont = document.getElementById("regionsList");
  if (cont.innerHTML.trim() !== "") { cont.innerHTML = ""; return; }
  cont.innerHTML = "<em>Cargando regiones...</em>";
  const res = await fetch(`${API}/regions`);
  const regions = await res.json();
  cont.innerHTML = "";
  regions.forEach(r => {
    const div = document.createElement("div");
    div.className = "region-item";
    div.textContent = r.nombre;
    div.onclick = () => loadDistricts(r.id, r.nombre);
    cont.appendChild(div);
  });
}

async function loadDistricts(region_id, region_name) {
  const res = await fetch(`${API}/districts/${region_id}`);
  const districts = await res.json();
  const box = document.getElementById("mainArea");
  box.innerHTML = `<h3>${region_name}</h3>`;
  if (!districts.length) { box.innerHTML += "<p>No hay distritos</p>"; return; }
  districts.forEach(d => {
    const b = document.createElement("button");
    b.textContent = d.nombre;
    b.style.display = "block";
    b.style.margin = "8px 0";
    b.onclick = () => loadMetas(d.nombre);
    box.appendChild(b);
  });
}

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
  let html = `<h3>Metas - ${distrito}</h3><table style="width:100%;border-collapse:collapse"><tr><th>Año</th><th>Mes</th><th>Objetivo</th><th>Alcanzado</th></tr>`;
  metas.forEach(m => {
    html += `<tr style="border-top:1px solid #eee"><td>${m.anio}</td><td>${m.mes}</td><td>${m.objetivo}</td><td>${m.alcanzado}</td></tr>`;
  });
  html += `</table>`;
  box.innerHTML = html;
}

function logout() {
  localStorage.removeItem("token");
  window.location.href = "/";
}
