// 🌐 API Base
const API = "https://movilco.onrender.com";

// 🔐 Token de sesión
const token = localStorage.getItem("token");
if (!token) window.location.href = "/";

// 🔎 Información del usuario
const user = JSON.parse(atob(token.split(".")[1]));

// Mostrar usuario
document.getElementById("userInfo").innerHTML = `
  <strong>${user.email}</strong><br>
  ${user.role} - ${user.distrito || 'Nacional'}
`;

/* ==================================================
   PANEL ACTIONS (BOTONES)
================================================== */

// Cargar metas del usuario según su distrito o rol
async function showMetas() {
  const main = document.getElementById("main-content");
  main.innerHTML = `<h2>Metas</h2><p>Cargando...</p>`;

  let url = "";
  if (user.role === "Misionera") {
    url = `${API}/metas/${encodeURIComponent(user.distrito)}`;
  } else {
    main.innerHTML = `<p>Selecciona una región para continuar</p>`;
    return;
  }

  const res = await fetch(url, {
    headers: { "Authorization": `Bearer ${token}` }
  });

  if (!res.ok) {
    main.innerHTML = `<p>🚫 No se pudieron cargar metas</p>`;
    return;
  }

  const metas = await res.json();
  renderMetas(main, metas, user.distrito);
}


// Mostrar form si rol es Admin o Nacional
function showAdd() {
  const main = document.getElementById("main-content");

  if (user.role !== "Admin" && user.role !== "Nacional") {
    main.innerHTML = `<p>❌ No tienes permisos para añadir metas</p>`;
    return;
  }

  main.innerHTML = `
    <h2>➕ Añadir Meta</h2>
    <form id="addForm" class="form-box">
      <input type="text" id="distrito" placeholder="Distrito" required />
      <input type="number" id="anio" placeholder="Año" required />
      <input type="text" id="mes" placeholder="Mes" required />
      <input type="number" id="objetivo" placeholder="Objetivo" required />
      <button class="btn-gold" type="submit">Guardar Meta</button>
    </form>
    <div id="msg"></div>
  `;

  document.getElementById("addForm").onsubmit = saveMeta;
}


// Mostrar progreso simple por ahora
async function showProgress() {
  const main = document.getElementById("main-content");
  main.innerHTML = `<h2>📊 Progreso del Distrito</h2><p>Cargando...</p>`;

  const res = await fetch(`${API}/metas/${encodeURIComponent(user.distrito)}`, {
    headers: { "Authorization": `Bearer ${token}` }
  });

  const metas = await res.json();
  let done = metas.filter(m => m.alcanzado >= m.objetivo).length;

  main.innerHTML = `
    <p>Metas completadas: ${done} / ${metas.length}</p>
    <progress max="${metas.length}" value="${done}"></progress>
  `;
}


// Mostrar info de usuario
function showPersonal() {
  const main = document.getElementById("main-content");

  main.innerHTML = `
    <h2>👤 Perfil</h2>
    <p>Email: ${user.email}</p>
    <p>Rol: ${user.role}</p>
    <p>Distrito: ${user.distrito || "Nacional"}</p>
    <button class="feedback-btn" onclick="logout()">Cerrar Sesión</button>
  `;
}


// Guardar meta (Admin solo)
async function saveMeta(e) {
  e.preventDefault();
  const msg = document.getElementById("msg");

  const data = {
    distrito: document.getElementById("distrito").value,
    anio: parseInt(document.getElementById("anio").value),
    mes: document.getElementById("mes").value,
    objetivo: parseInt(document.getElementById("objetivo").value)
  };

  const res = await fetch(`${API}/metas`, {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      "Authorization": `Bearer ${token}`
    },
    body: JSON.stringify(data)
  });

  msg.innerHTML = res.ok
    ? "<p style='color:green'>✔ Meta guardada</p>"
    : "<p style='color:red'>❌ No se pudo guardar</p>";
}


// Dibujar metas
function renderMetas(main, metas, distrito) {
  if (!metas.length) {
    main.innerHTML = `<h2>No hay metas en ${distrito}</h2>`;
    return;
  }

  let html = `<h2>Metas - ${distrito}</h2><table class="table">`;
  html += `<tr><th>Año</th><th>Mes</th><th>Objetivo</th><th>Alcanzado</th></tr>`;

  metas.forEach(m => {
    html += `
      <tr>
        <td>${m.anio}</td>
        <td>${m.mes}</td>
        <td>${m.objetivo}</td>
        <td>${m.alcanzado}</td>
      </tr>`;
  });

  html += `</table>`;
  main.innerHTML = html;
}


// Logout
function logout() {
  localStorage.removeItem("token");
  window.location.href = "/";
}
//===========================
//  CERRAR SESIÓN
// ============================
document.getElementById("logoutBtn").addEventListener("click", () => {
  localStorage.removeItem("token");
  window.location.href = "/";
});
