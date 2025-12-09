from fastapi import FastAPI, HTTPException, Header, Request
from fastapi.responses import FileResponse, JSONResponse, HTMLResponse
from fastapi.staticfiles import StaticFiles
from fastapi.middleware.cors import CORSMiddleware
from fastapi.templating import Jinja2Templates
from pydantic import BaseModel
from supabase import create_client, Client
import bcrypt
from jose import jwt, JWTError
import os

# ===============================
# CONFIGURACIÓN SUPABASE
# ===============================
SUPABASE_URL = "https://kjomvdghldqolamokekf.supabase.co"
SUPABASE_KEY = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJzdXBhYmFzZSIsInJlZiI6Imtqb212ZGdobGRxb2xhbW9rZWtmIiwicm9sZSI6InNlcnZpY2Vfcm9sZSIsImlhdCI6MTc2MDgzODU2MiwiZXhwIjoyMDc2NDE0NTYyfQ.UF4FMUphQk4PEuzqAKVL6XjwezrcfG-I7kxgCd8gKFc"
supabase: Client = create_client(SUPABASE_URL, SUPABASE_KEY)

# ===============================
# JWT CONFIG
# ===============================
SECRET_KEY = "Emivargas1308"
ALGORITHM = "HS256"

# ===============================
# FASTAPI INIT
# ===============================
app = FastAPI()

app.add_middleware(
    CORSMiddleware,
    allow_origins=["https://movilco.onrender.com", "http://localhost:8000", "*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# STATIC
app.mount("/static", StaticFiles(directory="static"), name="static")
app.mount("/IMG", StaticFiles(directory="IMG"), name="IMG")
templates = Jinja2Templates(directory="templates")

@app.get("/", response_class=HTMLResponse)
async def serve_index(request: Request):
    return templates.TemplateResponse("index.html", {"request": request})


# ============================
# MODELOS
# ============================
class RegisterModel(BaseModel):
    email: str
    password: str
    role: str = "misionera"
    region: str | None = None
    distrito: str | None = None

class LoginModel(BaseModel):
    email: str
    password: str

class PasswordReset(BaseModel):
    email: str
    old_password: str
    new_password: str


# ============================
# AUTENTICACIÓN
# ============================

@app.post("/register")
async def register(data: RegisterModel):
    existing = supabase.table("usuarios").select("*").eq("email", data.email).execute()
    if existing.data:
        raise HTTPException(400, "Usuario ya existe")

    hashed = bcrypt.hashpw(data.password.encode(), bcrypt.gensalt()).decode()
    supabase.table("usuarios").insert({
        "email": data.email,
        "password": hashed,
        "role": data.role,
        "region": data.region,
        "distrito": data.distrito
    }).execute()

    return {"message": "Usuario registrado correctamente"}

@app.post("/login")
async def login(data: LoginModel):
    res = supabase.table("usuarios").select("*").eq("email", data.email).execute()
    if not res.data:
        raise HTTPException(400, "Usuario no encontrado")

    user = res.data[0]

    if not bcrypt.checkpw(data.password.encode(), user["password"].encode()):
        raise HTTPException(400, "Contraseña incorrecta")

    payload = {
        "email": user["email"],
        "id": user["id"],
        "role": user.get("role"),
        "region": user.get("region"),
        "distrito": user.get("distrito")
    }

    token = jwt.encode(payload, SECRET_KEY, algorithm=ALGORITHM)

    return {"token": token, "user": payload}

@app.get("/me")
async def me(Authorization: str = Header(None)):
    if not Authorization:
        raise HTTPException(401, "Sin token")

    try:
        token = Authorization.split(" ")[1]
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        return payload
    except:
        raise HTTPException(401, "Token inválido")

@app.post("/reset-password")
async def reset(data: PasswordReset):
    res = supabase.table("usuarios").select("*").eq("email", data.email).execute()
    if not res.data:
        raise HTTPException(400, "Usuario no encontrado")

    user = res.data[0]
    if not bcrypt.checkpw(data.old_password.encode(), user["password"].encode()):
        raise HTTPException(400, "Contraseña incorrecta")

    new_hashed = bcrypt.hashpw(data.new_password.encode(), bcrypt.gensalt()).decode()
    supabase.table("usuarios").update({"password": new_hashed}).eq("email", data.email).execute()

    return {"message": "Contraseña actualizada"}


# ============================
# REGIONES / DISTRITOS / METAS
# ============================

@app.get("/regions")
async def get_regions():
    r = supabase.table("regiones").select("*").execute()
    return r.data

@app.get("/districts/{region_id}")
async def get_districts(region_id: int):
    r = supabase.table("distritos").select("*").eq("region_id", region_id).execute()
    return r.data

@app.get("/metas/{distrito}")
async def get_metas(distrito: str, Authorization: str = Header(None)):
    # validar district existente
    r = supabase.table("distritos").select("*").eq("nombre", distrito).execute()
    if not r.data:
        raise HTTPException(404, "Distrito no encontrado")

    distrito_id = r.data[0]["id"]
    metas = supabase.table("metas").select("*").eq("distrito_id", distrito_id).execute()
    return metas.data
@app.get("/panel", response_class=HTMLResponse)
async def get_panel(request: Request):
    return templates.TemplateResponse("panel.html", {"request": request})
