from fastapi import FastAPI, HTTPException, Header, Request
from fastapi.responses import HTMLResponse
from fastapi.staticfiles import StaticFiles
from fastapi.middleware.cors import CORSMiddleware
from fastapi.templating import Jinja2Templates
from pydantic import BaseModel
from supabase import Client, create_client
import bcrypt
from jose import jwt
import os

# ===============================
# CONFIGURACIÓN SUPABASE
# ===============================
SUPABASE_URL = "https://kjomvdghldqolamokekf.supabase.co"
SUPABASE_KEY = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJzdXBhYmFzZSIsInJlZiI6Imtqb212ZGdobGRxb2xhbW9rZWtmIiwicm9sZSI6InNlcnZpY2Vfcm9sZSIsImlhdCI6MTc2MDgzODU2MiwiZXhwIjoyMDc2NDE0NTYyfQ.UF4FMUphQk4PEuzqAKVL6XjwezrcfG-I7kxgCd8gKFc"

supabase: Client = create_client(SUPABASE_URL, SUPABASE_KEY)

# Probar conexión
try:
    supabase.table("usuarios").select("*").execute()
    print("✓ Conexión con Supabase correcta")
except Exception as e:
    print("Error Supabase:", e)

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
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

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

@app.get("/panel", response_class=HTMLResponse)
async def get_panel(request: Request):
    return templates.TemplateResponse("panel.html", {"request": request})
