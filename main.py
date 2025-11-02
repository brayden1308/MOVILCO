from fastapi import FastAPI, HTTPException, Header
from pydantic import BaseModel
from supabase import create_client, Client
import bcrypt
from jose import jwt, JWTError
from fastapi.staticfiles import StaticFiles
from fastapi.responses import HTMLResponse, FileResponse
from fastapi.middleware.cors import CORSMiddleware
import os


# ===============================
# CONFIGURACIÓN SUPABASE
# ===============================

SUPABASE_URL = "https://kjomvdghldqolamokekf.supabase.co"
SUPABASE_KEY = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJzdXBhYmFzZSIsInJlZiI6Imtqb212ZGdobGRxb2xhbW9rZWtmIiwicm9sZSI6InNlcnZpY2Vfcm9sZSIsImlhdCI6MTc2MDgzODU2MiwiZXhwIjoyMDc2NDE0NTYyfQ.UF4FMUphQk4PEuzqAKVL6XjwezrcfG-I7kxgCd8gKFc"  # <-- PÉGALA AQUÍ
supabase: Client = create_client(SUPABASE_URL, SUPABASE_KEY)

# ===============================
# CONFIGURACIÓN JWT
# ===============================

SECRET_KEY = "Emivargas1308" 
ALGORITHM = "HS256"

# ===============================
# FASTAPI APP
# ===============================

app = FastAPI()
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

#  Montar carpetas estáticas correctamente
app.mount("/static", StaticFiles(directory="static"), name="static")
app.mount("/IMG", StaticFiles(directory="IMG"), name="IMG")
app.mount("/static", StaticFiles(directory="."), name="static")
from fastapi.middleware.cors import CORSMiddleware

class UserRegister(BaseModel):
    email: str
    password: str

class UserLogin(BaseModel):
    email: str
    password: str

# ===============================
# RUTA: REGISTRO
# ===============================

@app.post("/register")
async def register(user: UserRegister):
    # Verificar si el usuario ya existe
    existing_user = supabase.table("usuarios").select("*").eq("email", user.email).execute()
    if existing_user.data:
        raise HTTPException(status_code=400, detail="El usuario ya existe")

    # Encriptar contraseña
    hashed = bcrypt.hashpw(user.password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')

    # Insertar en Supabase
    data = supabase.table("usuarios").insert({"email": user.email, "password": hashed}).execute()
    print("Resultado Supabase INSERT:", data)
    return {"message": "Usuario registrado correctamente", "db_response": data}


# ===============================
# RUTA: LOGIN
# ===============================

@app.post("/login")
async def login(user: UserLogin):
    response = supabase.table("usuarios").select("*").eq("email", user.email).execute()
    if not response.data:
        raise HTTPException(status_code=400, detail="Usuario no encontrado")

    db_user = response.data[0]

    # Verificar contraseña
    if not bcrypt.checkpw(user.password.encode('utf-8'), db_user["password"].encode('utf-8')):
        raise HTTPException(status_code=400, detail="Contraseña incorrecta")

    # Generar token con email + id
    token = jwt.encode({"email": db_user["email"], "id": db_user["id"]}, SECRET_KEY, algorithm=ALGORITHM)

    return {"token": token}

# ===============================
# RUTA: ME (VER USUARIO ACTUAL)
# ===============================

@app.get("/me")
async def get_me(Authorization: str = Header(None)):
    if not Authorization:
        raise HTTPException(status_code=401, detail="Token no proporcionado")

    try:
        token = Authorization.split(" ")[1]  # "Bearer token"
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        return {"email": payload["email"], "id": payload["id"]}
    except (JWTError, IndexError):
        raise HTTPException(status_code=401, detail="Token inválido o expirado")
@app.post("/logout")
async def logout():
    return {"message": "Logout exitoso. Elimina el token en el frontend."}
class PasswordReset(BaseModel):
    email: str
    old_password: str
    new_password: str

@app.post("/reset-password")
async def reset_password(data: PasswordReset):
    # Buscar usuario
    response = supabase.table("usuarios").select("*").eq("email", data.email).execute()
    if not response.data:
        raise HTTPException(status_code=400, detail="Usuario no encontrado")

    db_user = response.data[0]

    # Verificar contraseña actual
    if not bcrypt.checkpw(data.old_password.encode('utf-8'), db_user["password"].encode('utf-8')):
        raise HTTPException(status_code=400, detail="Contraseña actual incorrecta")

    # Hash nueva contraseña
    new_hashed = bcrypt.hashpw(data.new_password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')

    # Actualizar en Supabase
    supabase.table("usuarios").update({"password": new_hashed}).eq("email", data.email).execute()

    return {"message": "Contraseña actualizada correctamente"}
from fastapi.responses import HTMLResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from fastapi import Request


# Archivos estáticos
app.mount("/static", StaticFiles(directory="static"), name="static")
app.mount("/IMG", StaticFiles(directory="IMG"), name="IMG")

# HTML
templates = Jinja2Templates(directory="templates")

@app.get("/", response_class=HTMLResponse)
async def get_index(request: Request):
    return templates.TemplateResponse("index.html", {"request": request})
@app.get("/", response_class=HTMLResponse)
async def serve_index():
    file_path = os.path.join(os.path.dirname(__file__), "templates/index.html")
    with open(file_path, "r", encoding="utf-8") as f:
        return f.read()
