from fastapi import FastAPI, Form, HTTPException, Request
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.templating import Jinja2Templates
from fastapi.staticfiles import StaticFiles
from app.auth import authenticate_user, create_access_token, verify_token
from datetime import timedelta

# Configurații generale
ACCESS_TOKEN_EXPIRE_MINUTES = 30
templates = Jinja2Templates(directory="app/templates")
app = FastAPI()

app.mount("/static", StaticFiles(directory="app/static"), name="static")

# Pagina de login
@app.get("/", response_class=HTMLResponse)
async def login_page(request: Request):
    return templates.TemplateResponse("index.html", {"request": request})

# Login și generare token
@app.post("/login")
async def login(username: str = Form(...), password: str = Form(...)):
    user = authenticate_user(username, password)
    if not user:
        raise HTTPException(status_code=400, detail="Invalid credentials")
    token_expires = timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    token = create_access_token(data={"sub": username}, expires_delta=token_expires)
    response = RedirectResponse("/dashboard", status_code=303)
    response.set_cookie(key="access_token", value=f"Bearer {token}", httponly=True)
    return response

# Pagina de dashboard
@app.get("/dashboard", response_class=HTMLResponse)
async def dashboard(request: Request):
    token = request.cookies.get("access_token")  # Extrage token-ul din cookies
    if not token:
        return RedirectResponse("/", status_code=401)  # Redirecționează la login
    try:
        verify_token(token.split(" ")[1])  # Elimină prefixul "Bearer"
    except HTTPException:
        return RedirectResponse("/", status_code=403)  # Token invalid -> login din nou
    return templates.TemplateResponse("dashboard.html", {"request": request})
