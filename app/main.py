import os
from typing import Annotated
from fastapi import FastAPI, HTTPException, Request, Depends, status
from fastapi.responses import HTMLResponse
from fastapi.openapi.docs import get_redoc_html
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from pydantic import BaseModel, Field

from app.auth import (
    validate_password_strength,
    hash_password,
    verify_password,
    create_access_token,
    decode_token
)
from app.database import init_db, get_db
from app.logger import log_event

os.makedirs("logs", exist_ok=True)
init_db()

# --- METADANE SEKCJI W JĘZYKU POLSKIM ---
tags_metadata = [
    {
        "name": "1. Uwierzytelnianie i Rejestracja",
        "description": "Zarządzanie tożsamością: rejestracja z wymuszeniem silnego hasła, logowanie JWT oraz ochrona przed Brute-Force.",
    },
    {
        "name": "2. Kontrola Dostępu (RBAC)",
        "description": "Zasoby chronione wymagające uprawnień administracyjnych (Zasada Minimalnych Uprawnień - PoLP).",
    },
    {
        "name": "3. Diagnostyka Systemu",
        "description": "Weryfikacja dostępności serwera API.",
    },
]

app = FastAPI(
    title="System Bezpiecznego Logowania (Architektura Zero Trust)",
    description="""
### Projekt Laboratoryjny: Bezpieczeństwo Aplikacji Webowych
System demonstruje kluczowe mechanizmy obronne:
* **Polityka silnych haseł**: min. 8 znaków, cyfra, mała/duża litera, znak specjalny.
* **Uwierzytelnianie tokenowe (JWT)**: podpis HMAC-SHA256 z czasem ważności.
* **Kontrola dostępu (RBAC)**: separacja uprawnień użytkownika (`user`) i administratora (`admin`).
* **Ochrona przed atakiem Brute-Force**: natychmiastowa blokada konta po 3 nieudanych próbach.
* **Integralny Dziennik Audytowy**: rejestracja wszystkich zdarzeń bezpieczeństwa w pliku `logs/audit.log`.
""",
    version="1.0.0",
    openapi_tags=tags_metadata,
    docs_url=None,   # Wyłączamy domyślny angielski Swagger, aby podpiąć wersję spolszczoną
    redoc_url=None,
)

security = HTTPBearer()

@app.get("/gui", include_in_schema=False, response_class=HTMLResponse)
async def visual_interface():
    return """
    <!DOCTYPE html>
    <html lang="pl" class="dark">
    <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>Panel Bezpieczeństwa - Zero Trust</title>
        <script src="https://cdn.tailwindcss.com"></script>
        <script>
            tailwind.config = {
                darkMode: 'class',
                theme: {
                    extend: {
                        colors: {
                            brand: { 500: '#0ea5e9', 600: '#0284c7', 700: '#0369a1' },
                            dark: { 800: '#0f172a', 900: '#020617', 700: '#1e293b' }
                        }
                    }
                }
            }
        </script>
        <link href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.4.0/css/all.min.css" rel="stylesheet">
    </head>
    <body class="bg-dark-900 text-slate-100 min-h-screen font-sans antialiased flex flex-col justify-between">
        
        <!-- Pasek nawigacji -->
        <header class="border-b border-slate-800 bg-dark-800/80 backdrop-blur sticky top-0 z-50">
            <div class="max-w-6xl mx-auto px-6 py-4 flex justify-between items-center">
                <div class="flex items-center space-x-3">
                    <div class="h-10 w-10 rounded-xl bg-gradient-to-tr from-sky-500 to-indigo-600 flex items-center justify-center shadow-lg shadow-sky-500/20">
                        <i class="fa-solid fa-shield-halved text-white text-lg"></i>
                    </div>
                    <div>
                        <h1 class="font-bold text-lg leading-tight tracking-wide">Zero Trust Auth Guard</h1>
                        <p class="text-xs text-sky-400 font-medium">Demonstrator Bezpieczeństwa NIST CSF 2.0</p>
                    </div>
                </div>
                <div class="flex items-center space-x-3 text-xs">
                    <span class="inline-flex items-center px-2.5 py-1 rounded-full bg-emerald-500/10 text-emerald-400 border border-emerald-500/20">
                        <span class="w-1.5 h-1.5 rounded-full bg-emerald-400 mr-1.5 animate-pulse"></span> Serwer aktywny
                    </span>
                    <a href="/docs" target="_blank" class="px-3 py-1.5 bg-slate-800 hover:bg-slate-700 text-slate-300 rounded-lg transition border border-slate-700">
                        <i class="fa-solid fa-book mr-1"></i> Swagger
                    </a>
                    <a href="/redoc" target="_blank" class="px-3 py-1.5 bg-slate-800 hover:bg-slate-700 text-slate-300 rounded-lg transition border border-slate-700">
                        <i class="fa-solid fa-code mr-1"></i> Redoc
                    </a>
                </div>
            </div>
        </header>

        <!-- Główny kontener -->
        <main class="max-w-6xl mx-auto px-6 py-8 flex-1 grid grid-cols-1 lg:grid-cols-12 gap-8 w-full">
            
            <!-- Lewa kolumna: Formularze -->
            <div class="lg:col-span-7 space-y-6">
                
                <!-- Karta: Rejestracja i Logowanie -->
                <div class="bg-dark-800 rounded-2xl border border-slate-800 p-6 shadow-xl">
                    <div class="flex border-b border-slate-700 mb-6">
                        <button id="tab-login" onclick="switchTab('login')" class="pb-3 px-4 font-semibold text-sky-400 border-b-2 border-sky-400 transition">
                            <i class="fa-solid fa-right-to-bracket mr-2"></i> Logowanie (JWT)
                        </button>
                        <button id="tab-register" onclick="switchTab('register')" class="pb-3 px-4 font-medium text-slate-400 hover:text-slate-200 transition">
                            <i class="fa-solid fa-user-plus mr-2"></i> Rejestracja użytkownika
                        </button>
                    </div>

                    <form id="auth-form" onsubmit="handleAuth(event)" class="space-y-4">
                        <div>
                            <label class="block text-xs font-semibold text-slate-400 uppercase tracking-wider mb-2">Nazwa użytkownika (Login)</label>
                            <div class="relative">
                                <span class="absolute inset-y-0 left-0 flex items-center pl-3.5 text-slate-500">
                                    <i class="fa-solid fa-user text-sm"></i>
                                </span>
                                <input type="text" id="username" required value="filip" placeholder="Wpisz login..." 
                                    class="w-full bg-slate-900 border border-slate-700 rounded-xl pl-10 pr-4 py-2.5 text-sm focus:border-sky-500 focus:ring-1 focus:ring-sky-500 outline-none transition text-slate-200">
                            </div>
                        </div>

                        <div>
                            <label class="block text-xs font-semibold text-slate-400 uppercase tracking-wider mb-2">Hasło dostępu</label>
                            <div class="relative">
                                <span class="absolute inset-y-0 left-0 flex items-center pl-3.5 text-slate-500">
                                    <i class="fa-solid fa-lock text-sm"></i>
                                </span>
                                <input type="password" id="password" required value="B3zpi3czn3997@" placeholder="Wpisz hasło..." 
                                    class="w-full bg-slate-900 border border-slate-700 rounded-xl pl-10 pr-4 py-2.5 text-sm focus:border-sky-500 focus:ring-1 focus:ring-sky-500 outline-none transition text-slate-200">
                            </div>
                            <p id="password-hint" class="text-xs text-slate-400 mt-2 hidden">
                                <i class="fa-solid fa-circle-info text-sky-400 mr-1"></i> Wymogi: min. 8 znaków, cyfra, duża litera i znak specjalny.
                            </p>
                        </div>

                        <button type="submit" id="btn-submit" 
                            class="w-full mt-4 py-3 bg-gradient-to-r from-sky-500 to-indigo-600 hover:from-sky-400 hover:to-indigo-500 text-white font-semibold rounded-xl transition shadow-lg shadow-sky-500/25 flex items-center justify-center space-x-2">
                            <i class="fa-solid fa-arrow-right"></i>
                            <span id="btn-text">Zaloguj i uzyskaj token JWT</span>
                        </button>
                    </form>
                </div>

                <!-- Karta: Panel Administratora (Test RBAC) -->
                <div class="bg-dark-800 rounded-2xl border border-slate-800 p-6 shadow-xl relative overflow-hidden">
                    <div class="flex items-center justify-between mb-4">
                        <div class="flex items-center space-x-3">
                            <div class="h-9 w-9 rounded-lg bg-amber-500/10 text-amber-400 border border-amber-500/20 flex items-center justify-center">
                                <i class="fa-solid fa-lock text-sm"></i>
                            </div>
                            <div>
                                <h3 class="font-bold text-slate-200">Panel Administratora (/admin/dashboard)</h3>
                                <p class="text-xs text-slate-400">Chroniony endpoint wymagający roli <code>admin</code></p>
                            </div>
                        </div>
                        <button onclick="testAdminAccess()" 
                            class="px-4 py-2 bg-amber-600 hover:bg-amber-500 text-white text-xs font-semibold rounded-xl transition shadow-md shadow-amber-600/20 flex items-center space-x-1.5">
                            <i class="fa-solid fa-key"></i>
                            <span>Testuj dostęp RBAC</span>
                        </button>
                    </div>
                    <div id="admin-result" class="p-3.5 rounded-xl bg-slate-900/80 border border-slate-800 text-xs text-slate-400 font-mono">
                        Brak wykonanego zapytania. Zaloguj się, aby przesłać token Bearer.
                    </div>
                </div>

            </div>

            <!-- Prawa kolumna: Aktywny Token i Odpowiedzi -->
            <div class="lg:col-span-5 space-y-6">
                
                <!-- Karta: Token sesyjny JWT -->
                <div class="bg-dark-800 rounded-2xl border border-slate-800 p-6 shadow-xl">
                    <div class="flex items-center justify-between mb-3">
                        <h3 class="text-xs font-semibold text-slate-400 uppercase tracking-wider">
                            <i class="fa-solid fa-id-card-clip text-sky-400 mr-1.5"></i> Aktualny Token JWT
                        </h3>
                        <span id="jwt-badge" class="text-[10px] uppercase font-bold px-2 py-0.5 rounded bg-slate-700 text-slate-300">Brak tokenu</span>
                    </div>
                    <div id="token-box" class="h-28 overflow-y-auto p-3 bg-dark-900 rounded-xl border border-slate-800 text-xs font-mono text-slate-300 break-all select-all">
                        Nie jesteś zalogowany. Wyślij formularz, aby serwer podpisał token sesyjny HMAC-SHA256.
                    </div>
                    <div id="jwt-payload" class="mt-3 p-3 bg-slate-900/60 rounded-xl border border-slate-800/80 text-[11px] font-mono text-slate-400 space-y-1 hidden">
                        <div>Użytkownik (sub): <span id="jwt-sub" class="text-sky-300 font-bold">-</span></div>
                        <div>Rola (role): <span id="jwt-role" class="text-amber-300 font-bold">-</span></div>
                        <div>Wygasa: <span id="jwt-exp" class="text-slate-300">-</span></div>
                    </div>
                </div>

                <!-- Karta: Odpowiedź serwera (Live status) -->
                <div class="bg-dark-800 rounded-2xl border border-slate-800 p-6 shadow-xl">
                    <div class="flex items-center justify-between mb-3">
                        <h3 class="text-xs font-semibold text-slate-400 uppercase tracking-wider">
                            <i class="fa-solid fa-server text-emerald-400 mr-1.5"></i> Odpowiedź serwera API
                        </h3>
                        <span id="status-code" class="text-xs font-mono font-bold px-2 py-0.5 rounded bg-slate-800 text-slate-400">---</span>
                    </div>
                    <pre id="api-response" class="h-44 overflow-y-auto p-3.5 bg-dark-900 rounded-xl border border-slate-800 text-xs font-mono text-emerald-400 whitespace-pre-wrap">Oczekiwanie na pierwsze zdarzenie...</pre>
                </div>

            </div>

        </main>

        <footer class="border-t border-slate-800/60 py-4 text-center text-xs text-slate-500">
            Projekt zespołowy: Bezpieczna aplikacja logowania (Zero Trust) • Politechnika / Uniwersytet 2026
        </footer>

        <!-- Logika JavaScript -->
        <script>
            let currentTab = 'login';
            let savedToken = null;

            function switchTab(tab) {
                currentTab = tab;
                const tabLogin = document.getElementById('tab-login');
                const tabRegister = document.getElementById('tab-register');
                const btnText = document.getElementById('btn-text');
                const hint = document.getElementById('password-hint');

                if (tab === 'login') {
                    tabLogin.className = "pb-3 px-4 font-semibold text-sky-400 border-b-2 border-sky-400 transition";
                    tabRegister.className = "pb-3 px-4 font-medium text-slate-400 hover:text-slate-200 transition";
                    btnText.innerText = "Zaloguj i uzyskaj token JWT";
                    hint.classList.add('hidden');
                } else {
                    tabRegister.className = "pb-3 px-4 font-semibold text-sky-400 border-b-2 border-sky-400 transition";
                    tabLogin.className = "pb-3 px-4 font-medium text-slate-400 hover:text-slate-200 transition";
                    btnText.innerText = "Zarejestruj nowe konto";
                    hint.classList.remove('hidden');
                }
            }

            async function handleAuth(e) {
                e.preventDefault();
                const u = document.getElementById('username').value;
                const p = document.getElementById('password').value;
                const endpoint = currentTab === 'login' ? '/logowanie' : '/rejestracja';

                try {
                    const res = await fetch(endpoint, {
                        method: 'POST',
                        headers: {'Content-Type': 'application/json'},
                        body: JSON.stringify({username: u, password: p})
                    });
                    const data = await res.json();
                    
                    showResponse(res.status, data);

                    if (res.ok && currentTab === 'login') {
                        savedToken = data.access_token;
                        document.getElementById('token-box').innerText = savedToken;
                        document.getElementById('jwt-badge').innerText = "Ważny token";
                        document.getElementById('jwt-badge').className = "text-[10px] uppercase font-bold px-2 py-0.5 rounded bg-emerald-500/20 text-emerald-400 border border-emerald-500/30";
                        
                        // Rozkodowanie JWT bez biblioteki
                        const payload = JSON.parse(atob(savedToken.split('.')[1]));
                        document.getElementById('jwt-sub').innerText = payload.sub;
                        document.getElementById('jwt-role').innerText = payload.role;
                        document.getElementById('jwt-exp').innerText = new Date(payload.exp * 1000).toLocaleTimeString();
                        document.getElementById('jwt-payload').classList.remove('hidden');
                    }
                } catch (err) {
                    showResponse(500, {error: "Błąd połączenia z serwerem"});
                }
            }

            async function testAdminAccess() {
                const resultBox = document.getElementById('admin-result');
                if (!savedToken) {
                    resultBox.innerHTML = "<span class='text-amber-400'><i class='fa-solid fa-triangle-exclamation mr-1'></i> Brak tokenu! Najpierw zaloguj się, aby pobrać poświadczenie.</span>";
                    return;
                }

                try {
                    const res = await fetch('/admin/dashboard', {
                        method: 'GET',
                        headers: {'Authorization': 'Bearer ' + savedToken}
                    });
                    const data = await res.json();
                    showResponse(res.status, data);

                    if (res.status === 403) {
                        resultBox.innerHTML = "<span class='text-rose-400 font-semibold'><i class='fa-solid fa-ban mr-1.5'></i> STATUS 403 FORBIDDEN:</span> " + data.detail;
                    } else if (res.ok) {
                        resultBox.innerHTML = "<span class='text-emerald-400 font-semibold'><i class='fa-solid fa-check mr-1.5'></i> DOSTĘP PRZYZNANY:</span> " + data.komunikat;
                    } else {
                        resultBox.innerText = JSON.stringify(data);
                    }
                } catch (err) {
                    resultBox.innerText = "Błąd zapytania RBAC.";
                }
            }

            function showResponse(status, data) {
                const badge = document.getElementById('status-code');
                const out = document.getElementById('api-response');
                badge.innerText = "HTTP " + status;
                
                if (status >= 200 && status < 300) {
                    badge.className = "text-xs font-mono font-bold px-2.5 py-0.5 rounded bg-emerald-500/20 text-emerald-400 border border-emerald-500/30";
                    out.className = "h-44 overflow-y-auto p-3.5 bg-dark-900 rounded-xl border border-slate-800 text-xs font-mono text-emerald-400 whitespace-pre-wrap";
                } else if (status === 403 || status === 401) {
                    badge.className = "text-xs font-mono font-bold px-2.5 py-0.5 rounded bg-rose-500/20 text-rose-400 border border-rose-500/30";
                    out.className = "h-44 overflow-y-auto p-3.5 bg-dark-900 rounded-xl border border-slate-800 text-xs font-mono text-rose-400 whitespace-pre-wrap";
                } else {
                    badge.className = "text-xs font-mono font-bold px-2.5 py-0.5 rounded bg-amber-500/20 text-amber-400 border border-amber-500/30";
                    out.className = "h-44 overflow-y-auto p-3.5 bg-dark-900 rounded-xl border border-slate-800 text-xs font-mono text-amber-400 whitespace-pre-wrap";
                }
                out.innerText = JSON.stringify(data, null, 2);
            }
        </script>
    </body>
    </html>
    """

class UserAuth(BaseModel):
    username: str = Field(
        ...,
        description="Unikalny identyfikator użytkownika (login)",
        json_schema_extra={"example": "filip"}
    )
    password: str = Field(
        ...,
        description="Hasło użytkownika (min. 8 znaków, wielka/mała litera, cyfra, znak specjalny)",
        json_schema_extra={"example": "B3zpi3czn3997@"}
    )

class KomunikatSukcesu(BaseModel):
    status: str = Field(description="Status operacji", json_schema_extra={"example": "Sukces"})
    detail: str = Field(description="Szczegółowa informacja zwrotna", json_schema_extra={"example": "Użytkownik został zarejestrowany pomyślnie"})

class TokenOdpowiedz(BaseModel):
    access_token: str = Field(
        description="Kryptograficznie podpisany token JWT (HMAC-SHA256)",
        json_schema_extra={"example": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..."}
    )
    token_type: str = Field(
        default="bearer",
        description="Typ poświadczenia autoryzacyjnego",
        json_schema_extra={"example": "bearer"}
    )

class KomunikatBledu(BaseModel):
    detail: str = Field(description="Opis napotkanego błędu")

class AdminDashboardOdpowiedz(BaseModel):
    status: str = Field(json_schema_extra={"example": "Sukces"})
    komunikat: str = Field(json_schema_extra={"example": "Witaj w panelu administratora, admin!"})
    poufne_dane: str = Field(json_schema_extra={"example": "Raport Zero Trust: 100% sprawności, brak incydentów w sieci."})


# --- ENDPOINTY Z POLSKIMI ŚCIEŻKAMI ---

@app.get(
    "/",
    tags=["3. Diagnostyka Systemu"],
    summary="Sprawdzenie stanu serwera",
    description="Zwraca potwierdzenie poprawnego działania serwera aplikacji API.",
    response_model=dict
)
def root():
    return {"status": "Aplikacja działa poprawnie", "komunikat": "Witaj w bezpiecznym API"}


@app.post(
    "/rejestracja",
    tags=["1. Uwierzytelnianie i Rejestracja"],
    summary="Rejestracja nowego użytkownika",
    description="Tworzy konto użytkownika z rolą user po przejściu walidacji siły hasła.",
    response_model=KomunikatSukcesu,
    status_code=status.HTTP_201_CREATED,
    responses={
        201: {"model": KomunikatSukcesu, "description": "Konto zostało utworzone"},
        400: {"model": KomunikatBledu, "description": "Słabe hasło lub zajęta nazwa użytkownika"}
    }
)
def rejestracja(user: UserAuth, request: Request):
    ip = request.client.host if request.client else "127.0.0.1"
    
    if not validate_password_strength(user.password):
        log_event(ip, "REGISTER", user.username, "FAILED", "Haslo nie spelnia wymogow polityki bezpieczenstwa")
        raise HTTPException(
            status_code=400,
            detail="Hasło nie spełnia wymogów (min. 8 znaków, wielka/mała litera, cyfra, znak specjalny)"
        )

    conn = get_db()
    cursor = conn.cursor()
    cursor.execute("SELECT id FROM users WHERE username = ?", (user.username,))
    if cursor.fetchone():
        conn.close()
        log_event(ip, "REGISTER", user.username, "FAILED", "Konto o tej nazwie juz istnieje")
        raise HTTPException(status_code=400, detail="Użytkownik o podanej nazwie już istnieje")

    hashed_pw = hash_password(user.password)
    cursor.execute("INSERT INTO users (username, password_hash, role) VALUES (?, ?, 'user')", (user.username, hashed_pw))
    conn.commit()
    conn.close()

    log_event(ip, "REGISTER", user.username, "SUCCESS", "Zarejestrowano uzytkownika z rola user")
    return {"status": "Sukces", "detail": f"Użytkownik '{user.username}' został zarejestrowany pomyślnie"}


# Alias dla kompatybilności wstecznej (działa cicho pod maską)
@app.post("/register", include_in_schema=False)
def register_alias(user: UserAuth, request: Request):
    return rejestracja(user, request)


@app.post(
    "/logowanie",
    tags=["1. Uwierzytelnianie i Rejestracja"],
    summary="Logowanie użytkownika i generowanie tokenu JWT",
    description="Weryfikuje tożsamość. Blokada konta następuje po 3 nieudanych próbach.",
    response_model=TokenOdpowiedz,
    status_code=status.HTTP_200_OK,
    responses={
        200: {"model": TokenOdpowiedz, "description": "Pomyślne uwierzytelnienie"},
        401: {"model": KomunikatBledu, "description": "Błędne poświadczenia"},
        403: {"model": KomunikatBledu, "description": "Blokada konta po Brute-Force"}
    }
)
def logowanie(user: UserAuth, request: Request):
    ip = request.client.host if request.client else "127.0.0.1"
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM users WHERE username = ?", (user.username,))
    row = cursor.fetchone()

    if not row:
        conn.close()
        log_event(ip, "LOGIN", user.username, "FAILED", "Nieznana nazwa uzytkownika")
        raise HTTPException(status_code=401, detail="Błędny login lub hasło")

    if row["is_locked"]:
        conn.close()
        log_event(ip, "LOGIN", user.username, "DENIED", "Konto jest zablokowane")
        raise HTTPException(status_code=403, detail="Konto zablokowane wskutek zbyt wielu błędnych prób")

    if not verify_password(user.password, row["password_hash"]):
        failed = row["failed_attempts"] + 1
        if failed >= 3:
            cursor.execute("UPDATE users SET failed_attempts = ?, is_locked = 1 WHERE id = ?", (failed, row["id"]))
            conn.commit()
            conn.close()
            log_event(ip, "ACCOUNT_LOCKED", user.username, "TRIGGERED", f"Przekroczono limit nieudanych prob: {failed}")
            raise HTTPException(status_code=403, detail="Konto zablokowane wskutek zbyt wielu błędnych prób")
        else:
            cursor.execute("UPDATE users SET failed_attempts = ? WHERE id = ?", (failed, row["id"]))
            conn.commit()
            conn.close()
            log_event(ip, "LOGIN", user.username, "FAILED", f"Bledne haslo (proba {failed}/3)")
            raise HTTPException(status_code=401, detail="Błędny login lub hasło")

    cursor.execute("UPDATE users SET failed_attempts = 0 WHERE id = ?", (row["id"],))
    conn.commit()
    conn.close()

    token = create_access_token({"sub": row["username"], "role": row["role"]})
    log_event(ip, "LOGIN", user.username, "SUCCESS", f"Udane logowanie (rola={row['role']})")
    return {"access_token": token, "token_type": "bearer"}


# Alias dla kompatybilności wstecznej (dla test_rbac.py)
@app.post("/login", include_in_schema=False)
def login_alias(user: UserAuth, request: Request):
    return logowanie(user, request)


@app.get(
    "/admin/dashboard",
    tags=["2. Kontrola Dostępu (RBAC)"],
    summary="Panel Administratora (Tylko rola admin)",
    description="Endpoint chroniony mechanizmem RBAC. Zwykły użytkownik otrzymuje kod 403 Forbidden.",
    response_model=AdminDashboardOdpowiedz,
    responses={
        200: {"model": AdminDashboardOdpowiedz, "description": "Dostęp przyznany"},
        401: {"model": KomunikatBledu, "description": "Brak lub nieważny token"},
        403: {"model": KomunikatBledu, "description": "Odmowa dostępu (brak uprawnień)"}
    }
)
def admin_dashboard(credentials: HTTPAuthorizationCredentials = Depends(security), request: Request = None):
    ip = request.client.host if request and request.client else "127.0.0.1"
    token = credentials.credentials
    payload = decode_token(token)

    if not payload:
        raise HTTPException(status_code=401, detail="Nieprawidłowy lub wygasły token")

    username = payload.get("sub")
    role = payload.get("role")

    if role != "admin":
        log_event(ip, "RBAC_DENIED", username, "FAILED", f"Brak uprawnien administratora (rola={role})")
        raise HTTPException(status_code=403, detail="Dostęp zabroniony: wymagana rola administratora")

    log_event(ip, "ADMIN_ACCESS", username, "SUCCESS", "Uzyskano dostep administracyjny")
    return {
        "status": "Sukces",
        "komunikat": f"Witaj w panelu administratora, {username}!",
        "poufne_dane": "Raport Zero Trust: 100% sprawności, brak incydentów w sieci."
    }