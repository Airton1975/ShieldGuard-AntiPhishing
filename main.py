# ==============================================================================
# ShieldGuard - API & Motor Central AntiPhishing
# Copyright (c) 2026 Airton Luis Barboza. Todos os direitos reservados.
# ==============================================================================

import uvicorn
from fastapi import FastAPI
from core.detector import AntiPhishingDetector
from routers import gmail  # Importa o módulo de e-mail
import api as whatsapp_router  # Importa o módulo do WhatsApp

# 1. Instância do servidor FastAPI
app = FastAPI(
    title="ShieldGuard AntiPhishing API",
    description="Motor de Inteligência e Proteção contra Golpes em E-mails, WhatsApp e URLs.",
    version="1.0.0"
)

# 2. Registro dos Routers (Rotas Unificadas da API)
app.include_router(gmail.router)
app.include_router(whatsapp_router.router)  # <--- HABILITA O WHATSAPP NO SERVIDOR CENTRAL!


@app.get("/")
def home():
    """Endpoint de boas-vindas e verificação de status da API."""
    return {
        "status": "online",
        "service": "ShieldGuard AntiPhishing API",
        "author": "Airton Luis Barboza",
        "docs_url": "/docs"
    }


if __name__ == "__main__":
    print("🚀 Iniciando o Servidor ShieldGuard API...")
    uvicorn.run("main:app", host="0.0.0.0", port=8000, reload=True)