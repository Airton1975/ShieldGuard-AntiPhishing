# ==============================================================================
# ShieldGuard - API Webhook para WhatsApp e Antiphishing
# Copyright (c) 2026 Airton Luis Barboza. Todos os direitos reservados.
# ==============================================================================

import os
from dotenv import load_dotenv

# 1. Carrega as variáveis do arquivo .env no início da aplicação
load_dotenv()

import httpx
from fastapi import APIRouter
from core.detector import AntiPhishingDetector

# Define como APIRouter para unificar com o main.py
router = APIRouter(prefix="/whatsapp", tags=["WhatsApp Webhook"])
detector = AntiPhishingDetector()

# ---------------------------------------------------------
# CREDENCIAIS DA Z-API (Lidas com segurança do arquivo .env)
# ---------------------------------------------------------
ZAPI_INSTANCE_ID = os.getenv("ZAPI_INSTANCE_ID", "")
ZAPI_TOKEN = os.getenv("ZAPI_TOKEN", "")
ZAPI_CLIENT_TOKEN = os.getenv("ZAPI_CLIENT_TOKEN", "")


@router.post("/webhook")
async def whatsapp_webhook(payload: dict):
    print("\n📩 Mensagem recebida via Webhook do WhatsApp:", payload)

    # 1. Extração do remetente
    remetente = payload.get("phone") or payload.get("connectedPhone") or ""
    if not remetente and "chatId" in payload:
        remetente = str(payload["chatId"]).split("@")[0]

    # 2. Extração do texto da mensagem
    texto_mensagem = ""

    if isinstance(payload.get("text"), dict):
        texto_mensagem = payload["text"].get("message", "")
    elif isinstance(payload.get("text"), str):
        texto_mensagem = payload["text"]
    elif "message" in payload and isinstance(payload["message"], str):
        texto_mensagem = payload["message"]
    elif "body" in payload and isinstance(payload["body"], str):
        texto_mensagem = payload["body"]

    # Validação de mensagem vazia ou sem remetente
    if not texto_mensagem or not remetente:
        return {"status": "Mensagem vazia ignorada."}

    # 3. EVITA LOOP INFINITO: Ignora mensagens geradas pelo próprio robô
    if "ShieldGuard" in texto_mensagem or "GOLPE DETECTADO" in texto_mensagem:
        return {"status": "Mensagem do próprio ShieldGuard ignorada."}

    # 🛑 TRAVA DEFINITIVA: Se a mensagem NÃO contiver "http" (links), ignora na hora!
    if "http" not in texto_mensagem.lower():
        print("🟢 Ignorado: A mensagem é apenas um texto comum (sem links).")
        return {"status": "Ignorado: sem links na mensagem."}

    # 4. Análise do link no detector
    resultado = detector.analisar_mensagem(texto_mensagem)
    score = resultado.get("maior_score", 0)
    links_analisados = resultado.get("links_analisados", [])

    if not links_analisados or score == 0:
        print("🟢 Ignorado: Nenhum risco/link detectado pelo motor.")
        return {"status": "Ignorado: sem risco."}

    # 5. MONTAGEM DA RESPOSTA COM UX DIRETA (ALERTA NO TOPO + PHISHING)
    if score >= 60:
        resposta_zap = (
            "🚨 *ALERTA: GOLPE DETECTADO!* _(Phishing)_\n"
            f"🔴 *NÍVEL DE PERIGO:* ALTO ({score}/100)\n\n"
            "🛡️ *RECOMENDAÇÃO:* *NÃO CLIQUE NO LINK* e *NÃO ENVIE SEUS DADOS*!\n"
            "___________________________________\n\n"
            "🔍 *Por que esta mensagem é suspeita?*\n"
        )
        for link in links_analisados:
            for motivo in link.get("motivos", []):
                resposta_zap += f"• {motivo}\n"

        resposta_zap += "\n💡 _Bloqueie o remetente e apague a mensagem por segurança._"

    else:
        resposta_zap = (
            "⚠️ *ATENÇÃO: MENSAGEM COM SUSPEITA LEVE*\n"
            f"🟡 *NÍVEL DE PERIGO:* MÉDIO/BAIXO ({score}/100)\n\n"
            "🛡️ *RECOMENDAÇÃO:* Verifique a fonte antes de clicar.\n"
            "___________________________________\n\n"
            "🔍 *Evidências Detectadas:*\n"
        )
        for link in links_analisados:
            for motivo in link.get("motivos", []):
                resposta_zap += f"• {motivo}\n"

    # 6. DISPARO ASSÍNCRONO DA RESPOSTA VIA Z-API
    url_envio = f"https://api.z-api.io/instances/{ZAPI_INSTANCE_ID}/token/{ZAPI_TOKEN}/send-text"

    headers = {
        "Client-Token": ZAPI_CLIENT_TOKEN,
        "Content-Type": "application/json",
    }

    body = {"phone": remetente, "message": resposta_zap}

    try:
        async with httpx.AsyncClient() as client:
            response = await client.post(
                url_envio, json=body, headers=headers, timeout=5.0
            )
            print(f"\n⚡ Status do Envio Z-API: {response.status_code}\n")
    except Exception as e:
        print("Erro ao enviar mensagem via Z-API:", e)

    return {
        "remetente": remetente,
        "diagnostico": resultado.get("status", "ANALISADO"),
        "resposta_whatsapp": resposta_zap,
    }