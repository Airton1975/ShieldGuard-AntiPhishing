from fastapi import APIRouter, HTTPException
from pydantic import BaseModel
from typing import List, Optional

from services.email_parser import EmailParser
from services.url_analyzer import URLAnalyzer

router = APIRouter(
    prefix="/email",
    tags=["Email Protection"]
)

# Estrutura do Payload esperado na requisição
class EmailAnalysisRequest(BaseModel):
    sender: str
    reply_to: Optional[str] = ""
    html_body: str
    attachments: Optional[List[str]] = []


@router.post("/analyze")
async def analyze_email(payload: EmailAnalysisRequest):
    """
    Endpoint de análise de e-mails:
    1. Extrai remetente, HTML, anexos e links disfarçados via EmailParser.
    2. Roda cada link encontrado no URLAnalyzer (consultando o detector.py e dominio.json).
    """
    try:
        # 1. Extrai dados e links do corpo do e-mail
        parsed_data = EmailParser.parse_email_payload(
            sender=payload.sender,
            reply_to=payload.reply_to,
            html_body=payload.html_body,
            attachments=payload.attachments
        )

        # 2. Analisa cada link extraído contra a base do dominio.json/detector.py
        analyzed_urls = []
        overall_high_risk = False

        for link in parsed_data["links"]:
            actual_url = link["actual_url"]
            
            # Chama o URLAnalyzer (que varre o dominio.json)
            url_analysis = URLAnalyzer.analyze_url(actual_url)
            
            # Se a URL for classificada como suspeita ou houver divergência no link visível
            if url_analysis.get("is_phishing") or link["is_discrepant"]:
                overall_high_risk = True

            analyzed_urls.append({
                "visible_text": link["visible_text"],
                "actual_url": actual_url,
                "is_discrepant": link["is_discrepant"],
                "security_analysis": url_analysis
            })

        # 3. Validações adicionais de risco (anexos perigosos ou discrepância de Reply-To)
        if parsed_data["summary"]["high_risk_attachments_count"] > 0 or parsed_data["sender_info"]["reply_to_mismatch"]:
            overall_high_risk = True

        return {
            "status": "success",
            "is_phishing_suspect": overall_high_risk,
            "risk_level": "HIGH" if overall_high_risk else "LOW",
            "sender_analysis": parsed_data["sender_info"],
            "summary": parsed_data["summary"],
            "links_analysis": analyzed_urls,
            "attachments_analysis": parsed_data["attachments"]
        }

    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Erro ao processar análise do e-mail: {str(e)}")