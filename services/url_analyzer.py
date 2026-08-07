import os
import requests
from urllib.parse import urlparse

# Importa a classe com o nome exato do seu core/detector.py
from core.detector import AntiPhishingDetector


class URLAnalyzer:
    """
    Serviço que estende as análises do core/detector.py, integrando
    consultas ao Registro.br e validações do ShieldGuard.
    """

    @staticmethod
    def check_registro_br(domain: str) -> dict:
        """Consulta pública ao RDAP do Registro.br para verificar domínios .br."""
        if not domain.endswith(".br"):
            return {"status": "SKIPPED", "message": "Domínio não é .br"}

        try:
            url = f"https://rdap.registro.br/domain/{domain}"
            response = requests.get(url, timeout=5)

            if response.status_code == 200:
                data = response.json()
                events = data.get("events", [])
                created_date = next((e["eventDate"] for e in events if e["eventAction"] == "registration"), None)

                return {
                    "status": "SUCCESS",
                    "registered": True,
                    "created_date": created_date
                }
            elif response.status_code == 404:
                return {"status": "WARNING", "registered": False, "message": "Domínio não encontrado no Registro.br"}
            
        except Exception as e:
            return {"status": "ERROR", "message": f"Falha na consulta RDAP: {str(e)}"}

        return {"status": "UNKNOWN"}

    @classmethod
    def analyze_url(cls, url: str) -> dict:
        """
        Executa a análise da URL reaproveitando o AntiPhishingDetector do core
        e enriquecendo com informações do Registro.br.
        """
        parsed = urlparse(url if url.startswith(("http://", "https://")) else f"http://{url}")
        domain = parsed.netloc.lower()

        # 1. Instancia o detector do core e analisa a URL
        try:
            detector_instance = AntiPhishingDetector()
            detector_result = detector_instance.analisar_mensagem(url)
        except Exception as e:
            detector_result = {"status": "ERRO", "motivo": str(e), "maior_score": 0}

        # 2. Checagem no Registro.br (se for .br)
        rdap_result = cls.check_registro_br(domain)

        # 3. Define risco com base no score retornado pelo detector
        score = detector_result.get("maior_score", 0)
        is_phishing = score >= 50

        return {
            "target_url": url,
            "domain": domain,
            "is_phishing": is_phishing,
            "risk_score": "HIGH" if is_phishing else "LOW",
            "detector_analysis": detector_result,
            "registro_br": rdap_result
        }