import re
from urllib.parse import urlparse
from bs4 import BeautifulSoup


class EmailParser:
    """
    Serviço responsável por analisar a estrutura bruta de um e-mail (HTML, cabeçalhos,
    links ocultos e anexos) para extrair evidências de Phishing.
    """

    # Extensões de arquivos de alto risco comumente usadas em anexos maliciosos
    SUSPICIOUS_EXTENSIONS = {
        ".exe", ".bat", ".cmd", ".ps1", ".vbs", ".js", ".jar", 
        ".scr", ".iso", ".img", ".zip", ".rar", ".7z", ".htm", ".html"
    }

    @staticmethod
    def extract_links_from_html(html_content: str) -> list[dict]:
        """
        Varre o corpo HTML do e-mail, extrai todas as tags <a> e identifica
        discrepâncias entre o texto visível e a URL de destino real.
        """
        if not html_content:
            return []

        soup = BeautifulSoup(html_content, "html.parser")
        extracted_links = []

        for anchor in soup.find_all("a", href=True):
            actual_url = anchor["href"].strip()
            visible_text = anchor.get_text(strip=True)

            # Ignora links internos do próprio HTML ou vazios
            if not actual_url or actual_url.startswith("#") or actual_url.startswith("mailto:"):
                continue

            # Checagem Heurística de Discrepância (Mapeamento de Link Oculto)
            # Exemplo: O texto diz "http://banco.com", mas o href aponta para "http://golpe.site"
            is_discrepant = False
            if visible_text.startswith("http://") or visible_text.startswith("https://"):
                visible_domain = urlparse(visible_text).netloc.lower()
                actual_domain = urlparse(actual_url).netloc.lower()

                if visible_domain and actual_domain and visible_domain != actual_domain:
                    is_discrepant = True

            extracted_links.append({
                "visible_text": visible_text,
                "actual_url": actual_url,
                "is_discrepant": is_discrepant,
                "risk_flag": "LINK_DISCREPANCY_DETECTED" if is_discrepant else "NORMAL"
            })

        return extracted_links

    @staticmethod
    def inspect_attachments(attachments_list: list[str]) -> list[dict]:
        """
        Analisa os nomes dos arquivos anexados buscando por extensões perigosas ou
        truques de dupla extensão (ex: fatura.pdf.exe).
        """
        analyzed_attachments = []

        for filename in attachments_list:
            lower_name = filename.lower().strip()
            
            # Detecta dupla extensão (ex: .pdf.exe ou .docx.vbs)
            has_double_extension = len(re.findall(r"\.[a-z0-9]{2,4}", lower_name)) > 1

            # Pega a extensão final
            ext = "." + lower_name.split(".")[-1] if "." in lower_name else ""

            is_suspicious = ext in EmailParser.SUSPICIOUS_EXTENSIONS or has_double_extension

            analyzed_attachments.append({
                "filename": filename,
                "extension": ext,
                "has_double_extension": has_double_extension,
                "is_high_risk": is_suspicious
            })

        return analyzed_attachments

    @classmethod
    def parse_email_payload(cls, sender: str, reply_to: str, html_body: str, attachments: list[str] = None) -> dict:
        """
        Função principal do parser: Compila todas as evidências do e-mail em um relatório estruturado.
        """
        attachments = attachments or []

        # 1. Extrai e analisa os links do HTML
        links_analysis = cls.extract_links_from_html(html_body)

        # 2. Analisa os anexos
        attachments_analysis = cls.inspect_attachments(attachments)

        # 3. Validação de Reply-To incompatível com o Sender (Gatilho clássico de Phishing)
        reply_to_mismatch = False
        if reply_to and sender:
            sender_domain = sender.split("@")[-1].lower() if "@" in sender else ""
            reply_domain = reply_to.split("@")[-1].lower() if "@" in reply_to else ""
            if sender_domain and reply_domain and sender_domain != reply_domain:
                reply_to_mismatch = True

        # Resumo de flags de risco detectadas no e-mail
        discrepant_count = sum(1 for link in links_analysis if link["is_discrepant"])
        high_risk_attachments = sum(1 for att in attachments_analysis if att["is_high_risk"])

        return {
            "sender_info": {
                "sender": sender,
                "reply_to": reply_to,
                "reply_to_mismatch": reply_to_mismatch
            },
            "summary": {
                "total_links_found": len(links_analysis),
                "discrepant_links_count": discrepant_count,
                "total_attachments": len(attachments_analysis),
                "high_risk_attachments_count": high_risk_attachments
            },
            "links": links_analysis,
            "attachments": attachments_analysis
        }