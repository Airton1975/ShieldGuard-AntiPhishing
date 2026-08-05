import base64
import json
import os
import re
from urllib.parse import urlparse
import httpx

class AntiPhishingDetector:

    def __init__(self, json_path="data/dominios.json"):
        # Busca a chave cadastrada nas variáveis de ambiente
        self.virustotal_api_key = os.getenv("VIRUSTOTAL_API_KEY", "")

        self.config = {
            "tlds_suspeitos": [],
            "palavras_golpe": [],
            "dominios_oficiais": {},
        }

        # Tenta carregar as regras a partir da raiz ou do diretório superior
        caminhos_busca = [json_path, os.path.join("..", json_path), "dominios.json"]
        for caminho in caminhos_busca:
            if os.path.exists(caminho):
                try:
                    with open(caminho, "r", encoding="utf-8") as f:
                        self.config = json.load(f)
                    print(f"✅ Regras carregadas do arquivo '{caminho}'.")
                    break
                except Exception as e:
                    print(f"⚠️ Erro ao ler {caminho}: {e}")

        self.encurtadores = [
            "bit.ly",
            "tinyurl.com",
            "cutt.ly",
            "is.gd",
            "t.co",
            "rebrand.ly",
        ]

        self.termos_financeiros = [
            "pix",
            "banco",
            "pagamento",
            "transferencia",
            "comprovante",
            "extrato",
            "fatura",
            "saldo",
            "cartao",
            "credito",
            "militar",
            "consignado",
        ]

    def consultar_virustotal(self, url: str) -> bool:
        """Consulta a API do VirusTotal para checar a reputação da URL em tempo real."""
        if not self.virustotal_api_key:
            print("⚠️ [VirusTotal] Chave de API não informada.")
            return False

        print(f"🌐 [VirusTotal] Consultando URL na base global: {url}")

        try:
            # Converte a URL para Base64 sem caracteres de preenchimento '='
            url_id = (
                base64.urlsafe_b64encode(url.encode()).decode().strip("=")
            )
            endpoint = f"https://www.virustotal.com/api/v3/urls/{url_id}"

            headers = {
                "x-apikey": self.virustotal_api_key,
                "accept": "application/json",
            }

            response = httpx.get(endpoint, headers=headers, timeout=5.0)

            print(
                f"📊 [VirusTotal] Status da Resposta: HTTP {response.status_code}"
            )

            if response.status_code == 200:
                data = response.json()
                stats = (
                    data.get("data", {})
                    .get("attributes", {})
                    .get("last_analysis_stats", {})
                )

                maliciosos = stats.get("malicious", 0)
                suspeitos = stats.get("suspicious", 0)
                inofensivos = stats.get("harmless", 0)

                print(
                    f"🛡️ [VirusTotal] Motores: {maliciosos} Maliciosos | {suspeitos} Suspeitos | {inofensivos} Inofensivos"
                )

                if maliciosos > 0 or suspeitos > 0:
                    return True

            elif response.status_code == 404:
                print(
                    "ℹ️ [VirusTotal] URL ainda não foi catalogada. Seguindo apenas com regras heurísticas locais."
                )
            else:
                print(
                    f"⚠️ [VirusTotal] Falha na consulta (Status HTTP {response.status_code})."
                )

        except Exception as e:
            print(f"⚠️ [VirusTotal] Erro na requisição HTTP: {e}")

        return False

    def extrair_links(self, texto: str):
        regex_url = r"https?://[^\s]+"
        return re.findall(regex_url, texto)

    def analisar_mensagem(self, texto: str):
        links = self.extrair_links(texto)

        if not links:
            return {
                "status": "SEM_LINKS",
                "maior_score": 0,
                "links_analisados": [],
            }

        resultados_links = []
        maior_score = 0
        texto_lower = texto.lower()

        for link in links:
            score = 0
            motivos = []

            # ---------------------------------------------------------
            # 0. CONSULTA EM TEMPO REAL VIA VIRUSTOTAL
            # ---------------------------------------------------------
            if self.consultar_virustotal(link):
                score += 80
                motivos.append(
                    "🚨 URL confirmada como maliciosa/suspeita pela base global do VirusTotal"
                )

            parsed_url = urlparse(link)
            dominio = parsed_url.netloc.lower()

            # ---------------------------------------------------------
            # A. CHECAGEM DE TLDs SUSPEITOS
            # ---------------------------------------------------------
            for tld in self.config.get("tlds_suspeitos", []):
                if dominio.endswith(tld):
                    score += 35
                    motivos.append(f"Uso de TLD de risco: '{tld}'")
                    break

            # ---------------------------------------------------------
            # B. CHECAGEM DE PALAVRAS DE GOLPE
            # ---------------------------------------------------------
            for palavra in self.config.get("palavras_golpe", []):
                if palavra in dominio or palavra in texto_lower:
                    score += 15
                    motivos.append(f"Termo suspeito detectado: '{palavra}'")

            # ---------------------------------------------------------
            # C. IMITAÇÃO DE MARCAS DO JSON (Subdomínios / Phishing de Marca)
            # ---------------------------------------------------------
            for marca, dominios_validos in self.config.get(
                "dominios_oficiais", {}
            ).items():
                if marca in texto_lower or marca in dominio:
                    e_oficial = any(
                        dominio == d or dominio.endswith("." + d)
                        for d in dominios_validos
                    )
                    if not e_oficial:
                        score += 55
                        motivos.append(
                            f"Tentativa de imitação da instituição '{marca.title()}' em domínio não oficial"
                        )
                        break

            # ---------------------------------------------------------
            # D. BLINDAGEM GENÉRICA DE CONTEXTO FINANCEIRO
            # ---------------------------------------------------------
            tem_contexto_financeiro = any(
                termo in texto_lower for termo in self.termos_financeiros
            )
            e_dominio_br = dominio.endswith(".com.br") or dominio.endswith(
                ".gov.br"
            )

            if tem_contexto_financeiro and not e_dominio_br:
                score += 40
                motivos.append(
                    "Mensagem com contexto financeiro direcionando para domínio fora do padrão seguro (.com.br/.gov.br)"
                )

            # ---------------------------------------------------------
            # E. REGRAS DE ESTRUTURA DA URL
            # ---------------------------------------------------------
            if re.search(r"https?://\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}", link):
                score += 65
                motivos.append("Uso de IP direto no link")

            if any(enc in dominio for enc in self.encurtadores):
                score += 30
                motivos.append("Uso de encurtador de link")

            if dominio.count("-") >= 3:
                score += 25
                motivos.append("Domínio com excesso de hífens")

            # Trava o score máximo em 100
            score = min(score, 100)

            if score > maior_score:
                maior_score = score

            resultados_links.append(
                {"link": link, "score": score, "motivos": motivos}
            )

        return {
            "status": "ANALISADO",
            "maior_score": maior_score,
            "links_analisados": resultados_links,
        }


# =====================================================================
# BLOCO DE EXECUÇÃO E TESTE DIRETO NO TERMINAL
# =====================================================================
if __name__ == "__main__":
    detector = AntiPhishingDetector()

    # Teste combinando link falso + VirusTotal
    mensagem_teste = "Acesse: https://mercadolivre.security.com para ver sua promoção!"

    print("\n---------------------------------------------------------")
    print("🚀 INICIANDO TESTE DO SHIELDGUARD + VIRUSTOTAL")
    print("---------------------------------------------------------")

    resultado = detector.analisar_mensagem(mensagem_teste)

    print("\n================ RESULTADO FINAL ================")
    print(f"Status: {resultado['status']}")
    print(f"Maior Score de Risco: {resultado['maior_score']}/100")
    print("\nDetalhes dos links analisados:")

    for item in resultado["links_analisados"]:
        print(f"\n🔗 Link: {item['link']}")
        print(f"   Score: {item['score']}/100")
        print("   Motivos Encontrados:")
        for motivo in item["motivos"]:
            print(f"     • {motivo}")
    print("=========================================================\n")