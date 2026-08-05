import base64
import json
import os
import re
from urllib.parse import urlparse
import httpx


class AntiPhishingDetector:

    def __init__(self, json_path=None):
        self.virustotal_api_key = os.getenv("VIRUSTOTAL_API_KEY", "")

        self.config = {
            "tlds_suspeitos": [],
            "palavras_golpe": [],
            "dominios_oficiais": {},
        }

        # RESOLUÇÃO DE CAMINHO ABSOLUTO (Evita falhas de pasta no Render)
        diretorio_atual = os.path.dirname(os.path.abspath(__file__))
        caminho_absoluto_json = os.path.abspath(
            os.path.join(diretorio_atual, "..", "data", "dominio.json")
        )

        caminhos_busca = [
            caminho_absoluto_json,
            "data/dominio.json",
            "dominio.json",
        ]
        if json_path:
            caminhos_busca.insert(0, json_path)

        for caminho in caminhos_busca:
            if os.path.exists(caminho):
                try:
                    with open(caminho, "r", encoding="utf-8") as f:
                        self.config = json.load(f)
                    print(f"✅ [ShieldGuard] Base de domínios/regras carregada com sucesso de: '{caminho}'")
                    break
                except Exception as e:
                    print(f"⚠️ [ShieldGuard] Erro ao ler JSON em {caminho}: {e}")
            else:
                print(f"🔍 [ShieldGuard] Arquivo não encontrado em: {caminho}")

        self.encurtadores = [
            "bit.ly", "tinyurl.com", "cutt.ly", "is.gd", "t.co", "rebrand.ly"
        ]

        self.termos_financeiros = [
            "pix", "banco", "pagamento", "transferencia", "comprovante",
            "extrato", "fatura", "saldo", "cartao", "credito", "militar", "consignado"
        ]

    def normalizar_texto(self, texto: str) -> str:
        """Remove repetições de letras consecutivos para conter typosquatting."""
        return re.sub(r'(.)\1+', r'\1', texto.lower())

    def consultar_virustotal(self, url: str) -> bool:
        if not self.virustotal_api_key:
            print("⚠️ [VirusTotal] Chave VIRUSTOTAL_API_KEY não encontrada.")
            return False

        print(f"🌐 [VirusTotal] Consultando URL na base global: {url}")

        try:
            url_id = base64.urlsafe_b64encode(url.encode()).decode().strip("=")
            endpoint = f"https://www.virustotal.com/api/v3/urls/{url_id}"
            headers = {
                "x-apikey": self.virustotal_api_key,
                "accept": "application/json",
            }

            response = httpx.get(endpoint, headers=headers, timeout=3.0)
            print(f"📊 [VirusTotal] Status da Resposta: HTTP {response.status_code}")

            if response.status_code == 200:
                data = response.json()
                stats = data.get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
                maliciosos = stats.get("malicious", 0)
                suspeitos = stats.get("suspicious", 0)

                if maliciosos > 0 or suspeitos > 0:
                    return True

            elif response.status_code == 404:
                print("ℹ️ [VirusTotal] URL não catalogada na base global. Seguindo com heurística local.")

        except Exception as e:
            print(f"⚠️ [VirusTotal] Erro/Timeout na consulta: {e}")

        return False

    def extrair_links(self, texto: str):
        regex_url = r"(?:https?://)?(?:[a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}(?:/[^\s]*)?"
        links = re.findall(regex_url, texto)
        
        links_formatados = []
        for l in links:
            if not l.startswith("http://") and not l.startswith("https://"):
                links_formatados.append("https://" + l)
            else:
                links_formatados.append(l)
                
        return links_formatados

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
            # 0. CONSULTA VIRUSTOTAL
            # ---------------------------------------------------------
            if self.consultar_virustotal(link):
                score += 80
                motivos.append("🚨 URL confirmada como maliciosa pela base global do VirusTotal")

            parsed_url = urlparse(link)
            dominio = parsed_url.netloc.lower()
            dominio_normalizado = self.normalizar_texto(dominio)

            # ---------------------------------------------------------
            # A. CHECAGEM DE TLDs SUSPEITOS (.digital, .xyz, etc)
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
                if palavra in dominio or palavra in dominio_normalizado or palavra in texto_lower:
                    score += 20
                    motivos.append(f"Termo suspeito detectado: '{palavra}'")

            # ---------------------------------------------------------
            # C. IMITAÇÃO DE MARCAS
            # ---------------------------------------------------------
            for marca, dominios_validos in self.config.get("dominios_oficiais", {}).items():
                marca_sem_espaco = marca.replace(" ", "")
                marca_norm = self.normalizar_texto(marca_sem_espaco)

                # Verifica se a marca aparece no texto ou no domínio
                if (marca in texto_lower or 
                    marca_sem_espaco in dominio or 
                    marca_norm in dominio_normalizado):
                    
                    e_oficial = any(
                        dominio == d or dominio.endswith("." + d)
                        for d in dominios_validos
                    )
                    if not e_oficial:
                        score += 55
                        motivos.append(f"Tentativa de imitação da marca/instituição '{marca.title()}' em domínio não oficial")
                        break

            # ---------------------------------------------------------
            # D. CONTEXTO FINANCEIRO E TLD SEGURO
            # ---------------------------------------------------------
            tem_contexto_financeiro = any(termo in texto_lower for termo in self.termos_financeiros)
            e_dominio_br = dominio.endswith(".com.br") or dominio.endswith(".gov.br")

            if tem_contexto_financeiro and not e_dominio_br:
                score += 40
                motivos.append("Mensagem com contexto financeiro direcionando para domínio fora do padrão seguro (.com.br/.gov.br)")

            # ---------------------------------------------------------
            # E. ESTRUTURA DA URL
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

            score = min(score, 100)

            if score > maior_score:
                maior_score = score

            resultados_links.append({
                "link": link,
                "score": score,
                "motivos": motivos
            })

        return {
            "status": "ANALISADO",
            "maior_score": maior_score,
            "links_analisados": resultados_links,
        }