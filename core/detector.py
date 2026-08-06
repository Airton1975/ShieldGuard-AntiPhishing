import base64
from datetime import datetime, timezone
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

        # RESOLUÇÃO DE CAMINHO ABSOLUTO PARA O RENDER
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
                    print(f"✅ [ShieldGuard] Base de regras carregada de: '{caminho}'")
                    break
                except Exception as e:
                    print(f"⚠️ [ShieldGuard] Erro ao ler JSON em {caminho}: {e}")

        self.encurtadores = [
            "bit.ly", "tinyurl.com", "cutt.ly", "is.gd", "t.co", "rebrand.ly"
        ]

        self.termos_financeiros = [
            "pix", "banco", "pagamento", "transferencia", "comprovante",
            "extrato", "fatura", "saldo", "cartao", "credito", "militar", "consignado"
        ]

        self.termos_servicos_nacionais = [
            "pix", "receita", "fgts", "serasa", "detran", "correios", "gov",
            "caixa", "bb", "bradesco", "itau", "santander", "multa", "ipva", "cpf", "inss"
        ]

        # FALLBACK INTERNO DE TERMOS DE SEGURANÇA E ALERTA CRÍTICO
        self.termos_criticos_alerta = [
            "fraude", "golpe", "phishing", "clonado", "fake", "hack",
            "bloqueio", "suporte", "seguranca", "segurança", "atendimento"
        ]

    def normalizar_texto(self, texto: str) -> str:
        """Remove repetições consecutivas de letras para conter typosquatting."""
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

            if response.status_code == 200:
                data = response.json()
                stats = data.get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
                maliciosos = stats.get("malicious", 0)
                suspeitos = stats.get("suspicious", 0)

                if maliciosos > 0 or suspeitos > 0:
                    return True

            elif response.status_code == 404:
                print("ℹ️ [VirusTotal] URL não catalogada na base global.")

        except Exception as e:
            print(f"⚠️ [VirusTotal] Erro/Timeout na consulta: {e}")

        return False

    def consultar_registro_br(self, dominio: str):
        """Consulta a API oficial RDAP do Registro.br para domínios .br."""
        dominio_limpo = re.sub(r'^www\.', '', dominio)
        
        if not dominio_limpo.endswith(".br"):
            return None

        url_rdap = f"https://rdap.registro.br/domain/{dominio_limpo}"
        print(f"🇧🇷 [Registro.br RDAP] Consultando: {dominio_limpo}")

        try:
            response = httpx.get(url_rdap, timeout=3.0)

            if response.status_code == 404:
                return {
                    "existe": False,
                    "motivo": "Domínio .br não está registrado no Registro.br"
                }

            if response.status_code == 200:
                data = response.json()
                events = data.get("events", [])
                data_criacao_str = None

                for event in events:
                    if event.get("eventAction") == "registration":
                        data_criacao_str = event.get("eventDate")
                        break

                dias_existencia = None
                if data_criacao_str:
                    data_criacao = datetime.fromisoformat(data_criacao_str.replace("Z", "+00:00"))
                    agora = datetime.now(timezone.utc)
                    dias_existencia = (agora - data_criacao).days

                return {
                    "existe": True,
                    "dias_existencia": dias_existencia,
                    "handle": data.get("handle")
                }

        except Exception as e:
            print(f"⚠️ [Registro.br RDAP] Falha na consulta: {e}")

        return None

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
            # 0. VIRUSTOTAL
            # ---------------------------------------------------------
            if self.consultar_virustotal(link):
                score += 80
                motivos.append("🚨 URL confirmada como maliciosa pela base global do VirusTotal")

            parsed_url = urlparse(link)
            dominio = parsed_url.netloc.lower()
            dominio_normalizado = self.normalizar_texto(dominio)

            # ---------------------------------------------------------
            # 1. VALIDAÇÃO REGISTRO.BR (RDAP) PARA DOMÍNIOS .BR
            # ---------------------------------------------------------
            dados_registro_br = self.consultar_registro_br(dominio)
            if dados_registro_br:
                if not dados_registro_br["existe"]:
                    score += 70
                    motivos.append("🚨 Domínio .br não existe no banco oficial do Registro.br")
                elif dados_registro_br.get("dias_existencia") is not None:
                    dias = dados_registro_br["dias_existencia"]
                    if dias < 30:
                        score += 50
                        motivos.append(f"⚠️ Domínio registrado recentemente no Brasil (há apenas {dias} dias)")

            # ---------------------------------------------------------
            # 2. ALERTA DE DOMÍNIO NÃO NACIONAL PARA SERVIÇOS DO BRASIL
            # ---------------------------------------------------------
            tem_servico_br = any(t in texto_lower or t in dominio for t in self.termos_servicos_nacionais)
            e_dominio_br = dominio.endswith(".br")

            if tem_servico_br and not e_dominio_br:
                dominios_globais_autorizados = [
                    "shopee.com", "amazon.com", "netflix.com", "paypal.com", "google.com"
                ]
                e_global_autorizado = any(dominio == d or dominio.endswith("." + d) for d in dominios_globais_autorizados)

                if not e_global_autorizado:
                    score += 45
                    motivos.append("⚠️ Serviço/Instituição brasileira direcionando para domínio internacional não oficial (fora do padrão .br/.gov.br)")

            # ---------------------------------------------------------
            # 3. VERIFICAÇÃO DE TERMOS CRÍTICOS (FALLBACK INTERNO)
            # ---------------------------------------------------------
            for termo_critico in self.termos_criticos_alerta:
                if termo_critico in dominio or termo_critico in texto_lower:
                    score += 35
                    motivos.append(f"Termo suspeito/alerta de segurança detectado: '{termo_critico}'")
                    break

            # ---------------------------------------------------------
            # A. TLDs SUSPEITOS (.digital, .xyz, etc)
            # ---------------------------------------------------------
            for tld in self.config.get("tlds_suspeitos", []):
                if dominio.endswith(tld):
                    score += 35
                    motivos.append(f"Uso de TLD de risco: '{tld}'")
                    break

            # ---------------------------------------------------------
            # B. PALAVRAS DE GOLPE DO DOMINIO.JSON
            # ---------------------------------------------------------
            for palavra in self.config.get("palavras_golpe", []):
                if palavra in dominio or palavra in dominio_normalizado or palavra in texto_lower:
                    # Evita duplicar pontuação caso já tenha pego no termo crítico
                    if not any(palavra in m for m in motivos):
                        score += 20
                        motivos.append(f"Termo suspeito detectado: '{palavra}'")

            # ---------------------------------------------------------
            # C. IMITAÇÃO DE MARCAS (Com proteção para marcas curtas <= 3 letras)
            # ---------------------------------------------------------
            for marca, dominios_validos in self.config.get("dominios_oficiais", {}).items():
                marca_sem_espaco = marca.replace(" ", "")
                marca_norm = self.normalizar_texto(marca_sem_espaco)

                if len(marca_sem_espaco) <= 3:
                    # Marca curta (ex: "bb", "c6"): Exige correspondência exata de palavra isolada ou bloco de domínio
                    match_dominio = bool(re.search(r'(^|[\.\-])' + re.escape(marca_sem_espaco) + r'([\.\-]|$)', dominio))
                    match_texto = bool(re.search(r'\b' + re.escape(marca) + r'\b', texto_lower))
                    marca_detectada = match_dominio or match_texto
                else:
                    marca_detectada = (
                        marca in texto_lower or
                        marca_sem_espaco in dominio or
                        marca_norm in dominio_normalizado
                    )

                if marca_detectada:
                    e_oficial = any(
                        dominio == d or dominio.endswith("." + d)
                        for d in dominios_validos
                    )
                    if not e_oficial:
                        score += 55
                        motivos.append(f"Tentativa de imitação da marca/instituição '{marca.title()}' em domínio não oficial")
                        break

            # ---------------------------------------------------------
            # D. CONTEXTO FINANCEIRO E ESTRUTURA
            # ---------------------------------------------------------
            tem_contexto_financeiro = any(termo in texto_lower for termo in self.termos_financeiros)
            if tem_contexto_financeiro and not e_dominio_br:
                score += 30
                motivos.append("Mensagem com contexto financeiro direcionando para domínio fora do padrão seguro nacional")

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