# 🛡️ ShieldGuard Anti-Phishing

O **ShieldGuard** é uma API REST desenvolvida em Python (FastAPI) projetada para detectar e analisar tentativas de *phishing* e golpes digitais contidos em mensagens. O sistema é integrado ao **WhatsApp via Webhook (Z-API)** e consome inteligência de ameaças para classificar o risco de links recebidos.

---

## 🚀 Funcionalidades

* **Integração via Webhook:** Recebe mensagens de texto e mensagens de grupos do WhatsApp em tempo real.
* **Filtro de Conteúdo:** Ignora mensagens sem links (`http/https`) e previne *loops infinitos* de mensagens enviadas pela própria aplicação.
* **Motor de Detecção:** Analisa links contra listas de domínios conhecidos e consulta APIs de inteligência de ameaças (como VirusTotal).
* **Alertas Automáticos:** Envia respostas formatadas diretamente no WhatsApp do remetente com o **Score de Risco** e as **Evidências Detectadas**.

---

## 🛠️ Tecnologias Utilizadas

* **Python 3.10+**
* **FastAPI** (Framework Web para a API)
* **Uvicorn** (Servidor ASGI)
* **HTTPX** (Cliente HTTP assíncrono para requisições externas)
* **Python-Dotenv** (Gerenciamento de variáveis de ambiente)
* **Z-API** (Integração com WhatsApp)

---

## 📁 Estrutura do Projeto

```text
ShieldGuard-AntiPhishing/
├── core/
│   └── detector.py         # Lógica do motor de análise de Phishing
├── data/
│   └── dominio.json        # Base local de domínios e regras
├── .env                    # Variáveis de ambiente locais (Ignorado no Git)
├── .env.example            # Modelo de variáveis de ambiente
├── .gitignore              # Arquivos ignorados pelo controle de versão
├── api.py                  # Ponto de entrada da API FastAPI / Webhook
├── README.md               # Documentação do projeto
└── requirements.txt        # Dependências do projeto Python