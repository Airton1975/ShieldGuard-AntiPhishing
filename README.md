<!--
==============================================================================
ShieldGuard - Sistema de Gestão e Proteção Antiphishing
Copyright (c) 2026 Airton Luis Barboza. Todos os direitos reservados.
==============================================================================
-->

# 🛡️ ShieldGuard Anti-Phishing

O **ShieldGuard** é uma API REST desenvolvida em Python (FastAPI) projetada para detectar e analisar tentativas de *phishing* e golpes digitais contidos em mensagens. O sistema é integrado ao **WhatsApp via Webhook (Z-API)** e combina inteligência global de ameaças com verificações locais e consultas oficiais em registros de domínios para classificar o risco de links recebidos.

---

## 🚀 Funcionalidades

* **Integração via Webhook:** Recebe e processa mensagens em tempo real encaminhadas via Z-API no WhatsApp.
* **Filtro de Processamento Inteligente:** Descarta mensagens sem links (`http/https`) e possui travas de segurança para prevenir *loops infinitos* de mensagens geradas pelo próprio sistema.
* **Motor de Análise Multi-Camadas:**
  1. **Base Global (VirusTotal API):** Checa primeiro se a URL já possui relatórios globais de *malware* ou *phishing*.
  2. **Análise Heurística Local:** Caso a URL não seja apontada na base global, o motor verifica typosquatting, imitação de marcas registradas, TLDs de alto risco e contexto financeiro em `data/dominio.json`.
  3. **Validação de Registro Nacional (Registro.br RDAP API):** Para domínios terminados em `.br`, realiza consulta em tempo real para verificar a existência do registro e detectar domínios criados recentemente (menos de 30 dias).
* **Alertas Automáticos:** Envia respostas formatadas diretamente no WhatsApp do remetente detalhando o **Score de Risco (0 a 100)** e todas as **Evidências Detectadas**.

---

## 🔬 Fluxo de Análise da Mensagem

```text
[ Mensagem do WhatsApp ] 
         │
         ▼
[ Webhook (api.py) ] ──(Sem links / Próprio Bot?) ──► [ Ignora ]
         │
         ▼
[ Motor de Detecção (detector.py) ]
         │
         ├── 1º Passo: Consulta API VirusTotal (Ameaça Global)
         │      └─► Se malicioso/suspeito: Aplica pontuação crítica
         │
         ├── 2º Passo: Regras Heurísticas e Padrões (dominio.json)
         │      └─► Valida imitação de marcas, TLDs de risco e termos suspeitos
         │
         └── 3º Passo: Consulta RDAP Registro.br (Apenas domínios .br)
                └─► Checa existência real e data de criação (domínios recentes)
         │
         ▼
[ Disparo de Alerta Z-API ] ──► [ Resposta no WhatsApp ]
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