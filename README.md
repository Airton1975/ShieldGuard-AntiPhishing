# 🛡️ ShieldGuard - Anti-Phishing & Security API

> **Status do Projeto:** Em fase ativa de desenvolvimento e testes. 
> Este sistema faz parte de um projeto acadêmico de Análise e Desenvolvimento de Sistemas (ADS).

## 📝 Sobre o Projeto
O ShieldGuard é uma API robusta desenvolvida em **FastAPI** projetada para proteger usuários contra ataques de phishing. O sistema atua como uma camada de defesa que analisa, em tempo real, URLs suspeitas recebidas por múltiplos canais (como WhatsApp) e conteúdos de e-mails, utilizando uma abordagem de segurança em camadas para identificar ameaças antes que elas causem danos.

---

## 🔍 Fluxo de Análise e Pipeline de Segurança

O ShieldGuard utiliza uma lógica sequencial e integrada para garantir alta precisão na detecção de ameaças:

### 1. Pipeline de Análise de URLs (WhatsApp e Outros Canais)
Independentemente de a URL vir de uma mensagem de WhatsApp ou de outra fonte, o link passa pelo seguinte fluxo rigoroso:
* **Consulta ao VirusTotal:** A URL é enviada imediatamente para a API do VirusTotal, que realiza uma varredura com dezenas de provedores globais de segurança.
* **Fiscalização Heurística:** Caso o VirusTotal retorne limpo (sem acusar ameaças diretas), o sistema ativa uma análise heurística própria, verificando padrões suspeitos na estrutura do link.
* **Consulta Registro.br:** O sistema realiza uma consulta de domínio no Registro.br para validar a legitimidade, data de registro e o histórico daquele endereço web.

### 2. Análise Completa de E-mails
O e-mail recebe um tratamento abrangente que **aplica o mesmo pipeline de tratamento de URL mencionado acima**, somado a uma camada especializada para o corpo da mensagem:
* **Tratamento da URL do E-mail:** Qualquer link encontrado no corpo da mensagem passa exatamente pelo mesmo fluxo de segurança (VirusTotal ➔ Fiscalização Heurística ➔ Registro.br).
* **Análise de Conteúdo (Texto):** O motor do sistema examina o texto do e-mail procurando por itens suspeitos, gatilhos mentais de urgência, termos comuns em golpes de engenharia social e falsificação.
* **Consulta à API do Google:** Validação cruzada com ferramentas e APIs do Google para enriquecer a verificação de autenticidade da mensagem e do remetente.

---

## ⚙️ Tecnologias e Ferramentas
* **Backend:** Python e FastAPI.
* **Processamento:** Gunicorn (servidor de aplicação) e Uvicorn (worker ASGI).
* **Segurança e Consultas:** Integração com APIs externas (VirusTotal, Registro.br, Google).
* **Automação e Raspagem:** Selenium e BeautifulSoup.
* **Hospedagem:** Render (Plataforma Cloud).

---

## 👤 Autor
**Airton Luis Barboza**
* Estudante de Análise e Desenvolvimento de Sistemas (ADS).
* Conecte-se comigo no [GitHub](https://github.com/Airton1975).