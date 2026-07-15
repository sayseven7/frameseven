# Pentest Web — Prompt de Missão

Executar um pentest web completo contra um alvo definido. alvo: http://192.168.100.33:42000/#/

---

## 1. Recon + Detecção

- Rodar todos os scanners MCP: `recon`, `crawler`, `content`, `sqli`, `xss`, `lfi`, `ssrf`, `cmdi`, `access`, `misconfig`, `ssti`, `xxe`, `redirect`, `ratelimit`, `ports`, `subdomain`, `bannergrab`.
- Ler a skill correspondente (`skill://hack-skills/v1/*/SKILL.md`) **antes** de cada scan.
- Para cada endpoint, testar manualmente GET, POST, PUT, PATCH, DELETE.
- **Identificar a tecnologia (ASP.NET, PHP, Java, Node, Python, etc) com o recon.**
- **Adaptar a exploração à tecnologia identificada:**
    - **ASP.NET:** extrair `__VIEWSTATE`, `__VIEWSTATEGENERATOR`, `__EVENTVALIDATION` antes de POSTs; inspecionar HTML para nomes reais de inputs.
    - **PHP:** procurar cookies de sessão (PHPSESSID), upload de arquivos, LFI clássico.
    - **Java:** procurar por JSESSIONID, expressions (JSTL/EL), struts/spring specifics.
    - **Node/Express:** procurar cookies de sessão JWT, header injection, SSRF.
    - **Python (Django/Flask):** procurar CSRF tokens em forms, SSTI.
- **Não assumir tecnologia — deixar o recon decidir.**

## 2. Exploração Máxima

Após detectar, explorar **cada** vulnerabilidade até o fim:

### SQL/NoSQL Injection

- **Testar tipos de coluna explicitamente:** tentar INT, VARCHAR, NVARCHAR para cada coluna no UNION — nunca assumir que todas são string.
- **Sempre enumerar `INFORMATION_SCHEMA.TABLES` e `INFORMATION_SCHEMA.COLUMNS`** — jamais chutar nome de tabela.
- Se for NoSQL, adaptar (Mongo `$ne`/`$regex`, etc).
- Fazer login bypass, extração de dados (tabelas, usuários, senhas) e tentar RCE.
- **Após extrair hash de senha, fazer reverse lookup automaticamente** em `md5.gromweb.com` e `crackstation.net`.

### IDOR / Broken Access

- Enumerar todos os recursos.
- Modificar dados de outros usuários.
- Escalar privilégio (ex: customer → admin).

### JWT

- Testar `alg: none`.
- Testar algoritmos fracos (HS256 com chave pública).
- Manipular payload.

### XSS

- Tentar roubo de cookie/sessão, keylogger, screenshot, exfiltração de dados.

### LFI / Path Traversal

- Tentar ler `/etc/passwd`, `/proc/self/environ`, chaves SSH, código fonte.

### SSRF

- Tentar metadata cloud (AWS/GCP/Azure), serviços internos (redis, mysql, k8s API), port scanning interno.

### Command Injection

- Confirmar RCE (`whoami`, `id`, `uname -a`, `ifconfig`).
- Tentar reverse shell ou exfiltração de arquivos.

### SSTI

- Identificar engine (Jinja2, Twig, Freemarker, etc).
- Obter RCE.

### Upload de Arquivo

- Tentar webshell, shell, polyglot images.

### Rate Limit

- Confirmar se endpoints críticos (login, reset senha, API) não têm proteção.

### CORS

- Confirmar se origem refletida permite exfiltração de dados sensíveis.

## 3. Escalação de Privilégio

- Para cada sessão obtida, testar modificação de role/permissões via API.
- Testar *mass assignment* em POST/PUT/PATCH (ex: `"role":"admin"`, `"isAdmin":true`).
- Se encontrar JWT/secrets, forjar tokens de admin.

## 4. Dados Sensíveis

Extrair e registrar todo dado sensível encontrado:

- Credenciais, tokens, chaves API, secrets.
- Dados de usuários (email, hash de senha, perfil).
- Arquivos de configuração (`.env`, `config.js`, `database.yml`).
- Código fonte vazado (stack traces, backup files).
- Informações de infraestrutura (versões, cloud provider, IPs internos).

## 5. PoC — Passo a Passo Replicável (obrigatório)

Cada finding deve conter instruções passo a passo de como replicar o resultado.
Pode usar **curl, python, burp, sqlmap, nmap, ou qualquer ferramenta** — desde que seja claro e reproduzível.

Formato obrigatório:

```
=== Step-by-Step Replication ===

[Step 1] Descrição do passo:
comando/ação

[Step 2] Próximo passo:
comando/ação

[Step N] Verificação:
como confirmar que funcionou
```

- Começar sempre com um request/ação básica e avançar passo a passo.
- Incluir extração de tokens/campos ocultos/CSRF quando necessário.
- Terminar com a verificação do resultado esperado.

## 6. Relatório (MCP — obrigatório via ferramenta, nunca manual)

1. Criar **engagement** com `engagement_open` + target URL.
2. Registrar cada achado com `finding_add` incluindo: título, severidade, CWE, OWASP, CVSS, endpoint, descrição, PoC (passo a passo), evidence, `extracted_data`.
3. Após exploração completa, aprimorar findings com `finding_update` para adicionar PoC detalhado e dados extraídos.
4. Executar **triage** com `auto=true`.
5. Gerar relatório final com `report_engagement format="all"` (gera txt + md + html + pdf).
6. Salvar cada formato em arquivo separado.

---

## Regras

- **Não parar na detecção** — sempre tentar exploração máxima.
- Se houver 2+ caminhos de exploração, tentar todos.
- Se a skill descrever RCE, tentar até conseguir.
- Registrar `extracted_data` (dumps, hashes, tokens, arquivos baixados) em **cada** finding.
- Só marcar como concluído depois de confirmar impacto real.
- **Nunca** gerar relatório manualmente — usar **sempre** `report_engagement via MCP`.