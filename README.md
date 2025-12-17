# Sistema de Reimpressão de Notas Fiscais

Sistema web desenvolvido em PHP para reimpressão de notas fiscais através de impressoras de rede. O sistema integra-se com SQL Server para consulta de dados e Active Directory (LDAP) para autenticação centralizada.

---

## ?? Índice

- [Descrição](#-descrição)
- [Requisitos](#-requisitos)
- [Instalação](#-instalação)
- [Configuração](#-configuração)
- [Estrutura de Arquivos](#-estrutura-de-arquivos)
- [Funcionalidades](#-funcionalidades)
- [Segurança (DevSecOps)](#-segurança-devsecops)
- [Logs e Auditoria](#-logs-e-auditoria)
- [Troubleshooting](#-troubleshooting)
- [Manutenção](#-manutenção)
- [Referências](#-referências)

---

## ?? Descrição

Sistema web desenvolvido em PHP 8.2+ que permite a reimpressão de notas fiscais através de diferentes critérios de busca (número da nota, lote, remessa, etc.) e envio direto para impressoras de rede configuradas.

### Características Principais

- ? Autenticação via Active Directory (LDAP)
- ? Proteção CSRF em todas as requisições
- ? Prepared Statements para prevenção de SQL Injection
- ? Sanitização de output para prevenção de XSS
- ? Logging completo de eventos e segurança
- ? Suporte a múltiplas impressoras de rede
- ? Limpeza automática de arquivos temporários
- ? Interface responsiva e moderna

---

## ?? Requisitos

### Servidor

- **PHP**: 8.2 ou superior
- **Servidor Web**: IIS 10.0+ (com FastCGI) ou Apache 2.4+
- **Banco de Dados**: SQL Server 2012 ou superior
- **Sistema Operacional**: Windows Server 2016+ ou Windows 10+
- **Extensões PHP**:
  - `pdo_sqlsrv` (driver SQL Server)
  - `ldap` (autenticação Active Directory)
  - `mbstring` (manipulação de strings UTF-8)
  - `json` (formatação de respostas)
  - `openssl` (conexões seguras)

### Cliente

- Navegador moderno (Chrome, Firefox, Edge, Safari)
- JavaScript habilitado
- Acesso à rede interna da organização

---

## ?? Instalação

### 1. Download e Extração

```bash
# Clone ou copie os arquivos para o diretório do servidor web
# Exemplo para IIS:
X:\inetpub\wwwroot\Sistemas\ReimpressaoNF\
```

### 2. Configuração de Permissões

#### IIS (Application Pool Identity)

1. Abra o **IIS Manager**
2. Navegue até **Application Pools** ? Selecione o pool do site
3. Clique em **Advanced Settings**
4. Configure:
   - **Identity**: Conta de serviço (ex: `COLIBRIAPP$`)
   - **Load User Profile**: `True`
5. Em **Sites** ? Seu Site ? **Authentication**:
   - **Anonymous Authentication**: Configure para usar "Application pool identity"

#### Permissões de Arquivo

- A conta do Application Pool precisa de:
  - **Modify** na pasta do site
  - **Execute** para executar scripts PHP
  - **Print** nas impressoras de rede configuradas

### 3. Configuração do PHP

Certifique-se de que o PHP está configurado corretamente no IIS:

- FastCGI habilitado
- Handler mapeado para `.php`
- `php.ini` configurado corretamente

---

## ?? Configuração

### 1. Arquivo `.env`

Crie um arquivo `.env` na raiz do projeto com as seguintes variáveis:

```env
# Configurações do Banco de Dados
DB_SERVER=servidor-sql.dominio.local
DB_DATABASE=nome_do_banco
DB_USER=usuario_sql
DB_PASSWORD=senha_sql

# Configurações do Active Directory (Opcional)
AD_SERVER=dc.dominio.local
AD_DOMAIN=DOMINIO
AD_BASE_DN=DC=dominio,DC=local
AD_PORT=389
```

**?? IMPORTANTE**: O arquivo `.env` está protegido contra acesso direto via web. Nunca commite este arquivo no controle de versão.

### 2. Variáveis de Ambiente (Alternativa)

Em vez do arquivo `.env`, você pode configurar variáveis de ambiente do sistema:

```powershell
# Windows PowerShell (como Administrador)
[System.Environment]::SetEnvironmentVariable("DB_SERVER", "servidor-sql.dominio.local", "Machine")
[System.Environment]::SetEnvironmentVariable("DB_DATABASE", "nome_do_banco", "Machine")
[System.Environment]::SetEnvironmentVariable("DB_USER", "usuario_sql", "Machine")
[System.Environment]::SetEnvironmentVariable("DB_PASSWORD", "senha_sql", "Machine")
```

### 3. Configuração de Impressoras

Edite o arquivo `reimpressaoNF.php` e configure o array `$IMPRESSORAS`:

```php
$IMPRESSORAS = [
    'PDF' => '\\\\10.0.22.51\\pdf_entrada',
    'Impressora ENTRADA' => '\\\\10.0.22.51\\ENTRADA',
    // Adicione mais impressoras conforme necessário
];
```

### 4. Configuração do IIS (`web.config`)

O arquivo `web.config` já está configurado com:
- Handler para PHP via FastCGI
- Documento padrão (`reimpressaoNF.php`)
- Configurações de segurança

**Nota**: Não modifique as seções `<authentication>` e `<fastCgi>` diretamente no `web.config` se estiverem bloqueadas no nível do servidor. Configure via IIS Manager.

---

## ?? Estrutura de Arquivos

```
ReimpressaoNF/
?
??? reimpressaoNF.php          # Arquivo principal da aplicação
??? config.php                 # Configurações do banco de dados
??? auth.php                   # Sistema de autenticação LDAP
??? login.php                  # Página de login
??? log_impressao_helper.php   # Helper para logging em processos batch
??? limpar_arquivos_temporarios.php  # Script de limpeza periódica
??? limpar_arquivos_temporarios.bat  # Wrapper batch para limpeza
??? web.config                 # Configuração IIS
??? .htaccess                  # Proteção Apache (se aplicável)
??? .env                       # Variáveis de ambiente (NÃO COMMITAR)
??? devsecops.md               # Documentação de segurança
??? README.md                  # Este arquivo
?
??? logs/                      # Diretório de logs
    ??? auth.log              # Log de autenticação
    ??? impressao.log         # Log de impressões
```

---

## ?? Funcionalidades

### 1. Busca de Notas Fiscais

O sistema suporta múltiplas formas de busca:

- **Opção 1**: Busca por número da nota fiscal
- **Opção 2**: Busca por número do lote
- **Opção 3**: Busca por número da remessa
- **Opção 4**: Busca por número da nota (tipo CTR)
- **Opção 5**: Busca por número da nota (tipo geral, série 1)
- **Opção 6**: Busca por número da nota (tipo geral, série 2)

### 2. Seleção de Impressora

- Lista de impressoras configuradas
- Envio direto para fila de impressão
- Suporte a impressoras de rede via SMB

### 3. Processamento

- Geração de arquivo `.txt` em formato ANSI (Windows-1252)
- Envio síncrono para impressora
- Limpeza automática de arquivos temporários
- Logging completo de eventos

### 4. Limpeza Automática

- Remoção imediata de arquivos temporários após impressão
- Script de limpeza periódica para arquivos antigos
- Remoção de atributos de somente leitura antes de deletar

---

## ?? Segurança (DevSecOps)

Este sistema implementa práticas rigorosas de segurança seguindo os padrões OWASP Top 10 e CWE Top 25. Consulte o arquivo `devsecops.md` para documentação completa.

### Principais Medidas Implementadas

#### 1. Gestão Segura de Credenciais

- ? Credenciais armazenadas em variáveis de ambiente ou `.env`
- ? Arquivo `.env` protegido contra acesso direto
- ? Validação de configurações obrigatórias

#### 2. Autenticação e Autorização

- ? Autenticação via Active Directory (LDAP)
- ? Sessões seguras (HttpOnly, Secure, SameSite=Strict)
- ? Regeneração periódica de ID de sessão
- ? Timeout de sessão (30 minutos)
- ? Controle de acesso em todas as rotas

#### 3. Proteção CSRF

- ? Tokens CSRF em todas as requisições POST
- ? Validação usando `hash_equals()` (proteção contra timing attacks)
- ? Regeneração automática de tokens (1 hora)
- ? Logging de tentativas bloqueadas

#### 4. Proteção SQL Injection

- ? Uso exclusivo de Prepared Statements (PDO)
- ? Parâmetros vinculados via placeholders
- ? Modo de erro configurado como `PDO::ERRMODE_EXCEPTION`
- ? Nenhuma concatenação de strings SQL

#### 5. Proteção XSS

- ? Sanitização de output com `htmlspecialchars()`
- ? Flags `ENT_QUOTES` para proteger aspas
- ? Encoding UTF-8 explícito
- ? Headers HTTP configurados corretamente

#### 6. Proteção Command Injection

- ? Uso de `escapeshellarg()` em todos os comandos shell
- ? Validação de valores antes de execução
- ? Processos executados com contexto seguro

#### 7. Proteção de Arquivos Sensíveis

- ? `.htaccess` bloqueando acesso direto a `config.php` e `.env`
- ? Validação de acesso direto em código PHP
- ? Prevenção de listagem de diretórios

#### 8. Logging e Auditoria

- ? Log de todas as tentativas de login
- ? Log de eventos de segurança (CSRF, erros LDAP)
- ? Log detalhado de impressões
- ? Arquivos de log protegidos

#### 9. Tratamento Seguro de Erros

- ? Mensagens genéricas para usuários em produção
- ? Detalhes completos apenas em logs
- ? Handlers personalizados para exceções
- ? Stack traces apenas em logs

#### 10. Validação de Entrada

- ? Validação rigorosa de todos os inputs
- ? Validação contra listas permitidas (whitelist)
- ? Sanitização antes de processamento
- ? Validação de tipos de dados

### Checklist de Segurança

- [x] Gestão segura de credenciais
- [x] Autenticação Active Directory (LDAP)
- [x] Proteção CSRF
- [x] Proteção SQL Injection
- [x] Proteção XSS
- [x] Proteção Command Injection
- [x] Sessões seguras
- [x] Logging e auditoria
- [x] Proteção de arquivos sensíveis
- [x] Validação de entrada
- [x] Tratamento seguro de erros
- [x] Encoding UTF-8
- [x] Timeouts configurados

### Melhorias Futuras Recomendadas

- [ ] Implementar rate limiting para login
- [ ] Adicionar CAPTCHA após múltiplas tentativas falhas
- [ ] Implementar 2FA (autenticação de dois fatores)
- [ ] Adicionar headers de segurança HTTP (CSP, HSTS, X-Frame-Options)
- [ ] Implementar rotação de logs
- [ ] Adicionar monitoramento de segurança (SIEM)
- [ ] Implementar testes automatizados de segurança
- [ ] Adicionar análise estática de código (SAST)
- [ ] Implementar varredura de dependências (SCA)

---

## ?? Logs e Auditoria

### Arquivos de Log

#### `logs/auth.log`

Registra todas as tentativas de autenticação:

```
[2025-12-17 15:00:00] Login SUCESSO - Usuario: alberto.barella - IP: 10.0.22.1
[2025-12-17 15:01:00] Login FALHA - Usuario: usuario.invalido - IP: 10.0.22.2 - Erro: Invalid credentials
```

#### `logs/impressao.log`

Registra todos os eventos de impressão:

```
[2025-12-17 15:02:56] IMPRESSAO - Evento: ARQUIVO_CRIADO - Usuario: Alberto Barella Jr - IP: 10.0.22.1 - numero_nota: 907153
[2025-12-17 15:02:56] IMPRESSAO - Evento: SUCESSO_COPY_IMPRESSORA - Usuario: ReimpressaoNF - IP: CLI - numero_nota: 907153 | impressora: PDF
[2025-12-17 15:02:56] IMPRESSAO - Evento: ARQUIVO_REMOVIDO - Usuario: ReimpressaoNF - IP: CLI - numero_nota: 907153 | arquivo: nota_1765994576_6942f05004514.txt
```

### Eventos Registrados

- `ARQUIVO_CRIADO`: Arquivo temporário criado
- `INICIO_ENVIO_IMPRESSORA`: Início do processo de envio
- `SUCESSO_COPY_IMPRESSORA`: Envio bem-sucedido via comando COPY
- `SUCESSO_PHP_COPY`: Envio bem-sucedido via PHP copy()
- `ERRO_COPY_IMPRESSORA`: Erro no envio via COPY
- `ERRO_TODOS_METODOS_FALHARAM`: Todos os métodos de envio falharam
- `ARQUIVO_REMOVIDO`: Arquivo temporário removido
- `LIMPEZA_FALLBACK_TXT`: Limpeza de fallback do arquivo .txt
- `LIMPEZA_FALLBACK_BAT`: Limpeza de fallback do script batch

### Permissões de Log

- Os arquivos de log devem ter permissões de escrita para a conta do Application Pool
- Recomenda-se rotação periódica de logs (ex: diária ou semanal)

---

## ?? Troubleshooting

### Problema: Erro ao conectar ao banco de dados

**Sintomas**: Mensagem "Configurações do banco de dados não encontradas"

**Soluções**:
1. Verifique se o arquivo `.env` existe e está configurado corretamente
2. Verifique se as variáveis de ambiente estão definidas (se usando)
3. Verifique as credenciais do banco de dados
4. Verifique a conectividade de rede com o servidor SQL Server
5. Consulte `logs/auth.log` para detalhes do erro

### Problema: Erro de autenticação LDAP

**Sintomas**: Não consegue fazer login mesmo com credenciais corretas

**Soluções**:
1. Verifique as configurações do Active Directory no `.env`
2. Verifique a conectividade de rede com o servidor LDAP
3. Verifique se o usuário existe no Active Directory
4. Verifique se o formato do DN está correto
5. Consulte `logs/auth.log` para detalhes do erro

### Problema: Arquivos não são enviados para impressora

**Sintomas**: Mensagem de sucesso, mas impressora não recebe arquivo

**Soluções**:
1. Verifique se a conta do Application Pool tem permissão de "Print" na impressora
2. Verifique se o caminho da impressora está correto (formato: `\\servidor\impressora`)
3. Verifique a conectividade de rede com o servidor da impressora
4. Verifique se a impressora está online e funcionando
5. Consulte `logs/impressao.log` para detalhes do erro

### Problema: Arquivos temporários não são removidos

**Sintomas**: Arquivos `nota_*.txt` e `copy_background_*.bat` acumulando na pasta

**Soluções**:
1. Verifique se a conta do Application Pool tem permissão de "Modify" na pasta
2. Execute manualmente `limpar_arquivos_temporarios.bat`
3. Configure uma tarefa agendada para executar a limpeza periódica
4. Verifique se os arquivos não estão marcados como somente leitura
5. Consulte `logs/impressao.log` para eventos de limpeza

### Problema: Erro 500 ao acessar o site

**Sintomas**: HTTP Error 500.19 ou 500.0

**Soluções**:
1. Verifique se o PHP está instalado e configurado corretamente
2. Verifique se o FastCGI está habilitado no IIS
3. Verifique se o handler PHP está mapeado corretamente
4. Verifique se o `web.config` não tem seções bloqueadas
5. Consulte os logs de erro do IIS (Event Viewer)

### Problema: Erro CSRF ao enviar formulário

**Sintomas**: Mensagem "Token CSRF inválido"

**Soluções**:
1. Verifique se as sessões estão funcionando corretamente
2. Verifique se os cookies estão sendo aceitos pelo navegador
3. Limpe o cache do navegador e tente novamente
4. Verifique se não há múltiplas abas do sistema abertas
5. Consulte `logs/auth.log` para tentativas de CSRF bloqueadas

---

## ??? Manutenção

### Limpeza Periódica de Arquivos Temporários

Configure uma tarefa agendada no Windows para executar a limpeza diária:

1. Abra o **Task Scheduler**
2. Crie uma nova tarefa básica
3. Configure:
   - **Nome**: Limpeza Arquivos Temporários ReimpressaoNF
   - **Trigger**: Diariamente às 02:00 AM
   - **Action**: Iniciar programa
   - **Programa**: `C:\Windows\System32\cmd.exe`
   - **Argumentos**: `/c "X:\inetpub\wwwroot\Sistemas\ReimpressaoNF\limpar_arquivos_temporarios.bat"`
   - **Executar como**: Conta do Application Pool ou conta administrativa

### Rotação de Logs

Recomenda-se implementar rotação de logs para evitar crescimento excessivo:

- **auth.log**: Rotacionar diariamente ou quando atingir 10MB
- **impressao.log**: Rotacionar diariamente ou quando atingir 50MB

Exemplo de script PowerShell para rotação:

```powershell
# Rotacionar logs antigos
$logPath = "X:\inetpub\wwwroot\Sistemas\ReimpressaoNF\logs"
$date = Get-Date -Format "yyyyMMdd"
Get-ChildItem "$logPath\*.log" | Where-Object { $_.LastWriteTime -lt (Get-Date).AddDays(-7) } | 
    Rename-Item -NewName { $_.Name -replace '\.log$', "_$date.log" }
```

### Backup

Recomenda-se fazer backup regular de:
- Arquivo `.env` (credenciais)
- Arquivos de log (auditoria)
- Configurações do IIS (`web.config`)

### Atualizações

- Mantenha o PHP atualizado com as últimas versões de segurança
- Monitore vulnerabilidades conhecidas (CVE)
- Aplique patches de segurança do Windows Server
- Revise e atualize dependências regularmente

---

## ?? Referências

### Documentação Técnica

- **PHP**: https://www.php.net/docs.php
- **PDO**: https://www.php.net/manual/pt_BR/book.pdo.php
- **LDAP**: https://www.php.net/manual/pt_BR/book.ldap.php
- **IIS**: https://docs.microsoft.com/pt-br/iis/
- **SQL Server**: https://docs.microsoft.com/pt-br/sql/

### Padrões de Segurança

- **OWASP Top 10**: https://owasp.org/www-project-top-ten/
- **CWE Top 25**: https://cwe.mitre.org/top25/
- **NIST Cybersecurity Framework**: https://www.nist.gov/cyberframework

### Ferramentas Recomendadas

- **PHP Composer**: Gerenciador de dependências PHP
- **PHPUnit**: Framework de testes unitários
- **SonarQube**: Análise estática de código
- **OWASP ZAP**: Scanner de vulnerabilidades web

---

## ?? Suporte

Para questões relacionadas ao sistema:

- **Logs de Segurança**: `logs/auth.log`
- **Logs de Impressão**: `logs/impressao.log`
- **Erros do Sistema**: Logs do PHP (`error_log`)
- **Incidentes de Segurança**: Reportar imediatamente ao time de segurança

---

## ?? Changelog

### Versão 1.0 (Dezembro 2025)

- ? Implementação inicial do sistema
- ? Autenticação via Active Directory (LDAP)
- ? Proteção CSRF completa
- ? Prepared Statements para SQL
- ? Sanitização de output (XSS)
- ? Logging completo de eventos
- ? Limpeza automática de arquivos temporários
- ? Suporte a múltiplas impressoras de rede
- ? Documentação completa de segurança (DevSecOps)

---

## ?? Licença

Este sistema foi desenvolvido para uso interno da organização.

---

## ????? Desenvolvido por

**Alberto Barella Junior**

---

**Última Atualização**: Dezembro 2025  
**Versão**: 1.0  
**Status**: ? Produção

