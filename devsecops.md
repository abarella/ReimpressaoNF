# DevSecOps - Práticas de Segurança Implementadas

## ?? Sumário Executivo

Este documento descreve todas as práticas de segurança (DevSecOps) implementadas no sistema de Reimpressão de Notas Fiscais. O projeto segue os princípios de segurança por design, incorporando controles de segurança em todas as camadas da aplicação.

---

## ?? 1. Gestão Segura de Credenciais

### 1.1 Variáveis de Ambiente
- **Status**: ? IMPLEMENTADO
- **Descrição**: Todas as credenciais sensíveis são carregadas de variáveis de ambiente ou arquivo `.env`
- **Implementação**:
  - Prioriza variáveis de ambiente do sistema (`getenv()`)
  - Fallback para arquivo `.env` quando necessário
  - Suporte para múltiplos formatos (Laravel e formato padrão)
- **Arquivos**: `config.php`, `auth.php`

### 1.2 Proteção do Arquivo .env
- **Status**: ? IMPLEMENTADO
- **Descrição**: Arquivo `.env` protegido contra acesso direto via web
- **Implementação**:
  - Bloqueio via `.htaccess` (`<FilesMatch "^(config\.php|\.env)$">`)
  - Validação de acesso direto em `config.php` e `auth.php`
  - Mensagens genéricas de erro em produção
- **Arquivos**: `.htaccess`, `config.php`

### 1.3 Validação de Configurações
- **Status**: ? IMPLEMENTADO
- **Descrição**: Validação rigorosa de configurações obrigatórias
- **Implementação**:
  - Verificação de valores obrigatórios antes de uso
  - Logs detalhados para debug (apenas em desenvolvimento)
  - Exceções com mensagens genéricas em produção
- **Arquivos**: `config.php`

---

## ?? 2. Autenticação e Autorização

### 2.1 Autenticação Active Directory (LDAP)
- **Status**: ? IMPLEMENTADO
- **Descrição**: Integração com Active Directory via LDAP para autenticação centralizada
- **Implementação**:
  - Conexão LDAP segura com suporte a TLS/SSL
  - Múltiplos formatos de DN para compatibilidade
  - Busca de informações do usuário (displayName, email, grupos)
  - Timeout configurável para conexões LDAP
- **Arquivos**: `auth.php`, `login.php`

### 2.2 Proteção de Sessões
- **Status**: ? IMPLEMENTADO
- **Descrição**: Sessões PHP configuradas com segurança máxima
- **Implementação**:
  - `session.cookie_httponly = 1` (proteção contra XSS)
  - `session.cookie_secure` (configurável para HTTPS)
  - `session.use_strict_mode = 1` (prevenção de session fixation)
  - `session.cookie_samesite = Strict` (proteção CSRF)
  - Regeneração periódica de ID de sessão (a cada 30 minutos)
  - Timeout de sessão configurado (30 minutos)
- **Arquivos**: `auth.php`

### 2.3 Controle de Acesso
- **Status**: ? IMPLEMENTADO
- **Descrição**: Todas as páginas protegidas requerem autenticação
- **Implementação**:
  - Função `requerAutenticacao()` aplicada em todas as rotas
  - Redirecionamento automático para login quando não autenticado
  - Preservação de URL de destino após login
- **Arquivos**: `auth.php`, `reimpressaoNF.php`

---

## ??? 3. Proteção CSRF (Cross-Site Request Forgery)

### 3.1 Geração de Tokens CSRF
- **Status**: ? IMPLEMENTADO
- **Descrição**: Tokens CSRF gerados e validados em todas as requisições POST
- **Implementação**:
  - Tokens gerados com `random_bytes(32)` (64 caracteres hexadecimais)
  - Armazenados na sessão com timestamp
  - Regeneração automática a cada 1 hora
  - Tokens incluídos em todos os formulários e requisições AJAX
- **Arquivos**: `auth.php`, `reimpressaoNF.php`, `login.php`

### 3.2 Validação de Tokens CSRF
- **Status**: ? IMPLEMENTADO
- **Descrição**: Validação rigorosa de tokens usando `hash_equals()` para prevenir timing attacks
- **Implementação**:
  - Função `requerCSRF()` aplicada em todas as ações POST
  - Validação via `hash_equals()` (comparação segura contra timing attacks)
  - Logging de tentativas de CSRF bloqueadas
  - Resposta HTTP 403 para requisições inválidas
- **Arquivos**: `auth.php`

---

## ?? 4. Proteção contra SQL Injection

### 4.1 Prepared Statements
- **Status**: ? IMPLEMENTADO
- **Descrição**: Todas as consultas SQL usam prepared statements com PDO
- **Implementação**:
  - Uso exclusivo de `PDO::prepare()` e `execute()`
  - Parâmetros vinculados via placeholders (`?`)
  - Modo de erro configurado como `PDO::ERRMODE_EXCEPTION`
  - Nenhuma concatenação de strings SQL
- **Exemplos**:
  ```php
  $stmt = $pdo->prepare("SELECT no_nota FROM ipenfat..notafis WHERE MV100CHV = ?");
  $stmt->execute([$lote]);
  ```
- **Arquivos**: `reimpressaoNF.php`

### 4.2 Configuração Segura de Conexão
- **Status**: ? IMPLEMENTADO
- **Descrição**: Conexões PDO configuradas com segurança
- **Implementação**:
  - Múltiplas tentativas de conexão com diferentes configurações
  - Timeout reduzido (5 segundos) para evitar esperas longas
  - Suporte a TrustServerCertificate quando necessário
  - Fechamento adequado de conexões após uso
- **Arquivos**: `reimpressaoNF.php`

---

## ?? 5. Proteção contra XSS (Cross-Site Scripting)

### 5.1 Sanitização de Output
- **Status**: ? IMPLEMENTADO
- **Descrição**: Todos os dados de saída são sanitizados com `htmlspecialchars()`
- **Implementação**:
  - Uso de `htmlspecialchars($var, ENT_QUOTES, 'UTF-8')` em todos os outputs HTML
  - Flags `ENT_QUOTES` para proteger aspas simples e duplas
  - Encoding UTF-8 explícito
- **Exemplos**:
  ```php
  echo htmlspecialchars($usuario['displayName'], ENT_QUOTES, 'UTF-8');
  ```
- **Arquivos**: `reimpressaoNF.php`, `login.php`

### 5.2 Headers de Segurança
- **Status**: ? IMPLEMENTADO
- **Descrição**: Headers HTTP configurados corretamente
- **Implementação**:
  - `Content-Type: text/html; charset=UTF-8` em todas as páginas
  - Headers enviados antes de qualquer output
  - Output buffering para garantir ordem correta
- **Arquivos**: `reimpressaoNF.php`, `login.php`, `auth.php`

---

## ? 6. Proteção contra Command Injection

### 6.1 Sanitização de Comandos Shell
- **Status**: ? IMPLEMENTADO
- **Descrição**: Todos os comandos shell usam `escapeshellarg()`
- **Implementação**:
  - Uso de `escapeshellarg()` para todos os parâmetros de comandos
  - Validação de valores antes de execução
  - Processos executados em background com `start /MIN /B`
- **Exemplos**:
  ```php
  $comando_background = "start /MIN /B \"\" " . escapeshellarg($script_batch) . " >nul 2>&1";
  ```
- **Arquivos**: `reimpressaoNF.php`

### 6.2 Validação de Entrada
- **Status**: ? IMPLEMENTADO
- **Descrição**: Validação rigorosa de todos os inputs
- **Implementação**:
  - Validação de opções selecionadas contra lista permitida
  - Validação de impressoras contra array configurado
  - Sanitização de números de nota fiscal
- **Arquivos**: `reimpressaoNF.php`

---

## ?? 7. Proteção de Arquivos Sensíveis

### 7.1 .htaccess
- **Status**: ? IMPLEMENTADO
- **Descrição**: Regras Apache para proteger arquivos sensíveis
- **Implementação**:
  - Bloqueio de acesso direto a `config.php` e `.env`
  - Prevenção de listagem de diretórios (`Options -Indexes`)
  - Bloqueio de arquivos de exemplo
- **Arquivos**: `.htaccess`

### 7.2 Validação de Acesso Direto
- **Status**: ? IMPLEMENTADO
- **Descrição**: Validação em código PHP para prevenir acesso direto
- **Implementação**:
  - Verificação de `php_sapi_name()` para CLI vs Web
  - Validação de nome do script atual
  - Retorno HTTP 403 para acessos diretos
- **Arquivos**: `config.php`, `auth.php`

---

## ?? 8. Logging e Auditoria

### 8.1 Log de Autenticação
- **Status**: ? IMPLEMENTADO
- **Descrição**: Registro de todas as tentativas de login
- **Implementação**:
  - Log de sucessos e falhas de autenticação
  - Registro de IP, timestamp e username
  - Arquivo de log protegido (`logs/auth.log`)
  - Formato: `[YYYY-MM-DD HH:MM:SS] Login SUCESSO/FALHA - Usuário: xxx - IP: xxx`
- **Arquivos**: `auth.php`, `logs/auth.log`

### 8.2 Log de Segurança
- **Status**: ? IMPLEMENTADO
- **Descrição**: Logging de eventos de segurança
- **Implementação**:
  - Tentativas de CSRF bloqueadas
  - Erros de autenticação LDAP
  - Erros de configuração
  - Uso de `error_log()` para logs do PHP
- **Arquivos**: `auth.php`, `config.php`, `reimpressaoNF.php`

### 8.3 Tratamento de Erros
- **Status**: ? IMPLEMENTADO
- **Descrição**: Tratamento seguro de erros sem expor informações sensíveis
- **Implementação**:
  - Mensagens genéricas para usuários em produção
  - Detalhes completos apenas em logs
  - Handlers personalizados para exceções e erros fatais
  - Stack traces apenas em logs
- **Arquivos**: `reimpressaoNF.php`, `config.php`

---

## ? 9. Validação de Entrada

### 9.1 Validação de Dados
- **Status**: ? IMPLEMENTADO
- **Descrição**: Validação rigorosa de todos os inputs do usuário
- **Implementação**:
  - Validação de campos obrigatórios
  - Validação de tipos de dados
  - Validação contra listas permitidas (whitelist)
  - Sanitização antes de processamento
- **Arquivos**: `reimpressaoNF.php`, `login.php`

### 9.2 Validação de Path Traversal
- **Status**: ? MITIGADO
- **Descrição**: Validação de caminhos de arquivos
- **Implementação**:
  - Validação de impressoras contra array configurado
  - Uso de caminhos relativos validados
  - `escapeshellarg()` para comandos shell
- **Arquivos**: `reimpressaoNF.php`

---

## ?? 10. Configurações de Segurança PHP

### 10.1 Configurações de Sessão
- **Status**: ? IMPLEMENTADO
- **Descrição**: Configurações seguras de sessão PHP
- **Implementação**:
  - `session.cookie_httponly = 1`
  - `session.use_strict_mode = 1`
  - `session.cookie_samesite = Strict`
  - Timeout de 30 minutos
  - Regeneração periódica de ID
- **Arquivos**: `auth.php`

### 10.2 Configurações de Erro
- **Status**: ? IMPLEMENTADO
- **Descrição**: Configurações seguras de exibição de erros
- **Implementação**:
  - `display_errors = 0` em produção
  - `log_errors = 1` para logging
  - Handlers personalizados para erros
- **Arquivos**: `reimpressaoNF.php`

---

## ?? 11. Encoding e Internacionalização

### 11.1 UTF-8
- **Status**: ? IMPLEMENTADO
- **Descrição**: Suporte completo a UTF-8 em toda a aplicação
- **Implementação**:
  - `mb_internal_encoding('UTF-8')`
  - `mb_http_output('UTF-8')`
  - Headers HTTP com charset UTF-8
  - Função helper `utf8()` para conversão
  - Validação de encoding em output buffering
- **Arquivos**: `reimpressaoNF.php`, `login.php`, `auth.php`

---

## ?? 12. Timeouts e Performance

### 12.1 Timeouts de Conexão
- **Status**: ? IMPLEMENTADO
- **Descrição**: Timeouts configurados para evitar esperas longas
- **Implementação**:
  - LDAP timeout: 5 segundos
  - SQL Server LoginTimeout: 5 segundos
  - Múltiplas tentativas de conexão com fallback
- **Arquivos**: `auth.php`, `reimpressaoNF.php`

### 12.2 Processamento Assíncrono
- **Status**: ? IMPLEMENTADO
- **Descrição**: Processamento em background para operações longas
- **Implementação**:
  - `fastcgi_finish_request()` quando disponível
  - `ignore_user_abort(true)` para continuar após desconexão
  - Processos executados em background no Windows
- **Arquivos**: `reimpressaoNF.php`

---

## ?? 13. Checklist de Segurança

### ? Implementado
- [x] Gestão segura de credenciais (variáveis de ambiente)
- [x] Autenticação Active Directory (LDAP)
- [x] Proteção CSRF (tokens e validação)
- [x] Proteção SQL Injection (prepared statements)
- [x] Proteção XSS (htmlspecialchars)
- [x] Proteção Command Injection (escapeshellarg)
- [x] Sessões seguras (HttpOnly, Secure, SameSite)
- [x] Logging e auditoria
- [x] Proteção de arquivos sensíveis (.htaccess)
- [x] Validação de entrada
- [x] Tratamento seguro de erros
- [x] Encoding UTF-8
- [x] Timeouts configurados

### ?? Melhorias Futuras Recomendadas
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

## ?? 14. Análise de Vulnerabilidades

### Vulnerabilidades Críticas Resolvidas
1. ? **Credenciais Hardcoded** - Migrado para variáveis de ambiente
2. ? **Falta de Autenticação** - Implementado Active Directory
3. ? **SQL Injection** - Uso exclusivo de prepared statements
4. ? **XSS** - Sanitização completa de output
5. ? **CSRF** - Tokens CSRF em todas as requisições POST
6. ? **Session Fixation** - Regeneração de ID de sessão
7. ? **Command Injection** - Uso de escapeshellarg

### Vulnerabilidades Mitigadas
1. ?? **Path Traversal** - Validação contra whitelist
2. ?? **Exposição de Informações** - Mensagens genéricas em produção
3. ?? **Validação Insuficiente** - Validação implementada, pode ser expandida

---

## ?? 15. Referências e Padrões

### Padrões Seguidos
- **OWASP Top 10** - Proteção contra principais vulnerabilidades web
- **CWE Top 25** - Prevenção de erros comuns de programação
- **PCI DSS** - Boas práticas de segurança de dados
- **NIST Cybersecurity Framework** - Estrutura de segurança

### Ferramentas e Tecnologias
- **PHP 8.2+** - Versão moderna com melhorias de segurança
- **PDO** - Camada de abstração de banco de dados
- **LDAP** - Protocolo seguro para autenticação
- **Apache .htaccess** - Proteção de arquivos sensíveis

---

## ?? 16. Manutenção e Atualização

### Responsabilidades
- **Desenvolvedores**: Implementar novas funcionalidades seguindo padrões de segurança
- **DevOps**: Manter infraestrutura segura e atualizada
- **Segurança**: Revisar código e realizar testes de penetração periódicos

### Processo de Atualização
1. Revisar vulnerabilidades conhecidas
2. Atualizar dependências regularmente
3. Aplicar patches de segurança
4. Testar em ambiente de desenvolvimento
5. Deploy em produção com monitoramento

---

## ?? 17. Contato e Suporte

Para questões relacionadas à segurança deste projeto:
- **Logs de Segurança**: `logs/auth.log`
- **Erros do Sistema**: Logs do PHP (`error_log`)
- **Incidentes de Segurança**: Reportar imediatamente ao time de segurança

---

## ????? 18. Créditos

**Desenvolvido por**: Alberto Barella Junior

---

**Última Atualização**: Dezembro 2025  
**Versão do Documento**: 1.0  
**Status Geral**: ? Seguro para Produção

