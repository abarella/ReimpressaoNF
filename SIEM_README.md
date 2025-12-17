# Sistema SIEM (Security Information and Event Management)

## Visão Geral

Este sistema SIEM fornece monitoramento de segurança em tempo real, detecção de anomalias e geração de alertas para a aplicação de Reimpressão de Notas Fiscais.

## Componentes do Sistema

### 1. Arquivos Principais

- **`siem_config.php`** - Configurações centrais do sistema SIEM
- **`siem_logger.php`** - Sistema central de logging de eventos de segurança
- **`siem_detector.php`** - Detector inteligente de anomalias e padrões suspeitos
- **`siem_alerts.php`** - Sistema de alertas (email, webhook, etc.)
- **`siem_dashboard.php`** - Interface web para visualização e monitoramento
- **`siem_middleware.php`** - Middleware de interceptação automática de requisições
- **`siem_setup.php`** - Script de instalação e configuração

### 2. Funcionalidades

#### 🔒 Detecção de Ameaças
- **SQL Injection** - Detecta tentativas de injeção SQL
- **Cross-Site Scripting (XSS)** - Identifica tentativas de XSS
- **Directory Traversal** - Bloqueia tentativas de navegação maliciosa
- **Brute Force** - Detecta ataques de força bruta
- **IPs Maliciosos** - Verifica contra listas de IPs conhecidos
- **User Agents Suspeitos** - Identifica ferramentas de hacking

#### 📊 Análise de Anomalias
- **Comportamento de Usuários** - Detecta atividades incomuns por usuário
- **Padrões de Tempo** - Identifica atividade fora do horário normal
- **Concentração de IPs** - Detecta tráfego concentrado de poucos IPs
- **Logins Suspeitos** - Analisa padrões de autenticação anômalos

#### 🚨 Sistema de Alertas
- **Email** - Notificações por email para eventos críticos
- **Webhook** - Integração com sistemas externos (Slack, Teams, etc.)
- **Logs Estruturados** - Registro detalhado em formato JSON
- **Dashboard em Tempo Real** - Visualização web interativa

#### 📈 Dashboard e Relatórios
- **Estatísticas em Tempo Real** - Visão geral da atividade de segurança
- **Gráficos Interativos** - Visualização de eventos por hora, severidade, tipo
- **Lista de Eventos** - Detalhes completos de todos os eventos
- **Análise de Anomalias** - Execução sob demanda de análises

## Instalação

### 1. Execução do Setup

```bash
# Via linha de comando (recomendado)
php siem_setup.php

# Via navegador
http://seudominio/siem_setup.php
```

### 2. Configuração Manual

Se necessário, você pode configurar manualmente:

1. **Diretório de Logs**: Certifique-se que `logs/` é gravável
2. **Permissões**: Configure permissões adequadas (755 para diretórios, 644 para arquivos)
3. **Configurações**: Edite `siem_config.php` conforme necessário

### 3. Integração com a Aplicação

O middleware é automaticamente carregado nos arquivos principais:
- `login.php`
- `reimpressaoNF.php`
- Outros arquivos conforme necessário

Para adicionar em novos arquivos:
```php
// Adicione no início do arquivo PHP
require_once __DIR__ . '/siem_middleware.php';
```

## Configuração

### Alertas por Email

Para habilitar alertas por email, configure:

```php
// Em siem_config.php ou via variáveis de ambiente
const ALERT_EMAIL_ENABLED = true;
const ALERT_EMAIL_TO = 'admin@empresa.com';
const ALERT_EMAIL_FROM = 'siem@empresa.com';
```

### Webhook para Slack/Teams

Configure a URL do webhook:

```php
const ALERT_WEBHOOK_URL = 'https://hooks.slack.com/services/...';
```

### Ajuste de Sensibilidade

Modifique os thresholds em `siem_config.php`:

```php
const MAX_LOGIN_FAILURES_PER_MINUTE = 5;
const MAX_LOGIN_FAILURES_PER_HOUR = 20;
const SUSPICIOUS_IP_THRESHOLD = 10;
```

## Uso

### Dashboard Web

Acesse: `http://seudominio/siem_dashboard.php`

**Funcionalidades:**
- Visão geral de estatísticas de segurança
- Gráficos de eventos por hora e severidade
- Lista de eventos recentes
- Análise de anomalias sob demanda
- Alertas recentes

### Logging Manual

Para registrar eventos customizados:

```php
// Inclua o logger
require_once 'siem_logger.php';

// Registre um evento de segurança
$logger = SiemLogger::getInstance();
$eventId = $logger->logSecurityEvent(
    'CUSTOM_THREAT',
    SiemConfig::SEVERITY_HIGH,
    [
        'description' => 'Atividade suspeita detectada',
        'user_id' => $_SESSION['user_id'],
        'additional_info' => 'dados adicionais'
    ]
);
```

### Verificação de Padrões Suspeitos

```php
// Verifique input do usuário
if (SiemConfig::isSuspiciousPattern($_POST['input'], 'sql_injection')) {
    // Log da tentativa
    siemLogThreat(
        SiemConfig::EVENT_SQL_INJECTION,
        SiemConfig::SEVERITY_CRITICAL,
        ['payload' => $_POST['input']]
    );
    
    // Bloqueia processamento
    die('Entrada suspeita detectada');
}
```

## Arquivos de Log

### Localização
Todos os logs são salvos em: `logs/`

### Tipos de Log

1. **`security_events.log`** - Todos os eventos de segurança
2. **`anomalies.log`** - Anomalias detectadas
3. **`alerts.log`** - Alertas enviados
4. **`siem_events.log`** - Eventos críticos e de alta prioridade
5. **`auth.log`** - Log tradicional de autenticação (compatibilidade)

### Formato dos Logs

Os logs são salvos em formato JSON para facilitar análise:

```json
{
    "event_id": "SIEM_xxxxx",
    "timestamp": "2025-12-17 15:30:45",
    "event_type": "LOGIN_FAILURE",
    "severity": "WARNING",
    "source_ip": "192.168.1.100",
    "user_agent": "Mozilla/5.0...",
    "username": "usuario.teste",
    "session_id": "sess_123456",
    "request_uri": "/login.php",
    "http_method": "POST",
    "referer": "/",
    "details": {
        "failure_reason": "Invalid credentials",
        "attempt_number": 3
    }
}
```

## Manutenção

### Limpeza Automática de Logs

Configure um cron job para limpeza automática:

```bash
# Executa limpeza diariamente às 2h da manhã
0 2 * * * /usr/bin/php /caminho/para/siem_cleanup.php
```

### Limpeza Manual

```php
// Execute via PHP
require_once 'siem_logger.php';
$cleanedCount = SiemLogger::getInstance()->cleanOldLogs();
echo "Removidas {$cleanedCount} entradas antigas";
```

### Monitoramento dos Logs

```bash
# Monitore eventos de segurança em tempo real
tail -f logs/security_events.log | jq .

# Monitore apenas eventos críticos
tail -f logs/security_events.log | jq 'select(.severity == "CRITICAL")'

# Contagem de eventos por tipo nas últimas 24h
tail -n 1000 logs/security_events.log | jq -r .event_type | sort | uniq -c
```

## Troubleshooting

### Problemas Comuns

1. **Logs não são criados**
   - Verifique permissões do diretório `logs/`
   - Certifique-se que o PHP pode escrever no diretório

2. **Dashboard não carrega**
   - Verifique se o usuário está autenticado
   - Confirme que os arquivos SIEM estão no mesmo diretório

3. **Alertas não são enviados**
   - Verifique configuração de email no servidor
   - Teste a URL do webhook manualmente

4. **Performance degradada**
   - Ajuste os thresholds de detecção
   - Considere desabilitar algumas verificações em ambientes de alta carga

### Debug

Ative logs de debug adicionando:

```php
// No início dos arquivos SIEM
error_reporting(E_ALL);
ini_set('display_errors', 1);
ini_set('log_errors', 1);
```

### Verificação de Status

Execute o script de verificação:

```bash
php -r "
require 'siem_config.php';
\$errors = SiemConfigValidator::validate();
if (empty(\$errors)) {
    echo 'Sistema SIEM OK\n';
} else {
    echo 'Erros encontrados:\n';
    foreach (\$errors as \$error) echo '- ' . \$error . '\n';
}
"
```

## Segurança

### Proteção dos Arquivos SIEM

- Todos os arquivos PHP incluem proteção contra acesso direto
- Use HTTPS sempre que possível
- Configure adequadamente as permissões de arquivo
- Mantenha os logs fora do webroot se possível

### Configurações Recomendadas

```apache
# .htaccess para proteger logs (se no webroot)
<Files "*.log">
    Order allow,deny
    Deny from all
</Files>

<Files "siem_*.php">
    <RequireAll>
        Require valid-user
        # Ou configure autenticação específica
    </RequireAll>
</Files>
```

## Expansão do Sistema

### Adicionando Novos Tipos de Ameaças

1. **Defina o novo tipo** em `siem_config.php`:
```php
const EVENT_NEW_THREAT = 'NEW_THREAT';
```

2. **Adicione padrões de detecção** se necessário:
```php
public static $suspicious_patterns = [
    'new_attack' => ['/pattern1/', '/pattern2/']
];
```

3. **Implemente detecção** em `siem_detector.php`

### Integrando com Sistemas Externos

- **SIEM Enterprise**: Configure webhook para enviar events
- **Firewalls**: Use os logs para alimentar regras de bloqueio
- **Monitoramento**: Integre métricas com Prometheus/Grafana

## Suporte

Para questões e suporte:

1. Verifique os logs de erro do PHP
2. Consulte o arquivo `logs/setup_report.txt` gerado durante a instalação
3. Execute o script de verificação de status
4. Revise as configurações em `siem_config.php`

---

**Versão**: 1.0  
**Compatibilidade**: PHP 7.4+  
**Licença**: Uso interno  
**Última atualização**: Dezembro 2025