<?php
/**
 * Sistema de Alertas SIEM
 * 
 * Responsável por enviar notificações sobre eventos críticos de segurança
 * via email, webhook ou outros meios de comunicação
 */

// Previne acesso direto ao arquivo via web
if (php_sapi_name() !== 'cli') {
    $scriptName = basename($_SERVER['SCRIPT_NAME'] ?? $_SERVER['PHP_SELF'] ?? '');
    if ($scriptName === 'siem_alerts.php') {
        http_response_code(403);
        die('Acesso negado');
    }
}

require_once __DIR__ . DIRECTORY_SEPARATOR . 'siem_config.php';
require_once __DIR__ . DIRECTORY_SEPARATOR . 'siem_logger.php';

/**
 * Sistema principal de alertas
 */
class SiemAlerter {
    
    private $logger;
    
    public function __construct() {
        $this->logger = SiemLogger::getInstance();
    }
    
    /**
     * Envia alerta sobre evento de segurança
     */
    public function sendAlert($detection, $eventId = null) {
        $alert = $this->createAlert($detection, $eventId);
        
        // Registra o alerta
        $alertId = $this->logger->logAlert(
            'SECURITY_ALERT',
            $detection['severity'],
            $alert
        );
        
        $sent = false;
        
        // Envia por email se configurado
        if (SiemConfig::get('alert_email_enabled')) {
            $sent = $this->sendEmailAlert($alert) || $sent;
        }
        
        // Envia por webhook se configurado
        $webhookUrl = SiemConfig::get('alert_webhook_url');
        if (!empty($webhookUrl)) {
            $sent = $this->sendWebhookAlert($alert, $webhookUrl) || $sent;
        }
        
        // Se nenhum método funcionou, registra erro
        if (!$sent) {
            error_log("SIEM: Falha ao enviar alerta - ID: {$alertId}");
        }
        
        return $alertId;
    }
    
    /**
     * Cria estrutura do alerta
     */
    private function createAlert($detection, $eventId) {
        $alert = [
            'alert_id' => uniqid('ALERT_', true),
            'event_id' => $eventId,
            'timestamp' => date('Y-m-d H:i:s'),
            'severity' => $detection['severity'],
            'threat_type' => $detection['type'],
            'description' => $this->generateDescription($detection),
            'source_ip' => $this->getSourceIP(),
            'user_agent' => $_SERVER['HTTP_USER_AGENT'] ?? 'unknown',
            'username' => $this->getCurrentUser(),
            'details' => $detection['details'] ?? [],
            'recommendations' => $this->getRecommendations($detection['type'])
        ];
        
        return $alert;
    }
    
    /**
     * Gera descrição amigável do alerta
     */
    private function generateDescription($detection) {
        $type = $detection['type'];
        $details = $detection['details'] ?? [];
        
        switch ($type) {
            case SiemConfig::EVENT_SQL_INJECTION:
                return "Tentativa de SQL Injection detectada no parâmetro '{$details['parameter']}'";
                
            case SiemConfig::EVENT_XSS_ATTEMPT:
                return "Tentativa de Cross-Site Scripting (XSS) detectada no parâmetro '{$details['parameter']}'";
                
            case SiemConfig::EVENT_DIRECTORY_TRAVERSAL:
                return "Tentativa de Directory Traversal detectada no parâmetro '{$details['parameter']}'";
                
            case SiemConfig::EVENT_LOGIN_BRUTE_FORCE:
                return "Tentativa de ataque de força bruta detectada - {$details['failure_count']} falhas em {$details['period']}";
                
            case SiemConfig::EVENT_SUSPICIOUS_IP:
                return "Acesso de IP suspeito detectado: {$details['ip_address']}";
                
            case SiemConfig::EVENT_ANOMALY_DETECTED:
                return $details['description'] ?? 'Anomalia de comportamento detectada';
                
            case SiemConfig::EVENT_MALWARE_DETECTION:
                return "Possível malware detectado: {$details['filename']}";
                
            case SiemConfig::EVENT_DATA_EXFILTRATION:
                return "Possível tentativa de exfiltração de dados detectada";
                
            case 'multiple_users_same_ip':
                return "IP {$details['ip']} tentou logar com {$details['user_count']} usuários diferentes";
                
            case 'high_failure_rate_ip':
                return "IP {$details['ip']} com {$details['failure_rate']}% de falhas em login";
                
            case 'user_multiple_ips':
                return "Usuário {$details['username']} acessou de {$details['ip_count']} IPs diferentes";
                
            case 'high_activity_user':
                return "Usuário {$details['username']} com atividade intensa: {$details['event_count']} eventos";
                
            case 'rapid_logins':
                return "Usuário {$details['username']} com logins muito rápidos (automação suspeita)";
                
            case 'high_after_hours_activity':
                return "Alta atividade fora do horário comercial ({$details['after_hours_rate']}%)";
                
            case 'ip_concentration':
                return "IP {$details['top_ip']} domina {$details['concentration_rate']}% da atividade";
                
            default:
                return "Evento de segurança detectado: {$type}";
        }
    }
    
    /**
     * Gera recomendações baseadas no tipo de ameaça
     */
    private function getRecommendations($threatType) {
        $recommendations = [
            SiemConfig::EVENT_SQL_INJECTION => [
                'Verificar logs de aplicação para identificar vulnerabilidades',
                'Implementar prepared statements em queries SQL',
                'Validar e sanitizar todos os inputs do usuário',
                'Considerar bloquear o IP de origem temporariamente'
            ],
            SiemConfig::EVENT_XSS_ATTEMPT => [
                'Verificar se a aplicação está vulnerável a XSS',
                'Implementar encoding de output adequado',
                'Usar Content Security Policy (CSP)',
                'Validar e sanitizar inputs do usuário'
            ],
            SiemConfig::EVENT_LOGIN_BRUTE_FORCE => [
                'Implementar bloqueio temporário de IP',
                'Usar CAPTCHA após múltiplas tentativas',
                'Implementar rate limiting',
                'Considerar autenticação de dois fatores'
            ],
            SiemConfig::EVENT_SUSPICIOUS_IP => [
                'Bloquear IP no firewall se confirmado como malicioso',
                'Verificar outros acessos deste IP',
                'Monitorar atividades relacionadas',
                'Atualizar listas de IPs maliciosos'
            ],
            'multiple_users_same_ip' => [
                'Investigar se é uso legítimo (NAT, proxy)',
                'Verificar padrões de tentativas de login',
                'Considerar implementar verificação adicional',
                'Monitorar atividades futuras deste IP'
            ],
            'high_activity_user' => [
                'Verificar se o usuário está executando atividades legítimas',
                'Investigar possível comprometimento de conta',
                'Considerar análise de comportamento mais detalhada',
                'Verificar logs de aplicação para atividades específicas'
            ]
        ];
        
        return $recommendations[$threatType] ?? [
            'Investigar o evento detalhadamente',
            'Verificar logs relacionados',
            'Monitorar atividades futuras',
            'Considerar ações preventivas'
        ];
    }
    
    /**
     * Envia alerta por email
     */
    private function sendEmailAlert($alert) {
        $to = SiemConfig::get('alert_email_to');
        $from = SiemConfig::get('alert_email_from');
        
        if (empty($to) || empty($from)) {
            return false;
        }
        
        $subject = $this->getEmailSubject($alert);
        $body = $this->getEmailBody($alert);
        $headers = $this->getEmailHeaders($from);
        
        return mail($to, $subject, $body, $headers);
    }
    
    /**
     * Gera assunto do email
     */
    private function getEmailSubject($alert) {
        $severity = $alert['severity'];
        $threatType = $alert['threat_type'];
        $serverName = $_SERVER['SERVER_NAME'] ?? gethostname();
        
        return "[SIEM {$severity}] {$threatType} - {$serverName}";
    }
    
    /**
     * Gera corpo do email
     */
    private function getEmailBody($alert) {
        $body = "ALERTA DE SEGURANÇA SIEM\n";
        $body .= str_repeat("=", 50) . "\n\n";
        
        $body .= "ID do Alerta: {$alert['alert_id']}\n";
        $body .= "Timestamp: {$alert['timestamp']}\n";
        $body .= "Severidade: {$alert['severity']}\n";
        $body .= "Tipo de Ameaça: {$alert['threat_type']}\n";
        $body .= "Descrição: {$alert['description']}\n\n";
        
        $body .= "DETALHES TÉCNICOS:\n";
        $body .= str_repeat("-", 20) . "\n";
        $body .= "IP de Origem: {$alert['source_ip']}\n";
        $body .= "Usuário: {$alert['username']}\n";
        $body .= "User Agent: {$alert['user_agent']}\n";
        
        if (!empty($alert['details'])) {
            $body .= "\nDETALHES ADICIONAIS:\n";
            $body .= str_repeat("-", 20) . "\n";
            foreach ($alert['details'] as $key => $value) {
                if (is_array($value)) {
                    $value = implode(', ', $value);
                }
                $body .= ucfirst(str_replace('_', ' ', $key)) . ": {$value}\n";
            }
        }
        
        if (!empty($alert['recommendations'])) {
            $body .= "\nRECOMENDAÇÕES:\n";
            $body .= str_repeat("-", 15) . "\n";
            foreach ($alert['recommendations'] as $i => $recommendation) {
                $body .= ($i + 1) . ". {$recommendation}\n";
            }
        }
        
        $body .= "\n" . str_repeat("=", 50) . "\n";
        $body .= "Este é um alerta automático do sistema SIEM.\n";
        $body .= "Para mais detalhes, acesse o dashboard de segurança.\n";
        
        return $body;
    }
    
    /**
     * Gera headers do email
     */
    private function getEmailHeaders($from) {
        $headers = [];
        $headers[] = "From: {$from}";
        $headers[] = "Reply-To: {$from}";
        $headers[] = "Content-Type: text/plain; charset=UTF-8";
        $headers[] = "X-Mailer: SIEM-Alerter/1.0";
        $headers[] = "X-Priority: 1"; // Alta prioridade
        
        return implode("\r\n", $headers);
    }
    
    /**
     * Envia alerta via webhook
     */
    private function sendWebhookAlert($alert, $webhookUrl) {
        $payload = [
            'alert' => $alert,
            'system' => 'SIEM',
            'server' => $_SERVER['SERVER_NAME'] ?? gethostname(),
            'timestamp' => time()
        ];
        
        $jsonPayload = json_encode($payload, JSON_UNESCAPED_UNICODE);
        
        $context = stream_context_create([
            'http' => [
                'method' => 'POST',
                'header' => [
                    'Content-Type: application/json',
                    'User-Agent: SIEM-Alerter/1.0'
                ],
                'content' => $jsonPayload,
                'timeout' => 10
            ]
        ]);
        
        $result = @file_get_contents($webhookUrl, false, $context);
        
        if ($result === false) {
            error_log("SIEM: Falha ao enviar webhook para: {$webhookUrl}");
            return false;
        }
        
        return true;
    }
    
    /**
     * Envia alerta para Slack (formato específico)
     */
    public function sendSlackAlert($alert, $webhookUrl) {
        $color = $this->getSeverityColor($alert['severity']);
        $serverName = $_SERVER['SERVER_NAME'] ?? gethostname();
        
        $payload = [
            'attachments' => [
                [
                    'color' => $color,
                    'title' => "🚨 Alerta de Segurança SIEM",
                    'title_link' => "https://{$serverName}/siem_dashboard.php",
                    'fields' => [
                        [
                            'title' => 'Severidade',
                            'value' => $alert['severity'],
                            'short' => true
                        ],
                        [
                            'title' => 'Tipo de Ameaça',
                            'value' => $alert['threat_type'],
                            'short' => true
                        ],
                        [
                            'title' => 'IP de Origem',
                            'value' => $alert['source_ip'],
                            'short' => true
                        ],
                        [
                            'title' => 'Usuário',
                            'value' => $alert['username'],
                            'short' => true
                        ],
                        [
                            'title' => 'Descrição',
                            'value' => $alert['description'],
                            'short' => false
                        ]
                    ],
                    'footer' => "SIEM Alerter",
                    'ts' => time()
                ]
            ]
        ];
        
        return $this->sendWebhookAlert(['slack_payload' => $payload], $webhookUrl);
    }
    
    /**
     * Obtém cor baseada na severidade
     */
    private function getSeverityColor($severity) {
        switch ($severity) {
            case SiemConfig::SEVERITY_CRITICAL:
                return '#ff0000'; // Vermelho
            case SiemConfig::SEVERITY_HIGH:
                return '#ff8800'; // Laranja
            case SiemConfig::SEVERITY_MEDIUM:
                return '#ffaa00'; // Amarelo
            case SiemConfig::SEVERITY_LOW:
                return '#0088ff'; // Azul
            default:
                return '#888888'; // Cinza
        }
    }
    
    /**
     * Obtém IP de origem
     */
    private function getSourceIP() {
        if (php_sapi_name() === 'cli') {
            return 'CLI';
        }
        
        $headers = ['HTTP_X_FORWARDED_FOR', 'HTTP_X_REAL_IP', 'HTTP_CLIENT_IP', 'REMOTE_ADDR'];
        
        foreach ($headers as $header) {
            if (!empty($_SERVER[$header])) {
                $ips = explode(',', $_SERVER[$header]);
                $ip = trim($ips[0]);
                
                if (filter_var($ip, FILTER_VALIDATE_IP)) {
                    return $ip;
                }
            }
        }
        
        return 'unknown';
    }
    
    /**
     * Obtém usuário atual
     */
    private function getCurrentUser() {
        if (session_status() === PHP_SESSION_ACTIVE) {
            return $_SESSION['usuario'] ?? $_SESSION['username'] ?? 'anonymous';
        }
        
        if (php_sapi_name() === 'cli') {
            return get_current_user() ?: getenv('USERNAME') ?: getenv('USER') ?: 'system';
        }
        
        return 'anonymous';
    }
    
    /**
     * Envia resumo diário de alertas
     */
    public function sendDailySummary() {
        $yesterday = date('Y-m-d', strtotime('-1 day'));
        $today = date('Y-m-d');
        
        $criteria = [
            'start_time' => "{$yesterday} 00:00:00",
            'end_time' => "{$today} 00:00:00"
        ];
        
        $events = $this->logger->searchEvents($criteria);
        
        if (empty($events)) {
            return; // Não envia se não houver eventos
        }
        
        $summary = $this->generateDailySummary($events, $yesterday);
        
        // Envia por email se configurado
        if (SiemConfig::get('alert_email_enabled')) {
            $this->sendDailySummaryEmail($summary, $yesterday);
        }
    }
    
    /**
     * Gera resumo diário
     */
    private function generateDailySummary($events, $date) {
        $summary = [
            'date' => $date,
            'total_events' => count($events),
            'by_severity' => [],
            'by_type' => [],
            'top_ips' => [],
            'top_users' => [],
            'critical_events' => []
        ];
        
        foreach ($events as $event) {
            // Por severidade
            $severity = $event['severity'];
            $summary['by_severity'][$severity] = ($summary['by_severity'][$severity] ?? 0) + 1;
            
            // Por tipo
            $type = $event['event_type'];
            $summary['by_type'][$type] = ($summary['by_type'][$type] ?? 0) + 1;
            
            // IPs
            if ($event['source_ip'] !== 'unknown' && $event['source_ip'] !== 'CLI') {
                $summary['top_ips'][$event['source_ip']] = 
                    ($summary['top_ips'][$event['source_ip']] ?? 0) + 1;
            }
            
            // Usuários
            if ($event['username'] !== 'unknown' && $event['username'] !== 'anonymous') {
                $summary['top_users'][$event['username']] = 
                    ($summary['top_users'][$event['username']] ?? 0) + 1;
            }
            
            // Eventos críticos
            if ($event['severity'] === SiemConfig::SEVERITY_CRITICAL) {
                $summary['critical_events'][] = $event;
            }
        }
        
        // Ordena tops
        arsort($summary['top_ips']);
        arsort($summary['top_users']);
        
        return $summary;
    }
    
    /**
     * Envia email com resumo diário
     */
    private function sendDailySummaryEmail($summary, $date) {
        $to = SiemConfig::get('alert_email_to');
        $from = SiemConfig::get('alert_email_from');
        
        if (empty($to) || empty($from)) {
            return false;
        }
        
        $serverName = $_SERVER['SERVER_NAME'] ?? gethostname();
        $subject = "[SIEM] Resumo Diário de Segurança - {$date} - {$serverName}";
        
        $body = "RESUMO DIÁRIO DE SEGURANÇA SIEM\n";
        $body .= str_repeat("=", 50) . "\n\n";
        $body .= "Data: {$date}\n";
        $body .= "Total de Eventos: {$summary['total_events']}\n\n";
        
        if (!empty($summary['by_severity'])) {
            $body .= "POR SEVERIDADE:\n";
            $body .= str_repeat("-", 15) . "\n";
            foreach ($summary['by_severity'] as $severity => $count) {
                $body .= "• {$severity}: {$count} eventos\n";
            }
            $body .= "\n";
        }
        
        if (!empty($summary['by_type'])) {
            $body .= "POR TIPO DE EVENTO:\n";
            $body .= str_repeat("-", 20) . "\n";
            foreach (array_slice($summary['by_type'], 0, 10, true) as $type => $count) {
                $body .= "• {$type}: {$count} eventos\n";
            }
            $body .= "\n";
        }
        
        if (!empty($summary['top_ips'])) {
            $body .= "TOP IPs:\n";
            $body .= str_repeat("-", 10) . "\n";
            foreach (array_slice($summary['top_ips'], 0, 5, true) as $ip => $count) {
                $body .= "• {$ip}: {$count} eventos\n";
            }
            $body .= "\n";
        }
        
        if (!empty($summary['critical_events'])) {
            $body .= "EVENTOS CRÍTICOS:\n";
            $body .= str_repeat("-", 18) . "\n";
            foreach ($summary['critical_events'] as $event) {
                $body .= "• {$event['timestamp']} - {$event['event_type']}\n";
                $body .= "  IP: {$event['source_ip']}, User: {$event['username']}\n";
            }
        }
        
        $headers = $this->getEmailHeaders($from);
        
        return mail($to, $subject, $body, $headers);
    }
}

/**
 * Funções de conveniência
 */

/**
 * Envia alerta simples
 */
function sendSecurityAlert($threatType, $severity, $details = []) {
    $alerter = new SiemAlerter();
    $detection = [
        'type' => $threatType,
        'severity' => $severity,
        'details' => $details
    ];
    
    return $alerter->sendAlert($detection);
}