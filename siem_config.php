<?php
/**
 * Configurações do Sistema SIEM (Security Information and Event Management)
 * 
 * Define configurações centrais para monitoramento de segurança,
 * detecção de anomalias e geração de alertas
 */

// Previne acesso direto ao arquivo via web
if (php_sapi_name() !== 'cli') {
    $scriptName = basename($_SERVER['SCRIPT_NAME'] ?? $_SERVER['PHP_SELF'] ?? '');
    if ($scriptName === 'siem_config.php') {
        http_response_code(403);
        die('Acesso negado');
    }
}

/**
 * Configurações do Sistema SIEM
 */
class SiemConfig {
    
    // Configurações de Log
    const LOG_DIRECTORY = __DIR__ . DIRECTORY_SEPARATOR . 'logs' . DIRECTORY_SEPARATOR;
    const SIEM_LOG_FILE = 'siem_events.log';
    const SECURITY_LOG_FILE = 'security_events.log';
    const ANOMALY_LOG_FILE = 'anomalies.log';
    const ALERTS_LOG_FILE = 'alerts.log';
    
    // Configurações de Alertas
    const ALERT_EMAIL_ENABLED = false; // Desabilitado por padrão
    const ALERT_EMAIL_TO = 'admin@empresa.com';
    const ALERT_EMAIL_FROM = 'siem@empresa.com';
    const ALERT_WEBHOOK_URL = ''; // URL para webhook (Slack, Teams, etc.)
    
    // Configurações de Detecção de Anomalias
    const MAX_LOGIN_FAILURES_PER_MINUTE = 5;
    const MAX_LOGIN_FAILURES_PER_HOUR = 20;
    const MAX_LOGIN_FAILURES_PER_DAY = 50;
    const SUSPICIOUS_IP_THRESHOLD = 10; // Falhas por IP
    
    // Configurações de Retenção de Dados
    const LOG_RETENTION_DAYS = 90;
    const ALERT_RETENTION_DAYS = 365;
    
    // Configurações de Níveis de Severidade
    const SEVERITY_INFO = 'INFO';
    const SEVERITY_WARNING = 'WARNING';
    const SEVERITY_CRITICAL = 'CRITICAL';
    const SEVERITY_HIGH = 'HIGH';
    const SEVERITY_MEDIUM = 'MEDIUM';
    const SEVERITY_LOW = 'LOW';
    
    // Tipos de Eventos de Segurança
    const EVENT_LOGIN_SUCCESS = 'LOGIN_SUCCESS';
    const EVENT_LOGIN_FAILURE = 'LOGIN_FAILURE';
    const EVENT_LOGIN_BRUTE_FORCE = 'LOGIN_BRUTE_FORCE';
    const EVENT_SUSPICIOUS_IP = 'SUSPICIOUS_IP';
    const EVENT_SESSION_HIJACK = 'SESSION_HIJACK';
    const EVENT_FILE_ACCESS = 'FILE_ACCESS';
    const EVENT_SQL_INJECTION = 'SQL_INJECTION';
    const EVENT_XSS_ATTEMPT = 'XSS_ATTEMPT';
    const EVENT_CSRF_ATTEMPT = 'CSRF_ATTEMPT';
    const EVENT_DIRECTORY_TRAVERSAL = 'DIRECTORY_TRAVERSAL';
    const EVENT_PRIVILEGE_ESCALATION = 'PRIVILEGE_ESCALATION';
    const EVENT_DATA_EXFILTRATION = 'DATA_EXFILTRATION';
    const EVENT_MALWARE_DETECTION = 'MALWARE_DETECTION';
    const EVENT_ANOMALY_DETECTED = 'ANOMALY_DETECTED';
    
    // Configurações de Dashboard
    const DASHBOARD_REFRESH_INTERVAL = 30; // segundos
    const DASHBOARD_MAX_RECENT_EVENTS = 100;
    const DASHBOARD_CHART_HOURS = 24;
    
    // Padrões Suspeitos (Regex)
    public static $suspicious_patterns = [
        'sql_injection' => [
            '/(\bor\b|\band\b)\s*1\s*=\s*1/i',
            '/union\s+select/i',
            '/\bdrop\s+table\b/i',
            '/\binsert\s+into\b/i',
            '/\bupdate\s+.*\bset\b/i',
            '/\bdelete\s+from\b/i',
            '/exec\s*\(/i',
            '/script\s*:/i'
        ],
        'xss' => [
            '/<script[^>]*>/i',
            '/javascript\s*:/i',
            '/on\w+\s*=/i',
            '/<iframe[^>]*>/i',
            '/<object[^>]*>/i',
            '/<embed[^>]*>/i'
        ],
        'directory_traversal' => [
            '/\.\.\//',
            '/\.\.\\\\/',
            '/\.\.\%2f/i',
            '/\.\.\%5c/i'
        ],
        'file_inclusion' => [
            '/php:\/\/input/i',
            '/data:\/\//i',
            '/expect:\/\//i',
            '/file:\/\//i'
        ]
    ];
    
    // IPs suspeitos conhecidos (lista básica - expandir conforme necessário)
    public static $known_malicious_ips = [
        '127.0.0.1', // Exemplo - remover em produção
        // Adicionar IPs maliciosos conhecidos aqui
    ];
    
    // User Agents suspeitos
    public static $suspicious_user_agents = [
        'sqlmap',
        'nikto',
        'nessus',
        'openvas',
        'w3af',
        'burpsuite',
        'havij',
        'pangolin',
        'webscarab'
    ];
    
    /**
     * Retorna configuração específica
     */
    public static function get($key, $default = null) {
        $config = [
            'log_directory' => self::LOG_DIRECTORY,
            'siem_log_file' => self::SIEM_LOG_FILE,
            'security_log_file' => self::SECURITY_LOG_FILE,
            'anomaly_log_file' => self::ANOMALY_LOG_FILE,
            'alerts_log_file' => self::ALERTS_LOG_FILE,
            'alert_email_enabled' => self::ALERT_EMAIL_ENABLED,
            'alert_email_to' => self::ALERT_EMAIL_TO,
            'alert_email_from' => self::ALERT_EMAIL_FROM,
            'alert_webhook_url' => self::ALERT_WEBHOOK_URL,
            'max_login_failures_per_minute' => self::MAX_LOGIN_FAILURES_PER_MINUTE,
            'max_login_failures_per_hour' => self::MAX_LOGIN_FAILURES_PER_HOUR,
            'max_login_failures_per_day' => self::MAX_LOGIN_FAILURES_PER_DAY,
            'suspicious_ip_threshold' => self::SUSPICIOUS_IP_THRESHOLD,
            'log_retention_days' => self::LOG_RETENTION_DAYS,
            'alert_retention_days' => self::ALERT_RETENTION_DAYS,
            'dashboard_refresh_interval' => self::DASHBOARD_REFRESH_INTERVAL,
            'dashboard_max_recent_events' => self::DASHBOARD_MAX_RECENT_EVENTS,
            'dashboard_chart_hours' => self::DASHBOARD_CHART_HOURS
        ];
        
        return isset($config[$key]) ? $config[$key] : $default;
    }
    
    /**
     * Verifica se um padrão é suspeito
     */
    public static function isSuspiciousPattern($input, $type = null) {
        if ($type && isset(self::$suspicious_patterns[$type])) {
            $patterns = self::$suspicious_patterns[$type];
        } else {
            $patterns = [];
            foreach (self::$suspicious_patterns as $category => $categoryPatterns) {
                $patterns = array_merge($patterns, $categoryPatterns);
            }
        }
        
        foreach ($patterns as $pattern) {
            if (preg_match($pattern, $input)) {
                return true;
            }
        }
        
        return false;
    }
    
    /**
     * Verifica se um IP é conhecido como malicioso
     */
    public static function isMaliciousIP($ip) {
        return in_array($ip, self::$known_malicious_ips);
    }
    
    /**
     * Verifica se um User Agent é suspeito
     */
    public static function isSuspiciousUserAgent($userAgent) {
        $userAgent = strtolower($userAgent);
        foreach (self::$suspicious_user_agents as $suspicious) {
            if (strpos($userAgent, $suspicious) !== false) {
                return true;
            }
        }
        return false;
    }
}

/**
 * Classe para validar configurações do SIEM
 */
class SiemConfigValidator {
    
    /**
     * Valida todas as configurações do SIEM
     */
    public static function validate() {
        $errors = [];
        
        // Verifica se o diretório de logs existe e é gravável
        if (!is_dir(SiemConfig::LOG_DIRECTORY)) {
            $errors[] = "Diretório de logs não existe: " . SiemConfig::LOG_DIRECTORY;
        } elseif (!is_writable(SiemConfig::LOG_DIRECTORY)) {
            $errors[] = "Diretório de logs não é gravável: " . SiemConfig::LOG_DIRECTORY;
        }
        
        // Verifica configurações de email se habilitado
        if (SiemConfig::ALERT_EMAIL_ENABLED) {
            if (empty(SiemConfig::ALERT_EMAIL_TO)) {
                $errors[] = "Email de destino para alertas não configurado";
            }
            if (empty(SiemConfig::ALERT_EMAIL_FROM)) {
                $errors[] = "Email de origem para alertas não configurado";
            }
        }
        
        // Verifica configurações de threshold
        if (SiemConfig::MAX_LOGIN_FAILURES_PER_MINUTE <= 0) {
            $errors[] = "Threshold de falhas por minuto deve ser maior que 0";
        }
        
        if (SiemConfig::LOG_RETENTION_DAYS <= 0) {
            $errors[] = "Período de retenção de logs deve ser maior que 0";
        }
        
        return $errors;
    }
}