<?php
/**
 * Middleware de Segurança SIEM
 * 
 * Sistema de interceptação de requisições para detecção automática
 * de ameaças e monitoramento de segurança
 * 
 * Para usar: inclua este arquivo no início dos seus scripts PHP
 * require_once 'siem_middleware.php';
 */

// Previne acesso direto ao arquivo via web
if (php_sapi_name() !== 'cli') {
    $scriptName = basename($_SERVER['SCRIPT_NAME'] ?? $_SERVER['PHP_SELF'] ?? '');
    if ($scriptName === 'siem_middleware.php') {
        http_response_code(403);
        die('Acesso negado');
    }
}

require_once __DIR__ . DIRECTORY_SEPARATOR . 'siem_config.php';
require_once __DIR__ . DIRECTORY_SEPARATOR . 'siem_logger.php';
require_once __DIR__ . DIRECTORY_SEPARATOR . 'siem_detector.php';
require_once __DIR__ . DIRECTORY_SEPARATOR . 'siem_alerts.php';

/**
 * Classe principal do middleware SIEM
 */
class SiemMiddleware {
    
    private static $initialized = false;
    private static $startTime;
    private static $detector;
    private static $alerter;
    
    /**
     * Inicializa o middleware SIEM
     */
    public static function init() {
        if (self::$initialized) {
            return;
        }
        
        // Só executa se não for CLI
        if (php_sapi_name() === 'cli') {
            return;
        }
        
        self::$startTime = microtime(true);
        self::$detector = new SiemAnomalyDetector();
        self::$alerter = new SiemAlerter();
        self::$detector->setAlerter(self::$alerter);
        
        // Registra handlers
        self::registerHandlers();
        
        // Executa verificações iniciais
        self::performInitialChecks();
        
        self::$initialized = true;
    }
    
    /**
     * Registra handlers de segurança
     */
    private static function registerHandlers() {
        // Handler para shutdown (final da execução)
        register_shutdown_function([__CLASS__, 'onShutdown']);
        
        // Handler para erros fatais
        register_shutdown_function([__CLASS__, 'handleFatalErrors']);
        
        // Handler personalizado para logs de erro
        set_error_handler([__CLASS__, 'errorHandler'], E_ALL);
    }
    
    /**
     * Executa verificações iniciais de segurança
     */
    private static function performInitialChecks() {
        $threats = [];
        
        // Verifica IP malicioso
        $ip = self::getClientIP();
        if (SiemConfig::isMaliciousIP($ip)) {
            $threats[] = [
                'type' => SiemConfig::EVENT_SUSPICIOUS_IP,
                'severity' => SiemConfig::SEVERITY_CRITICAL,
                'details' => [
                    'ip_address' => $ip,
                    'threat_type' => 'known_malicious_ip',
                    'action' => 'blocked'
                ]
            ];
            
            // Bloqueia acesso se for IP malicioso crítico
            self::blockAccess('IP malicioso detectado');
        }
        
        // Verifica User Agent suspeito
        $userAgent = $_SERVER['HTTP_USER_AGENT'] ?? '';
        if (SiemConfig::isSuspiciousUserAgent($userAgent)) {
            $threats[] = [
                'type' => SiemConfig::EVENT_ANOMALY_DETECTED,
                'severity' => SiemConfig::SEVERITY_HIGH,
                'details' => [
                    'anomaly_type' => 'suspicious_user_agent',
                    'user_agent' => $userAgent,
                    'action' => 'monitored'
                ]
            ];
        }
        
        // Verifica padrões de ataque em parâmetros
        $attackPatterns = self::checkForAttackPatterns();
        $threats = array_merge($threats, $attackPatterns);
        
        // Verifica rate limiting
        $rateLimitThreat = self::checkRateLimit();
        if ($rateLimitThreat) {
            $threats[] = $rateLimitThreat;
        }
        
        // Processa ameaças detectadas
        foreach ($threats as $threat) {
            self::processThreat($threat);
        }
    }
    
    /**
     * Verifica padrões de ataque nos parâmetros
     */
    private static function checkForAttackPatterns() {
        $threats = [];
        $allInputs = array_merge($_GET, $_POST, $_COOKIE);
        
        foreach ($allInputs as $param => $value) {
            if (!is_string($value)) continue;
            
            // SQL Injection
            if (SiemConfig::isSuspiciousPattern($value, 'sql_injection')) {
                $threats[] = [
                    'type' => SiemConfig::EVENT_SQL_INJECTION,
                    'severity' => SiemConfig::SEVERITY_CRITICAL,
                    'details' => [
                        'parameter' => $param,
                        'attack_vector' => 'sql_injection',
                        'payload' => substr($value, 0, 200),
                        'action' => 'blocked'
                    ]
                ];
                
                // Bloqueia tentativas de SQL injection
                self::blockAccess('Tentativa de SQL Injection detectada');
            }
            
            // XSS
            if (SiemConfig::isSuspiciousPattern($value, 'xss')) {
                $threats[] = [
                    'type' => SiemConfig::EVENT_XSS_ATTEMPT,
                    'severity' => SiemConfig::SEVERITY_HIGH,
                    'details' => [
                        'parameter' => $param,
                        'attack_vector' => 'xss',
                        'payload' => substr($value, 0, 200),
                        'action' => 'monitored'
                    ]
                ];
            }
            
            // Directory Traversal
            if (SiemConfig::isSuspiciousPattern($value, 'directory_traversal')) {
                $threats[] = [
                    'type' => SiemConfig::EVENT_DIRECTORY_TRAVERSAL,
                    'severity' => SiemConfig::SEVERITY_HIGH,
                    'details' => [
                        'parameter' => $param,
                        'attack_vector' => 'directory_traversal',
                        'payload' => substr($value, 0, 200),
                        'action' => 'blocked'
                    ]
                ];
                
                // Bloqueia tentativas de directory traversal
                self::blockAccess('Tentativa de Directory Traversal detectada');
            }
            
            // File Inclusion
            if (SiemConfig::isSuspiciousPattern($value, 'file_inclusion')) {
                $threats[] = [
                    'type' => SiemConfig::EVENT_ANOMALY_DETECTED,
                    'severity' => SiemConfig::SEVERITY_HIGH,
                    'details' => [
                        'parameter' => $param,
                        'attack_vector' => 'file_inclusion',
                        'payload' => substr($value, 0, 200),
                        'action' => 'blocked'
                    ]
                ];
                
                // Bloqueia tentativas de file inclusion
                self::blockAccess('Tentativa de File Inclusion detectada');
            }
        }
        
        return $threats;
    }
    
    /**
     * Verifica rate limiting
     */
    private static function checkRateLimit() {
        $ip = self::getClientIP();
        $now = time();
        
        // Arquivo temporário para controle de rate limit
        $rateLimitFile = sys_get_temp_dir() . DIRECTORY_SEPARATOR . 'siem_rate_limit_' . md5($ip) . '.json';
        
        // Carrega dados existentes
        $data = [];
        if (file_exists($rateLimitFile)) {
            $content = file_get_contents($rateLimitFile);
            $data = json_decode($content, true) ?: [];
        }
        
        // Remove entradas antigas (mais de 1 hora)
        $data = array_filter($data, function($timestamp) use ($now) {
            return ($now - $timestamp) <= 3600;
        });
        
        // Adiciona requisição atual
        $data[] = $now;
        
        // Salva dados atualizados
        file_put_contents($rateLimitFile, json_encode($data), LOCK_EX);
        
        // Verifica limites
        $requestCount = count($data);
        
        // Mais de 100 requisições por hora é suspeito
        if ($requestCount > 100) {
            return [
                'type' => SiemConfig::EVENT_ANOMALY_DETECTED,
                'severity' => SiemConfig::SEVERITY_HIGH,
                'details' => [
                    'anomaly_type' => 'rate_limit_exceeded',
                    'ip_address' => $ip,
                    'request_count' => $requestCount,
                    'time_window' => '1 hour',
                    'action' => 'rate_limited'
                ]
            ];
        }
        
        return null;
    }
    
    /**
     * Processa uma ameaça detectada
     */
    private static function processThreat($threat) {
        $logger = SiemLogger::getInstance();
        
        // Registra o evento
        $eventId = $logger->logSecurityEvent(
            $threat['type'],
            $threat['severity'],
            $threat['details']
        );
        
        // Envia alerta se for crítico ou alto
        if ($threat['severity'] === SiemConfig::SEVERITY_CRITICAL || 
            $threat['severity'] === SiemConfig::SEVERITY_HIGH) {
            
            self::$alerter->sendAlert($threat, $eventId);
        }
    }
    
    /**
     * Bloqueia acesso e encerra a execução
     */
    private static function blockAccess($reason) {
        $ip = self::getClientIP();
        $userAgent = $_SERVER['HTTP_USER_AGENT'] ?? 'unknown';
        $uri = $_SERVER['REQUEST_URI'] ?? 'unknown';
        
        // Log detalhado do bloqueio
        error_log("SIEM BLOCK: {$reason} | IP: {$ip} | UA: {$userAgent} | URI: {$uri}");
        
        // Registra evento de bloqueio
        $logger = SiemLogger::getInstance();
        $logger->logSecurityEvent(
            'ACCESS_BLOCKED',
            SiemConfig::SEVERITY_CRITICAL,
            [
                'reason' => $reason,
                'ip_address' => $ip,
                'user_agent' => $userAgent,
                'request_uri' => $uri,
                'blocked_at' => date('Y-m-d H:i:s')
            ]
        );
        
        // Resposta HTTP
        http_response_code(403);
        
        // Verifica se é uma requisição AJAX
        $isAjax = !empty($_SERVER['HTTP_X_REQUESTED_WITH']) && 
                  strtolower($_SERVER['HTTP_X_REQUESTED_WITH']) === 'xmlhttprequest';
        
        if ($isAjax) {
            header('Content-Type: application/json');
            die(json_encode([
                'error' => 'Acesso negado por motivos de segurança',
                'code' => 'SIEM_BLOCKED'
            ]));
        } else {
            header('Content-Type: text/html; charset=UTF-8');
            die('
            <!DOCTYPE html>
            <html>
            <head>
                <title>Acesso Negado</title>
                <meta charset="UTF-8">
                <style>
                    body { font-family: Arial, sans-serif; margin: 50px; text-align: center; }
                    .container { max-width: 600px; margin: 0 auto; }
                    .error { color: #dc3545; }
                    .code { background: #f8f9fa; padding: 20px; border-radius: 5px; margin: 20px 0; }
                </style>
            </head>
            <body>
                <div class="container">
                    <h1 class="error">🚫 Acesso Negado</h1>
                    <p>Sua requisição foi bloqueada por motivos de segurança.</p>
                    <div class="code">
                        <strong>Motivo:</strong> ' . htmlspecialchars($reason) . '<br>
                        <strong>Timestamp:</strong> ' . date('Y-m-d H:i:s') . '<br>
                        <strong>ID da Sessão:</strong> ' . substr(md5($ip . time()), 0, 8) . '
                    </div>
                    <p><small>Se você acredita que isso é um erro, entre em contato com o administrador.</small></p>
                </div>
            </body>
            </html>
            ');
        }
    }
    
    /**
     * Handler para shutdown (final da requisição)
     */
    public static function onShutdown() {
        if (!self::$initialized) {
            return;
        }
        
        $endTime = microtime(true);
        $executionTime = $endTime - self::$startTime;
        
        // Se a execução demorou muito (possível DoS)
        if ($executionTime > 30) {
            $logger = SiemLogger::getInstance();
            $logger->logSecurityEvent(
                SiemConfig::EVENT_ANOMALY_DETECTED,
                SiemConfig::SEVERITY_MEDIUM,
                [
                    'anomaly_type' => 'slow_execution',
                    'execution_time' => $executionTime,
                    'threshold' => 30,
                    'possible_cause' => 'DoS attack or resource exhaustion'
                ]
            );
        }
    }
    
    /**
     * Handler para erros fatais
     */
    public static function handleFatalErrors() {
        $error = error_get_last();
        
        if ($error && in_array($error['type'], [E_ERROR, E_PARSE, E_CORE_ERROR, E_CORE_WARNING, E_COMPILE_ERROR, E_COMPILE_WARNING])) {
            
            $logger = SiemLogger::getInstance();
            $logger->logSecurityEvent(
                'FATAL_ERROR',
                SiemConfig::SEVERITY_HIGH,
                [
                    'error_type' => $error['type'],
                    'error_message' => $error['message'],
                    'error_file' => $error['file'],
                    'error_line' => $error['line'],
                    'possible_security_issue' => 'Application error might indicate attack attempt'
                ]
            );
        }
    }
    
    /**
     * Handler personalizado para erros
     */
    public static function errorHandler($severity, $message, $file, $line) {
        // Ignora erros suprimidos com @
        if (!(error_reporting() & $severity)) {
            return false;
        }
        
        // Log apenas erros que podem indicar problemas de segurança
        $securityRelevantErrors = [
            'file_get_contents',
            'include',
            'require',
            'fopen',
            'mysql_connect',
            'mysqli_connect',
            'eval',
            'exec',
            'system',
            'shell_exec'
        ];
        
        foreach ($securityRelevantErrors as $errorType) {
            if (strpos($message, $errorType) !== false) {
                $logger = SiemLogger::getInstance();
                $logger->logSecurityEvent(
                    'SECURITY_RELEVANT_ERROR',
                    SiemConfig::SEVERITY_MEDIUM,
                    [
                        'error_severity' => $severity,
                        'error_message' => $message,
                        'error_file' => $file,
                        'error_line' => $line,
                        'error_type' => $errorType,
                        'potential_security_risk' => true
                    ]
                );
                break;
            }
        }
        
        // Retorna false para que o handler padrão do PHP também seja executado
        return false;
    }
    
    /**
     * Obtém IP real do cliente
     */
    private static function getClientIP() {
        $headers = [
            'HTTP_X_FORWARDED_FOR',
            'HTTP_X_REAL_IP',
            'HTTP_CLIENT_IP',
            'REMOTE_ADDR'
        ];
        
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
     * Verifica se o arquivo atual deve ser monitorado
     */
    public static function shouldMonitor($filename = null) {
        $filename = $filename ?: basename($_SERVER['SCRIPT_NAME'] ?? '');
        
        // Arquivos que devem ser monitorados
        $monitoredFiles = [
            'login.php',
            'auth.php',
            'reimpressaoNF.php',
            'siem_dashboard.php'
        ];
        
        return in_array($filename, $monitoredFiles);
    }
    
    /**
     * Monitora acesso a arquivo sensível
     */
    public static function monitorFileAccess($filename) {
        $logger = SiemLogger::getInstance();
        $logger->logSecurityEvent(
            SiemConfig::EVENT_FILE_ACCESS,
            SiemConfig::SEVERITY_INFO,
            [
                'filename' => $filename,
                'access_time' => date('Y-m-d H:i:s'),
                'ip_address' => self::getClientIP(),
                'user_agent' => $_SERVER['HTTP_USER_AGENT'] ?? 'unknown'
            ]
        );
    }
}

// Auto-inicialização do middleware se não for CLI
if (php_sapi_name() !== 'cli') {
    SiemMiddleware::init();
    
    // Monitora acesso ao arquivo atual se for relevante
    $currentFile = basename($_SERVER['SCRIPT_NAME'] ?? '');
    if (SiemMiddleware::shouldMonitor($currentFile)) {
        SiemMiddleware::monitorFileAccess($currentFile);
    }
}

/**
 * Funções de conveniência para uso em outros arquivos
 */

/**
 * Registra evento de segurança customizado
 */
function siemLogThreat($threatType, $severity, $details = []) {
    if (class_exists('SiemLogger')) {
        $logger = SiemLogger::getInstance();
        return $logger->logSecurityEvent($threatType, $severity, $details);
    }
    return false;
}

/**
 * Verifica se um IP está na lista de IPs suspeitos
 */
function siemCheckSuspiciousIP($ip) {
    return SiemConfig::isMaliciousIP($ip);
}

/**
 * Adiciona IP à lista de IPs suspeitos (temporário)
 */
function siemAddSuspiciousIP($ip, $reason = '') {
    $logger = SiemLogger::getInstance();
    return $logger->logSecurityEvent(
        SiemConfig::EVENT_SUSPICIOUS_IP,
        SiemConfig::SEVERITY_HIGH,
        [
            'ip_address' => $ip,
            'reason' => $reason,
            'added_by' => 'manual',
            'timestamp' => date('Y-m-d H:i:s')
        ]
    );
}