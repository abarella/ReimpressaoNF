<?php
/**
 * Sistema Central de Logging SIEM (Security Information and Event Management)
 * 
 * Responsável por capturar, processar e armazenar eventos de segurança
 * de forma estruturada para análise posterior
 */

// Previne acesso direto ao arquivo via web
if (php_sapi_name() !== 'cli') {
    $scriptName = basename($_SERVER['SCRIPT_NAME'] ?? $_SERVER['PHP_SELF'] ?? '');
    if ($scriptName === 'siem_logger.php') {
        http_response_code(403);
        die('Acesso negado');
    }
}

require_once __DIR__ . DIRECTORY_SEPARATOR . 'siem_config.php';

/**
 * Classe principal do SIEM Logger
 */
class SiemLogger {
    
    private static $instance = null;
    private $logDirectory;
    
    /**
     * Singleton pattern
     */
    public static function getInstance() {
        if (self::$instance === null) {
            self::$instance = new self();
        }
        return self::$instance;
    }
    
    private function __construct() {
        $this->logDirectory = SiemConfig::LOG_DIRECTORY;
        $this->ensureLogDirectory();
    }
    
    /**
     * Garante que o diretório de logs existe
     */
    private function ensureLogDirectory() {
        if (!is_dir($this->logDirectory)) {
            if (!mkdir($this->logDirectory, 0755, true)) {
                error_log("SIEM: Não foi possível criar diretório de logs: " . $this->logDirectory);
                return false;
            }
        }
        return true;
    }
    
    /**
     * Registra um evento de segurança
     */
    public function logSecurityEvent($eventType, $severity, $details = []) {
        $event = $this->createEventStructure($eventType, $severity, $details);
        $this->writeToLog(SiemConfig::SECURITY_LOG_FILE, $event);
        
        // Se for um evento crítico, também registra no log principal do SIEM
        if ($severity === SiemConfig::SEVERITY_CRITICAL || $severity === SiemConfig::SEVERITY_HIGH) {
            $this->writeToLog(SiemConfig::SIEM_LOG_FILE, $event);
        }
        
        return $event['event_id'];
    }
    
    /**
     * Registra uma anomalia detectada
     */
    public function logAnomaly($anomalyType, $severity, $details = []) {
        $event = $this->createEventStructure($anomalyType, $severity, $details);
        $event['event_category'] = 'ANOMALY';
        $this->writeToLog(SiemConfig::ANOMALY_LOG_FILE, $event);
        
        return $event['event_id'];
    }
    
    /**
     * Registra um alerta
     */
    public function logAlert($alertType, $severity, $details = []) {
        $event = $this->createEventStructure($alertType, $severity, $details);
        $event['event_category'] = 'ALERT';
        $this->writeToLog(SiemConfig::ALERTS_LOG_FILE, $event);
        
        return $event['event_id'];
    }
    
    /**
     * Cria estrutura padronizada de evento
     */
    private function createEventStructure($eventType, $severity, $details = []) {
        $timestamp = date('Y-m-d H:i:s');
        $eventId = $this->generateEventId();
        
        // Coleta informações do contexto
        $context = $this->collectContextInfo();
        
        $event = [
            'event_id' => $eventId,
            'timestamp' => $timestamp,
            'event_type' => $eventType,
            'severity' => $severity,
            'source_ip' => $context['ip'],
            'user_agent' => $context['user_agent'],
            'username' => $context['username'],
            'session_id' => $context['session_id'],
            'request_uri' => $context['request_uri'],
            'http_method' => $context['http_method'],
            'referer' => $context['referer'],
            'details' => $details
        ];
        
        // Adiciona informações específicas se fornecidas
        if (isset($details['custom_user'])) {
            $event['username'] = $details['custom_user'];
        }
        
        if (isset($details['custom_ip'])) {
            $event['source_ip'] = $details['custom_ip'];
        }
        
        return $event;
    }
    
    /**
     * Gera ID único para o evento
     */
    private function generateEventId() {
        return uniqid('SIEM_', true);
    }
    
    /**
     * Coleta informações do contexto atual
     */
    private function collectContextInfo() {
        $context = [
            'ip' => 'unknown',
            'user_agent' => 'unknown',
            'username' => 'unknown',
            'session_id' => 'unknown',
            'request_uri' => 'unknown',
            'http_method' => 'unknown',
            'referer' => 'unknown'
        ];
        
        // Se executando via CLI
        if (php_sapi_name() === 'cli') {
            $context['ip'] = 'CLI';
            $context['user_agent'] = 'CLI';
            $context['username'] = get_current_user() ?: getenv('USERNAME') ?: getenv('USER') ?: 'system';
            return $context;
        }
        
        // Coleta IP do cliente
        $context['ip'] = $this->getClientIP();
        
        // User Agent
        $context['user_agent'] = $_SERVER['HTTP_USER_AGENT'] ?? 'unknown';
        
        // URI requisitada
        $context['request_uri'] = $_SERVER['REQUEST_URI'] ?? 'unknown';
        
        // Método HTTP
        $context['http_method'] = $_SERVER['REQUEST_METHOD'] ?? 'unknown';
        
        // Referer
        $context['referer'] = $_SERVER['HTTP_REFERER'] ?? 'unknown';
        
        // Session ID
        if (session_status() === PHP_SESSION_ACTIVE) {
            $context['session_id'] = session_id();
            $context['username'] = $_SESSION['usuario'] ?? $_SESSION['username'] ?? 'anonymous';
        }
        
        return $context;
    }
    
    /**
     * Obtém o IP real do cliente
     */
    private function getClientIP() {
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
                
                if (filter_var($ip, FILTER_VALIDATE_IP, 
                    FILTER_FLAG_NO_PRIV_RANGE | FILTER_FLAG_NO_RES_RANGE)) {
                    return $ip;
                }
                
                // Se não for IP público válido, retorna mesmo assim (pode ser rede interna)
                if (filter_var($ip, FILTER_VALIDATE_IP)) {
                    return $ip;
                }
            }
        }
        
        return 'unknown';
    }
    
    /**
     * Escreve evento no arquivo de log
     */
    private function writeToLog($logFile, $event) {
        $filePath = $this->logDirectory . $logFile;
        
        // Formata o evento como JSON estruturado
        $logEntry = json_encode($event, JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES) . "\n";
        
        $result = file_put_contents($filePath, $logEntry, FILE_APPEND | LOCK_EX);
        
        if ($result === false) {
            error_log("SIEM: Erro ao escrever no log: " . $filePath);
            return false;
        }
        
        return true;
    }
    
    /**
     * Busca eventos por critérios
     */
    public function searchEvents($criteria = []) {
        $events = [];
        $logFiles = [
            SiemConfig::SECURITY_LOG_FILE,
            SiemConfig::ANOMALY_LOG_FILE,
            SiemConfig::ALERTS_LOG_FILE
        ];
        
        foreach ($logFiles as $logFile) {
            $filePath = $this->logDirectory . $logFile;
            if (file_exists($filePath)) {
                $fileEvents = $this->parseLogFile($filePath, $criteria);
                $events = array_merge($events, $fileEvents);
            }
        }
        
        // Ordena por timestamp (mais recentes primeiro)
        usort($events, function($a, $b) {
            return strtotime($b['timestamp']) - strtotime($a['timestamp']);
        });
        
        return $events;
    }
    
    /**
     * Parse do arquivo de log com filtros
     */
    private function parseLogFile($filePath, $criteria = []) {
        $events = [];
        $handle = fopen($filePath, 'r');
        
        if (!$handle) {
            return $events;
        }
        
        while (($line = fgets($handle)) !== false) {
            $line = trim($line);
            if (empty($line)) continue;
            
            $event = json_decode($line, true);
            if (!$event) continue;
            
            // Aplica filtros
            if ($this->matchesCriteria($event, $criteria)) {
                $events[] = $event;
            }
        }
        
        fclose($handle);
        return $events;
    }
    
    /**
     * Verifica se o evento atende aos critérios
     */
    private function matchesCriteria($event, $criteria) {
        foreach ($criteria as $field => $value) {
            switch ($field) {
                case 'start_time':
                    if (strtotime($event['timestamp']) < strtotime($value)) {
                        return false;
                    }
                    break;
                    
                case 'end_time':
                    if (strtotime($event['timestamp']) > strtotime($value)) {
                        return false;
                    }
                    break;
                    
                case 'severity':
                    if (is_array($value)) {
                        if (!in_array($event['severity'], $value)) {
                            return false;
                        }
                    } else {
                        if ($event['severity'] !== $value) {
                            return false;
                        }
                    }
                    break;
                    
                case 'event_type':
                    if (is_array($value)) {
                        if (!in_array($event['event_type'], $value)) {
                            return false;
                        }
                    } else {
                        if ($event['event_type'] !== $value) {
                            return false;
                        }
                    }
                    break;
                    
                case 'source_ip':
                    if ($event['source_ip'] !== $value) {
                        return false;
                    }
                    break;
                    
                case 'username':
                    if ($event['username'] !== $value) {
                        return false;
                    }
                    break;
                    
                case 'limit':
                    // Este será tratado após a filtragem
                    break;
            }
        }
        
        return true;
    }
    
    /**
     * Obtém estatísticas dos eventos
     */
    public function getEventStatistics($hours = 24) {
        $startTime = date('Y-m-d H:i:s', strtotime("-{$hours} hours"));
        $criteria = ['start_time' => $startTime];
        
        $events = $this->searchEvents($criteria);
        
        $stats = [
            'total_events' => count($events),
            'by_severity' => [],
            'by_type' => [],
            'by_hour' => [],
            'unique_ips' => [],
            'unique_users' => []
        ];
        
        foreach ($events as $event) {
            // Por severidade
            $severity = $event['severity'];
            $stats['by_severity'][$severity] = ($stats['by_severity'][$severity] ?? 0) + 1;
            
            // Por tipo
            $type = $event['event_type'];
            $stats['by_type'][$type] = ($stats['by_type'][$type] ?? 0) + 1;
            
            // Por hora
            $hour = date('H', strtotime($event['timestamp']));
            $stats['by_hour'][$hour] = ($stats['by_hour'][$hour] ?? 0) + 1;
            
            // IPs únicos
            if ($event['source_ip'] !== 'unknown' && $event['source_ip'] !== 'CLI') {
                $stats['unique_ips'][$event['source_ip']] = 
                    ($stats['unique_ips'][$event['source_ip']] ?? 0) + 1;
            }
            
            // Usuários únicos
            if ($event['username'] !== 'unknown' && $event['username'] !== 'anonymous') {
                $stats['unique_users'][$event['username']] = 
                    ($stats['unique_users'][$event['username']] ?? 0) + 1;
            }
        }
        
        return $stats;
    }
    
    /**
     * Remove logs antigos baseado na configuração de retenção
     */
    public function cleanOldLogs() {
        $retentionDays = SiemConfig::LOG_RETENTION_DAYS;
        $cutoffTime = strtotime("-{$retentionDays} days");
        
        $logFiles = [
            SiemConfig::SECURITY_LOG_FILE,
            SiemConfig::ANOMALY_LOG_FILE,
            SiemConfig::ALERTS_LOG_FILE,
            SiemConfig::SIEM_LOG_FILE
        ];
        
        $cleanedCount = 0;
        
        foreach ($logFiles as $logFile) {
            $filePath = $this->logDirectory . $logFile;
            if (file_exists($filePath)) {
                $cleanedCount += $this->cleanLogFile($filePath, $cutoffTime);
            }
        }
        
        return $cleanedCount;
    }
    
    /**
     * Remove entradas antigas de um arquivo de log específico
     */
    private function cleanLogFile($filePath, $cutoffTime) {
        $tempFile = $filePath . '.tmp';
        $cleanedCount = 0;
        
        $readHandle = fopen($filePath, 'r');
        $writeHandle = fopen($tempFile, 'w');
        
        if (!$readHandle || !$writeHandle) {
            return 0;
        }
        
        while (($line = fgets($readHandle)) !== false) {
            $line = trim($line);
            if (empty($line)) continue;
            
            $event = json_decode($line, true);
            if (!$event) continue;
            
            $eventTime = strtotime($event['timestamp']);
            
            if ($eventTime >= $cutoffTime) {
                fwrite($writeHandle, $line . "\n");
            } else {
                $cleanedCount++;
            }
        }
        
        fclose($readHandle);
        fclose($writeHandle);
        
        // Substitui o arquivo original
        if (rename($tempFile, $filePath)) {
            return $cleanedCount;
        } else {
            unlink($tempFile);
            return 0;
        }
    }
}

/**
 * Funções de conveniência para uso fácil em outras partes do sistema
 */

/**
 * Registra evento de login bem-sucedido
 */
function logLoginSuccess($username, $ip = null) {
    $logger = SiemLogger::getInstance();
    $details = [];
    if ($username) $details['custom_user'] = $username;
    if ($ip) $details['custom_ip'] = $ip;
    
    return $logger->logSecurityEvent(
        SiemConfig::EVENT_LOGIN_SUCCESS,
        SiemConfig::SEVERITY_INFO,
        $details
    );
}

/**
 * Registra evento de falha de login
 */
function logLoginFailure($username, $ip = null, $reason = '') {
    $logger = SiemLogger::getInstance();
    $details = [];
    if ($username) $details['custom_user'] = $username;
    if ($ip) $details['custom_ip'] = $ip;
    if ($reason) $details['failure_reason'] = $reason;
    
    return $logger->logSecurityEvent(
        SiemConfig::EVENT_LOGIN_FAILURE,
        SiemConfig::SEVERITY_WARNING,
        $details
    );
}

/**
 * Registra tentativa de ataque detectada
 */
function logSecurityThreat($threatType, $details = []) {
    $logger = SiemLogger::getInstance();
    
    return $logger->logSecurityEvent(
        $threatType,
        SiemConfig::SEVERITY_CRITICAL,
        $details
    );
}

/**
 * Registra acesso a arquivo sensível
 */
function logFileAccess($filename, $username = null) {
    $logger = SiemLogger::getInstance();
    $details = ['filename' => $filename];
    if ($username) $details['custom_user'] = $username;
    
    return $logger->logSecurityEvent(
        SiemConfig::EVENT_FILE_ACCESS,
        SiemConfig::SEVERITY_INFO,
        $details
    );
}