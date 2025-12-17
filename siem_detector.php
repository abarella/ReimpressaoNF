<?php
/**
 * Detector de Anomalias SIEM
 * 
 * Sistema inteligente para detectar padrões suspeitos e anomalias
 * de segurança baseado em análise de comportamento e regras
 */

// Previne acesso direto ao arquivo via web
if (php_sapi_name() !== 'cli') {
    $scriptName = basename($_SERVER['SCRIPT_NAME'] ?? $_SERVER['PHP_SELF'] ?? '');
    if ($scriptName === 'siem_detector.php') {
        http_response_code(403);
        die('Acesso negado');
    }
}

require_once __DIR__ . DIRECTORY_SEPARATOR . 'siem_config.php';
require_once __DIR__ . DIRECTORY_SEPARATOR . 'siem_logger.php';

/**
 * Detector de Anomalias principal
 */
class SiemAnomalyDetector {
    
    private $logger;
    private $alerter;
    
    public function __construct() {
        $this->logger = SiemLogger::getInstance();
    }
    
    /**
     * Define sistema de alertas
     */
    public function setAlerter($alerter) {
        $this->alerter = $alerter;
    }
    
    /**
     * Analisa requisição atual em busca de anomalias
     */
    public function analyzeCurrentRequest() {
        if (php_sapi_name() === 'cli') {
            return; // Não analisa requisições CLI
        }
        
        $detections = [];
        
        // Verifica padrões de ataque em parâmetros
        $detections = array_merge($detections, $this->checkAttackPatterns());
        
        // Verifica User Agent suspeito
        $detections = array_merge($detections, $this->checkSuspiciousUserAgent());
        
        // Verifica IPs maliciosos conhecidos
        $detections = array_merge($detections, $this->checkMaliciousIP());
        
        // Verifica tentativas de brute force em tempo real
        $detections = array_merge($detections, $this->checkBruteForceAttempts());
        
        // Processa detecções encontradas
        foreach ($detections as $detection) {
            $this->processDetection($detection);
        }
        
        return $detections;
    }
    
    /**
     * Analisa logs históricos em busca de anomalias
     */
    public function analyzeHistoricalData($hours = 24) {
        $anomalies = [];
        
        // Analisa padrões de login suspeitos
        $anomalies = array_merge($anomalies, $this->analyzeSuspiciousLogins($hours));
        
        // Analisa atividades incomuns por usuário
        $anomalies = array_merge($anomalies, $this->analyzeUserBehavior($hours));
        
        // Analisa padrões de tempo suspeitos
        $anomalies = array_merge($anomalies, $this->analyzeTimePatterns($hours));
        
        // Analisa concentração de IPs
        $anomalies = array_merge($anomalies, $this->analyzeIPConcentration($hours));
        
        return $anomalies;
    }
    
    /**
     * Verifica padrões de ataque nos parâmetros da requisição
     */
    private function checkAttackPatterns() {
        $detections = [];
        $allInputs = array_merge($_GET, $_POST, $_COOKIE);
        
        foreach ($allInputs as $param => $value) {
            if (!is_string($value)) continue;
            
            // Verifica SQL Injection
            if (SiemConfig::isSuspiciousPattern($value, 'sql_injection')) {
                $detections[] = [
                    'type' => SiemConfig::EVENT_SQL_INJECTION,
                    'severity' => SiemConfig::SEVERITY_HIGH,
                    'details' => [
                        'parameter' => $param,
                        'value' => substr($value, 0, 200), // Limita tamanho do log
                        'pattern_type' => 'sql_injection'
                    ]
                ];
            }
            
            // Verifica XSS
            if (SiemConfig::isSuspiciousPattern($value, 'xss')) {
                $detections[] = [
                    'type' => SiemConfig::EVENT_XSS_ATTEMPT,
                    'severity' => SiemConfig::SEVERITY_HIGH,
                    'details' => [
                        'parameter' => $param,
                        'value' => substr($value, 0, 200),
                        'pattern_type' => 'xss'
                    ]
                ];
            }
            
            // Verifica Directory Traversal
            if (SiemConfig::isSuspiciousPattern($value, 'directory_traversal')) {
                $detections[] = [
                    'type' => SiemConfig::EVENT_DIRECTORY_TRAVERSAL,
                    'severity' => SiemConfig::SEVERITY_MEDIUM,
                    'details' => [
                        'parameter' => $param,
                        'value' => substr($value, 0, 200),
                        'pattern_type' => 'directory_traversal'
                    ]
                ];
            }
        }
        
        return $detections;
    }
    
    /**
     * Verifica User Agent suspeito
     */
    private function checkSuspiciousUserAgent() {
        $detections = [];
        $userAgent = $_SERVER['HTTP_USER_AGENT'] ?? '';
        
        if (SiemConfig::isSuspiciousUserAgent($userAgent)) {
            $detections[] = [
                'type' => SiemConfig::EVENT_ANOMALY_DETECTED,
                'severity' => SiemConfig::SEVERITY_MEDIUM,
                'details' => [
                    'anomaly_type' => 'suspicious_user_agent',
                    'user_agent' => $userAgent,
                    'description' => 'User Agent associado a ferramentas de hacking detectado'
                ]
            ];
        }
        
        return $detections;
    }
    
    /**
     * Verifica IPs maliciosos conhecidos
     */
    private function checkMaliciousIP() {
        $detections = [];
        $clientIP = $this->getClientIP();
        
        if (SiemConfig::isMaliciousIP($clientIP)) {
            $detections[] = [
                'type' => SiemConfig::EVENT_SUSPICIOUS_IP,
                'severity' => SiemConfig::SEVERITY_CRITICAL,
                'details' => [
                    'ip_address' => $clientIP,
                    'threat_type' => 'known_malicious',
                    'description' => 'Acesso de IP conhecido como malicioso'
                ]
            ];
        }
        
        return $detections;
    }
    
    /**
     * Verifica tentativas de brute force em tempo real
     */
    private function checkBruteForceAttempts() {
        $detections = [];
        
        // Verifica se há muitas tentativas de login recentes
        $recentFailures = $this->getRecentLoginFailures();
        
        // Por minuto
        $failuresLastMinute = $this->countFailuresInPeriod($recentFailures, 1);
        if ($failuresLastMinute >= SiemConfig::MAX_LOGIN_FAILURES_PER_MINUTE) {
            $detections[] = [
                'type' => SiemConfig::EVENT_LOGIN_BRUTE_FORCE,
                'severity' => SiemConfig::SEVERITY_HIGH,
                'details' => [
                    'period' => 'minute',
                    'failure_count' => $failuresLastMinute,
                    'threshold' => SiemConfig::MAX_LOGIN_FAILURES_PER_MINUTE,
                    'description' => 'Múltiplas tentativas de login falharam no último minuto'
                ]
            ];
        }
        
        // Por hora
        $failuresLastHour = $this->countFailuresInPeriod($recentFailures, 60);
        if ($failuresLastHour >= SiemConfig::MAX_LOGIN_FAILURES_PER_HOUR) {
            $detections[] = [
                'type' => SiemConfig::EVENT_LOGIN_BRUTE_FORCE,
                'severity' => SiemConfig::SEVERITY_MEDIUM,
                'details' => [
                    'period' => 'hour',
                    'failure_count' => $failuresLastHour,
                    'threshold' => SiemConfig::MAX_LOGIN_FAILURES_PER_HOUR,
                    'description' => 'Múltiplas tentativas de login falharam na última hora'
                ]
            ];
        }
        
        return $detections;
    }
    
    /**
     * Obtém falhas de login recentes
     */
    private function getRecentLoginFailures() {
        $startTime = date('Y-m-d H:i:s', strtotime('-1 day'));
        $criteria = [
            'start_time' => $startTime,
            'event_type' => SiemConfig::EVENT_LOGIN_FAILURE
        ];
        
        return $this->logger->searchEvents($criteria);
    }
    
    /**
     * Conta falhas em período específico
     */
    private function countFailuresInPeriod($failures, $minutes) {
        $cutoff = time() - ($minutes * 60);
        $count = 0;
        
        foreach ($failures as $failure) {
            if (strtotime($failure['timestamp']) >= $cutoff) {
                $count++;
            }
        }
        
        return $count;
    }
    
    /**
     * Analisa padrões de login suspeitos
     */
    private function analyzeSuspiciousLogins($hours) {
        $anomalies = [];
        $startTime = date('Y-m-d H:i:s', strtotime("-{$hours} hours"));
        
        // Busca todos os eventos de login
        $loginEvents = $this->logger->searchEvents([
            'start_time' => $startTime,
            'event_type' => [SiemConfig::EVENT_LOGIN_SUCCESS, SiemConfig::EVENT_LOGIN_FAILURE]
        ]);
        
        // Agrupa por IP
        $ipStats = [];
        foreach ($loginEvents as $event) {
            $ip = $event['source_ip'];
            if ($ip === 'unknown' || $ip === 'CLI') continue;
            
            if (!isset($ipStats[$ip])) {
                $ipStats[$ip] = ['success' => 0, 'failure' => 0, 'users' => []];
            }
            
            if ($event['event_type'] === SiemConfig::EVENT_LOGIN_SUCCESS) {
                $ipStats[$ip]['success']++;
            } else {
                $ipStats[$ip]['failure']++;
            }
            
            if (!in_array($event['username'], $ipStats[$ip]['users'])) {
                $ipStats[$ip]['users'][] = $event['username'];
            }
        }
        
        // Analisa estatísticas por IP
        foreach ($ipStats as $ip => $stats) {
            $totalAttempts = $stats['success'] + $stats['failure'];
            $failureRate = $totalAttempts > 0 ? ($stats['failure'] / $totalAttempts) * 100 : 0;
            $userCount = count($stats['users']);
            
            // IP com muitos usuários diferentes (possível ataque)
            if ($userCount >= 5 && $totalAttempts >= 10) {
                $anomalies[] = [
                    'type' => 'multiple_users_same_ip',
                    'severity' => SiemConfig::SEVERITY_MEDIUM,
                    'ip' => $ip,
                    'user_count' => $userCount,
                    'total_attempts' => $totalAttempts,
                    'description' => "IP {$ip} tentou logar com {$userCount} usuários diferentes"
                ];
            }
            
            // IP com alta taxa de falha
            if ($totalAttempts >= 10 && $failureRate >= 80) {
                $anomalies[] = [
                    'type' => 'high_failure_rate_ip',
                    'severity' => SiemConfig::SEVERITY_HIGH,
                    'ip' => $ip,
                    'failure_rate' => round($failureRate, 2),
                    'total_attempts' => $totalAttempts,
                    'description' => "IP {$ip} com {$failureRate}% de falhas em {$totalAttempts} tentativas"
                ];
            }
        }
        
        return $anomalies;
    }
    
    /**
     * Analisa comportamento incomum dos usuários
     */
    private function analyzeUserBehavior($hours) {
        $anomalies = [];
        $startTime = date('Y-m-d H:i:s', strtotime("-{$hours} hours"));
        
        // Busca eventos de usuários
        $userEvents = $this->logger->searchEvents([
            'start_time' => $startTime
        ]);
        
        // Agrupa por usuário
        $userStats = [];
        foreach ($userEvents as $event) {
            $user = $event['username'];
            if ($user === 'unknown' || $user === 'anonymous') continue;
            
            if (!isset($userStats[$user])) {
                $userStats[$user] = [
                    'ips' => [],
                    'sessions' => [],
                    'events' => 0,
                    'login_times' => []
                ];
            }
            
            $userStats[$user]['events']++;
            
            if ($event['source_ip'] !== 'unknown' && !in_array($event['source_ip'], $userStats[$user]['ips'])) {
                $userStats[$user]['ips'][] = $event['source_ip'];
            }
            
            if ($event['session_id'] !== 'unknown' && !in_array($event['session_id'], $userStats[$user]['sessions'])) {
                $userStats[$user]['sessions'][] = $event['session_id'];
            }
            
            if ($event['event_type'] === SiemConfig::EVENT_LOGIN_SUCCESS) {
                $userStats[$user]['login_times'][] = strtotime($event['timestamp']);
            }
        }
        
        // Analisa estatísticas por usuário
        foreach ($userStats as $user => $stats) {
            // Usuário com muitos IPs diferentes
            $ipCount = count($stats['ips']);
            if ($ipCount >= 3) {
                $anomalies[] = [
                    'type' => 'user_multiple_ips',
                    'severity' => SiemConfig::SEVERITY_MEDIUM,
                    'username' => $user,
                    'ip_count' => $ipCount,
                    'ips' => $stats['ips'],
                    'description' => "Usuário {$user} acessou de {$ipCount} IPs diferentes"
                ];
            }
            
            // Usuário com atividade muito intensa
            if ($stats['events'] >= 100) {
                $anomalies[] = [
                    'type' => 'high_activity_user',
                    'severity' => SiemConfig::SEVERITY_LOW,
                    'username' => $user,
                    'event_count' => $stats['events'],
                    'description' => "Usuário {$user} teve {$stats['events']} eventos em {$hours}h"
                ];
            }
            
            // Logins muito rápidos (possível automação)
            if (count($stats['login_times']) >= 3) {
                $timeDiffs = [];
                for ($i = 1; $i < count($stats['login_times']); $i++) {
                    $timeDiffs[] = $stats['login_times'][$i] - $stats['login_times'][$i-1];
                }
                
                $avgTimeDiff = array_sum($timeDiffs) / count($timeDiffs);
                if ($avgTimeDiff < 30) { // Menos de 30 segundos entre logins
                    $anomalies[] = [
                        'type' => 'rapid_logins',
                        'severity' => SiemConfig::SEVERITY_MEDIUM,
                        'username' => $user,
                        'avg_time_between_logins' => $avgTimeDiff,
                        'login_count' => count($stats['login_times']),
                        'description' => "Usuário {$user} teve logins muito rápidos (média de {$avgTimeDiff}s)"
                    ];
                }
            }
        }
        
        return $anomalies;
    }
    
    /**
     * Analisa padrões de tempo suspeitos
     */
    private function analyzeTimePatterns($hours) {
        $anomalies = [];
        $startTime = date('Y-m-d H:i:s', strtotime("-{$hours} hours"));
        
        $events = $this->logger->searchEvents(['start_time' => $startTime]);
        
        // Analisa atividade fora do horário comercial
        $afterHoursCount = 0;
        $businessHoursCount = 0;
        
        foreach ($events as $event) {
            $hour = (int)date('H', strtotime($event['timestamp']));
            $dayOfWeek = (int)date('N', strtotime($event['timestamp'])); // 1-7 (Mon-Sun)
            
            // Considera horário comercial: 8h-18h, segunda a sexta
            if ($dayOfWeek >= 6 || $hour < 8 || $hour > 18) {
                $afterHoursCount++;
            } else {
                $businessHoursCount++;
            }
        }
        
        $totalEvents = $afterHoursCount + $businessHoursCount;
        if ($totalEvents > 20) {
            $afterHoursRate = ($afterHoursCount / $totalEvents) * 100;
            
            if ($afterHoursRate >= 60) {
                $anomalies[] = [
                    'type' => 'high_after_hours_activity',
                    'severity' => SiemConfig::SEVERITY_MEDIUM,
                    'after_hours_rate' => round($afterHoursRate, 2),
                    'after_hours_count' => $afterHoursCount,
                    'total_events' => $totalEvents,
                    'description' => "Alta atividade fora do horário comercial ({$afterHoursRate}%)"
                ];
            }
        }
        
        return $anomalies;
    }
    
    /**
     * Analisa concentração de IPs
     */
    private function analyzeIPConcentration($hours) {
        $anomalies = [];
        $startTime = date('Y-m-d H:i:s', strtotime("-{$hours} hours"));
        
        $events = $this->logger->searchEvents(['start_time' => $startTime]);
        
        $ipCounts = [];
        foreach ($events as $event) {
            $ip = $event['source_ip'];
            if ($ip === 'unknown' || $ip === 'CLI') continue;
            
            $ipCounts[$ip] = ($ipCounts[$ip] ?? 0) + 1;
        }
        
        if (count($ipCounts) === 0) return $anomalies;
        
        $totalEvents = array_sum($ipCounts);
        arsort($ipCounts);
        $topIP = array_key_first($ipCounts);
        $topIPCount = $ipCounts[$topIP];
        $topIPRate = ($topIPCount / $totalEvents) * 100;
        
        // Se um IP representa mais de 50% da atividade
        if ($topIPRate >= 50 && $totalEvents >= 20) {
            $anomalies[] = [
                'type' => 'ip_concentration',
                'severity' => SiemConfig::SEVERITY_MEDIUM,
                'top_ip' => $topIP,
                'concentration_rate' => round($topIPRate, 2),
                'event_count' => $topIPCount,
                'total_events' => $totalEvents,
                'description' => "IP {$topIP} representa {$topIPRate}% de toda atividade"
            ];
        }
        
        return $anomalies;
    }
    
    /**
     * Processa uma detecção encontrada
     */
    private function processDetection($detection) {
        // Registra a anomalia
        $eventId = $this->logger->logAnomaly(
            $detection['type'],
            $detection['severity'],
            $detection['details']
        );
        
        // Se for crítico ou alto, gera alerta
        if ($detection['severity'] === SiemConfig::SEVERITY_CRITICAL || 
            $detection['severity'] === SiemConfig::SEVERITY_HIGH) {
            
            if ($this->alerter) {
                $this->alerter->sendAlert($detection, $eventId);
            }
        }
        
        return $eventId;
    }
    
    /**
     * Obtém IP do cliente (método auxiliar)
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
                
                if (filter_var($ip, FILTER_VALIDATE_IP)) {
                    return $ip;
                }
            }
        }
        
        return 'unknown';
    }
}

/**
 * Funções de conveniência
 */

/**
 * Executa análise completa da requisição atual
 */
function detectAnomaliesInRequest() {
    $detector = new SiemAnomalyDetector();
    return $detector->analyzeCurrentRequest();
}

/**
 * Executa análise histórica de anomalias
 */
function detectHistoricalAnomalies($hours = 24) {
    $detector = new SiemAnomalyDetector();
    return $detector->analyzeHistoricalData($hours);
}