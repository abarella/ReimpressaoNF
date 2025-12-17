<?php
/**
 * Dashboard SIEM - Interface Web para Monitoramento de Segurança
 * 
 * Fornece uma interface visual para monitorar eventos de segurança,
 * visualizar estatísticas e gerenciar alertas do sistema SIEM
 */

// Configurações iniciais
require_once __DIR__ . DIRECTORY_SEPARATOR . 'siem_config.php';
require_once __DIR__ . DIRECTORY_SEPARATOR . 'siem_logger.php';
require_once __DIR__ . DIRECTORY_SEPARATOR . 'siem_detector.php';
require_once __DIR__ . DIRECTORY_SEPARATOR . 'siem_alerts.php';

// Autenticação básica para o dashboard SIEM
session_start();

// Verifica se precisa fazer login simples
$needAuth = true;

// Verifica se já tem autenticação do sistema principal
if (file_exists(__DIR__ . DIRECTORY_SEPARATOR . 'auth.php')) {
    require_once __DIR__ . DIRECTORY_SEPARATOR . 'auth.php';
    
    // Se já está logado no sistema principal, permite acesso
    if (isset($_SESSION['logado']) && $_SESSION['logado'] && isset($_SESSION['usuario'])) {
        $needAuth = false;
    }
}

// Autenticação simples para o dashboard SIEM se não estiver logado
if ($needAuth) {
    // Credenciais básicas para o dashboard (altere conforme necessário)
    $siem_users = [
        'admin' => 'siem123',
        'siem' => 'dashboard',
        'security' => 'monitor'
    ];
    
    // Processa login simples
    if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['siem_login'])) {
        $user = $_POST['username'] ?? '';
        $pass = $_POST['password'] ?? '';
        
        if (isset($siem_users[$user]) && $siem_users[$user] === $pass) {
            $_SESSION['siem_authenticated'] = true;
            $_SESSION['siem_user'] = $user;
            header('Location: ' . $_SERVER['PHP_SELF']);
            exit;
        } else {
            $login_error = 'Credenciais inválidas';
        }
    }
    
    // Verifica se já está autenticado no SIEM
    if (!isset($_SESSION['siem_authenticated']) || !$_SESSION['siem_authenticated']) {
        // Mostra formulário de login simples
        ?>
        <!DOCTYPE html>
        <html lang="pt-BR">
        <head>
            <meta charset="UTF-8">
            <meta name="viewport" content="width=device-width, initial-scale=1.0">
            <title>Login - Dashboard SIEM</title>
            <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.1.3/dist/css/bootstrap.min.css" rel="stylesheet">
            <style>
                body { background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); min-height: 100vh; }
                .login-container { max-width: 400px; margin: 100px auto; }
                .card { border: none; border-radius: 15px; box-shadow: 0 10px 30px rgba(0,0,0,0.2); }
            </style>
        </head>
        <body>
            <div class="login-container">
                <div class="card">
                    <div class="card-body p-5">
                        <div class="text-center mb-4">
                            <h2 class="text-primary">🛡️ Dashboard SIEM</h2>
                            <p class="text-muted">Acesso ao Sistema de Monitoramento</p>
                        </div>
                        
                        <?php if (isset($login_error)): ?>
                            <div class="alert alert-danger"><?= $login_error ?></div>
                        <?php endif; ?>
                        
                        <form method="POST">
                            <input type="hidden" name="siem_login" value="1">
                            <div class="mb-3">
                                <label for="username" class="form-label">Usuário</label>
                                <input type="text" class="form-control" id="username" name="username" required>
                            </div>
                            <div class="mb-3">
                                <label for="password" class="form-label">Senha</label>
                                <input type="password" class="form-control" id="password" name="password" required>
                            </div>
                            <button type="submit" class="btn btn-primary w-100">Entrar</button>
                        </form>
                        
                        <hr>
                        <div class="small text-muted text-center">
                            <strong>Credenciais padrão:</strong><br>
                            Usuário: <code>admin</code> | Senha: <code>siem123</code><br>
                            Usuário: <code>siem</code> | Senha: <code>dashboard</code>
                        </div>
                    </div>
                </div>
            </div>
        </body>
        </html>
        <?php
        exit;
    }
}

// Define usuário atual
$current_user = 'SIEM User'; // padrão

// Verifica se tem usuário do sistema principal
if (isset($_SESSION['usuario'])) {
    if (is_array($_SESSION['usuario'])) {
        $current_user = $_SESSION['usuario']['username'] ?? $_SESSION['usuario']['displayName'] ?? $_SESSION['usuario'][0] ?? 'Sistema Principal';
    } else {
        $current_user = $_SESSION['usuario'];
    }
} elseif (isset($_SESSION['siem_user'])) {
    $current_user = $_SESSION['siem_user'];
}

// Garante que seja sempre string
$current_user = (string) $current_user;

// Processa logout
if (isset($_GET['logout'])) {
    // Limpa sessão SIEM
    unset($_SESSION['siem_authenticated']);
    unset($_SESSION['siem_user']);
    
    // Se não tem autenticação do sistema principal, destroi sessão completamente
    if (!isset($_SESSION['logado']) || !$_SESSION['logado']) {
        session_destroy();
    }
    
    header('Location: ' . strtok($_SERVER['REQUEST_URI'], '?'));
    exit;
}

// Instancia classes SIEM
$logger = SiemLogger::getInstance();
$detector = new SiemAnomalyDetector();

// Processa ações AJAX
if (isset($_GET['action'])) {
    header('Content-Type: application/json');
    
    switch ($_GET['action']) {
        case 'get_events':
            echo json_encode(getRecentEvents());
            exit;
            
        case 'get_stats':
            echo json_encode(getSecurityStats());
            exit;
            
        case 'get_chart_data':
            echo json_encode(getChartData());
            exit;
            
        case 'run_analysis':
            echo json_encode(runAnomalyAnalysis());
            exit;
            
        case 'get_alerts':
            echo json_encode(getRecentAlerts());
            exit;
    }
}

/**
 * Funções auxiliares
 */
function getRecentEvents() {
    global $logger;
    $limit = $_GET['limit'] ?? 50;
    $criteria = ['limit' => $limit];
    
    if (!empty($_GET['severity'])) {
        $criteria['severity'] = $_GET['severity'];
    }
    
    if (!empty($_GET['event_type'])) {
        $criteria['event_type'] = $_GET['event_type'];
    }
    
    if (!empty($_GET['hours'])) {
        $hours = (int)$_GET['hours'];
        $criteria['start_time'] = date('Y-m-d H:i:s', strtotime("-{$hours} hours"));
    }
    
    $events = $logger->searchEvents($criteria);
    
    // Limita a quantidade se necessário
    if (isset($criteria['limit'])) {
        $events = array_slice($events, 0, $criteria['limit']);
    }
    
    return $events;
}

function getSecurityStats() {
    global $logger;
    $hours = $_GET['hours'] ?? 24;
    return $logger->getEventStatistics($hours);
}

function getChartData() {
    global $logger;
    $hours = $_GET['hours'] ?? 24;
    $stats = $logger->getEventStatistics($hours);
    
    // Prepara dados para gráficos
    $chartData = [
        'severity_chart' => [],
        'hourly_chart' => [],
        'top_ips_chart' => [],
        'event_types_chart' => []
    ];
    
    // Gráfico por severidade
    foreach ($stats['by_severity'] as $severity => $count) {
        $chartData['severity_chart'][] = [
            'label' => $severity,
            'data' => $count,
            'color' => getSeverityColor($severity)
        ];
    }
    
    // Gráfico por hora
    for ($i = 23; $i >= 0; $i--) {
        $hour = date('H', strtotime("-{$i} hours"));
        $count = $stats['by_hour'][$hour] ?? 0;
        $chartData['hourly_chart'][] = [
            'hour' => $hour . ':00',
            'events' => $count
        ];
    }
    
    // Top IPs
    $topIPs = array_slice($stats['unique_ips'], 0, 10, true);
    foreach ($topIPs as $ip => $count) {
        $chartData['top_ips_chart'][] = [
            'ip' => $ip,
            'events' => $count
        ];
    }
    
    // Tipos de eventos
    $topTypes = array_slice($stats['by_type'], 0, 8, true);
    foreach ($topTypes as $type => $count) {
        $chartData['event_types_chart'][] = [
            'type' => $type,
            'count' => $count
        ];
    }
    
    return $chartData;
}

function runAnomalyAnalysis() {
    global $detector;
    $hours = $_GET['hours'] ?? 24;
    
    $anomalies = $detector->analyzeHistoricalData($hours);
    
    return [
        'total_anomalies' => count($anomalies),
        'anomalies' => $anomalies,
        'analysis_timestamp' => date('Y-m-d H:i:s')
    ];
}

function getRecentAlerts() {
    global $logger;
    $hours = $_GET['hours'] ?? 24;
    $criteria = [
        'start_time' => date('Y-m-d H:i:s', strtotime("-{$hours} hours")),
        'limit' => 20
    ];
    
    // Busca nos logs de alerta
    $logFile = SiemConfig::LOG_DIRECTORY . SiemConfig::ALERTS_LOG_FILE;
    $alerts = [];
    
    if (file_exists($logFile)) {
        $handle = fopen($logFile, 'r');
        if ($handle) {
            while (($line = fgets($handle)) !== false) {
                $event = json_decode(trim($line), true);
                if ($event && strtotime($event['timestamp']) >= strtotime($criteria['start_time'])) {
                    $alerts[] = $event;
                }
            }
            fclose($handle);
        }
    }
    
    // Ordena por timestamp
    usort($alerts, function($a, $b) {
        return strtotime($b['timestamp']) - strtotime($a['timestamp']);
    });
    
    return array_slice($alerts, 0, $criteria['limit']);
}

function getSeverityColor($severity) {
    switch ($severity) {
        case SiemConfig::SEVERITY_CRITICAL: return '#dc3545';
        case SiemConfig::SEVERITY_HIGH: return '#fd7e14';
        case SiemConfig::SEVERITY_MEDIUM: return '#ffc107';
        case SiemConfig::SEVERITY_LOW: return '#17a2b8';
        default: return '#6c757d';
    }
}

function formatEventType($type) {
    return str_replace('_', ' ', ucwords(strtolower($type), '_'));
}

function timeAgo($timestamp) {
    $time = strtotime($timestamp);
    $diff = time() - $time;
    
    if ($diff < 60) return 'Agora mesmo';
    if ($diff < 3600) return floor($diff/60) . ' min atrás';
    if ($diff < 86400) return floor($diff/3600) . ' h atrás';
    return floor($diff/86400) . ' dias atrás';
}

// Estatísticas iniciais
$stats = getSecurityStats();
$recentEvents = getRecentEvents();
$chartData = getChartData();
?>
<!DOCTYPE html>
<html lang="pt-BR">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Dashboard SIEM - Monitoramento de Segurança</title>
    
    <!-- Bootstrap CSS -->
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.1.3/dist/css/bootstrap.min.css" rel="stylesheet">
    <!-- FontAwesome -->
    <link href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.0.0/css/all.min.css" rel="stylesheet">
    <!-- Chart.js -->
    <script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
    
    <style>
        .bg-critical { background-color: #dc3545 !important; }
        .bg-high { background-color: #fd7e14 !important; }
        .bg-medium { background-color: #ffc107 !important; }
        .bg-low { background-color: #17a2b8 !important; }
        .bg-info { background-color: #6c757d !important; }
        
        .severity-badge {
            font-size: 0.75rem;
            padding: 0.25rem 0.5rem;
        }
        
        .event-row:hover {
            background-color: #f8f9fa;
        }
        
        .chart-container {
            position: relative;
            height: 300px;
        }
        
        .stats-card {
            transition: transform 0.2s;
        }
        
        .stats-card:hover {
            transform: translateY(-5px);
        }
        
        .dashboard-header {
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white;
            padding: 2rem 0;
        }
        
        .refresh-btn {
            animation: spin 2s linear infinite;
        }
        
        @keyframes spin {
            0% { transform: rotate(0deg); }
            100% { transform: rotate(360deg); }
        }
        
        .event-details {
            font-size: 0.85rem;
            color: #6c757d;
        }
        
        .anomaly-card {
            border-left: 4px solid #dc3545;
        }
    </style>
</head>
<body class="bg-light">

<!-- Header -->
<div class="dashboard-header">
    <div class="container">
        <div class="row align-items-center">
            <div class="col-md-6">
                <h1 class="mb-2">
                    <i class="fas fa-shield-alt me-3"></i>
                    Dashboard SIEM
                </h1>
                <p class="mb-0 opacity-75">Monitoramento de Segurança em Tempo Real</p>
            </div>
            <div class="col-md-6 text-end">
                <div class="d-flex align-items-center justify-content-end">
                    <div class="me-3">
                        <small class="opacity-75">Logado como:</small><br>
                        <strong><?= htmlspecialchars($current_user) ?></strong>
                    </div>
                    <button class="btn btn-outline-light btn-sm me-2" onclick="refreshDashboard()">
                        <i class="fas fa-sync-alt"></i> Atualizar
                    </button>
                    <a href="?logout=1" class="btn btn-outline-light btn-sm me-2" onclick="return confirm('Deseja fazer logout?')">
                        <i class="fas fa-sign-out-alt"></i> Sair
                    </a>
                </div>
                <div class="text-end">
                    <span class="small opacity-75">Última atualização: <span id="last-update"><?= date('H:i:s') ?></span></span>
                </div>
            </div>
        </div>
    </div>
</div>

<div class="container-fluid mt-4">
    
    <!-- Cards de Estatísticas -->
    <div class="row mb-4">
        <div class="col-lg-3 col-md-6 mb-3">
            <div class="card stats-card h-100">
                <div class="card-body text-center">
                    <div class="d-flex justify-content-between align-items-center">
                        <div>
                            <h5 class="text-muted mb-0">Total de Eventos</h5>
                            <h2 class="mb-0"><?= $stats['total_events'] ?></h2>
                            <small class="text-muted">Últimas 24h</small>
                        </div>
                        <i class="fas fa-list-alt fa-2x text-primary"></i>
                    </div>
                </div>
            </div>
        </div>
        
        <div class="col-lg-3 col-md-6 mb-3">
            <div class="card stats-card h-100">
                <div class="card-body text-center">
                    <div class="d-flex justify-content-between align-items-center">
                        <div>
                            <h5 class="text-muted mb-0">Eventos Críticos</h5>
                            <h2 class="mb-0 text-danger"><?= $stats['by_severity'][SiemConfig::SEVERITY_CRITICAL] ?? 0 ?></h2>
                            <small class="text-muted">Requer atenção</small>
                        </div>
                        <i class="fas fa-exclamation-triangle fa-2x text-danger"></i>
                    </div>
                </div>
            </div>
        </div>
        
        <div class="col-lg-3 col-md-6 mb-3">
            <div class="card stats-card h-100">
                <div class="card-body text-center">
                    <div class="d-flex justify-content-between align-items-center">
                        <div>
                            <h5 class="text-muted mb-0">IPs Únicos</h5>
                            <h2 class="mb-0 text-info"><?= count($stats['unique_ips']) ?></h2>
                            <small class="text-muted">Fontes diferentes</small>
                        </div>
                        <i class="fas fa-network-wired fa-2x text-info"></i>
                    </div>
                </div>
            </div>
        </div>
        
        <div class="col-lg-3 col-md-6 mb-3">
            <div class="card stats-card h-100">
                <div class="card-body text-center">
                    <div class="d-flex justify-content-between align-items-center">
                        <div>
                            <h5 class="text-muted mb-0">Usuários Ativos</h5>
                            <h2 class="mb-0 text-success"><?= count($stats['unique_users']) ?></h2>
                            <small class="text-muted">Usuários únicos</small>
                        </div>
                        <i class="fas fa-users fa-2x text-success"></i>
                    </div>
                </div>
            </div>
        </div>
    </div>
    
    <!-- Gráficos -->
    <div class="row mb-4">
        <div class="col-lg-6 mb-3">
            <div class="card h-100">
                <div class="card-header">
                    <h5 class="card-title mb-0">
                        <i class="fas fa-chart-pie me-2"></i>
                        Eventos por Severidade
                    </h5>
                </div>
                <div class="card-body">
                    <div class="chart-container">
                        <canvas id="severityChart"></canvas>
                    </div>
                </div>
            </div>
        </div>
        
        <div class="col-lg-6 mb-3">
            <div class="card h-100">
                <div class="card-header">
                    <h5 class="card-title mb-0">
                        <i class="fas fa-chart-line me-2"></i>
                        Eventos por Hora
                    </h5>
                </div>
                <div class="card-body">
                    <div class="chart-container">
                        <canvas id="hourlyChart"></canvas>
                    </div>
                </div>
            </div>
        </div>
    </div>
    
    <!-- Alertas e Anomalias -->
    <div class="row mb-4">
        <div class="col-lg-6 mb-3">
            <div class="card h-100">
                <div class="card-header d-flex justify-content-between align-items-center">
                    <h5 class="card-title mb-0">
                        <i class="fas fa-exclamation-circle me-2"></i>
                        Alertas Recentes
                    </h5>
                    <button class="btn btn-sm btn-outline-primary" onclick="loadAlerts()">
                        <i class="fas fa-sync-alt"></i>
                    </button>
                </div>
                <div class="card-body" id="alerts-container" style="max-height: 400px; overflow-y: auto;">
                    <div class="text-center">
                        <div class="spinner-border" role="status">
                            <span class="visually-hidden">Carregando...</span>
                        </div>
                    </div>
                </div>
            </div>
        </div>
        
        <div class="col-lg-6 mb-3">
            <div class="card h-100">
                <div class="card-header d-flex justify-content-between align-items-center">
                    <h5 class="card-title mb-0">
                        <i class="fas fa-search me-2"></i>
                        Análise de Anomalias
                    </h5>
                    <button class="btn btn-sm btn-outline-warning" onclick="runAnalysis()">
                        <i class="fas fa-play"></i> Executar
                    </button>
                </div>
                <div class="card-body" id="anomalies-container" style="max-height: 400px; overflow-y: auto;">
                    <div class="text-center text-muted">
                        <i class="fas fa-robot fa-3x mb-3"></i>
                        <p>Clique em "Executar" para iniciar a análise de anomalias</p>
                    </div>
                </div>
            </div>
        </div>
    </div>
    
    <!-- Lista de Eventos Recentes -->
    <div class="row">
        <div class="col-12">
            <div class="card">
                <div class="card-header d-flex justify-content-between align-items-center">
                    <h5 class="card-title mb-0">
                        <i class="fas fa-list me-2"></i>
                        Eventos Recentes de Segurança
                    </h5>
                    <div class="btn-group">
                        <button class="btn btn-sm btn-outline-secondary dropdown-toggle" type="button" data-bs-toggle="dropdown">
                            <i class="fas fa-filter"></i> Filtros
                        </button>
                        <ul class="dropdown-menu">
                            <li><a class="dropdown-item" href="#" onclick="filterEvents('severity', 'CRITICAL')">Apenas Críticos</a></li>
                            <li><a class="dropdown-item" href="#" onclick="filterEvents('severity', 'HIGH')">Alta Prioridade</a></li>
                            <li><a class="dropdown-item" href="#" onclick="filterEvents('hours', '1')">Última Hora</a></li>
                            <li><a class="dropdown-item" href="#" onclick="filterEvents('hours', '6')">Últimas 6h</a></li>
                            <li><hr class="dropdown-divider"></li>
                            <li><a class="dropdown-item" href="#" onclick="clearFilters()">Limpar Filtros</a></li>
                        </ul>
                    </div>
                </div>
                <div class="card-body p-0">
                    <div class="table-responsive">
                        <table class="table table-hover mb-0">
                            <thead class="table-dark">
                                <tr>
                                    <th>Timestamp</th>
                                    <th>Severidade</th>
                                    <th>Tipo de Evento</th>
                                    <th>IP de Origem</th>
                                    <th>Usuário</th>
                                    <th>Detalhes</th>
                                </tr>
                            </thead>
                            <tbody id="events-table-body">
                                <?php foreach (array_slice($recentEvents, 0, 20) as $event): ?>
                                <tr class="event-row">
                                    <td>
                                        <small><?= date('d/m H:i:s', strtotime($event['timestamp'])) ?></small>
                                        <br>
                                        <small class="text-muted"><?= timeAgo($event['timestamp']) ?></small>
                                    </td>
                                    <td>
                                        <span class="badge severity-badge bg-<?= strtolower(str_replace('_', '', $event['severity'])) ?>">
                                            <?= $event['severity'] ?>
                                        </span>
                                    </td>
                                    <td><?= formatEventType($event['event_type']) ?></td>
                                    <td>
                                        <code><?= htmlspecialchars($event['source_ip']) ?></code>
                                    </td>
                                    <td><?= htmlspecialchars($event['username']) ?></td>
                                    <td>
                                        <?php if (isset($event['details'])): ?>
                                            <button class="btn btn-sm btn-outline-info" 
                                                    onclick="showEventDetails('<?= htmlspecialchars(json_encode($event), ENT_QUOTES) ?>')">
                                                <i class="fas fa-info-circle"></i>
                                            </button>
                                        <?php endif; ?>
                                    </td>
                                </tr>
                                <?php endforeach; ?>
                            </tbody>
                        </table>
                    </div>
                </div>
            </div>
        </div>
    </div>
</div>

<!-- Modal para Detalhes do Evento -->
<div class="modal fade" id="eventDetailsModal" tabindex="-1">
    <div class="modal-dialog modal-lg">
        <div class="modal-content">
            <div class="modal-header">
                <h5 class="modal-title">Detalhes do Evento de Segurança</h5>
                <button type="button" class="btn-close" data-bs-dismiss="modal"></button>
            </div>
            <div class="modal-body" id="event-details-content">
            </div>
        </div>
    </div>
</div>

<!-- Scripts -->
<script src="https://cdn.jsdelivr.net/npm/bootstrap@5.1.3/dist/js/bootstrap.bundle.min.js"></script>

<script>
// Variáveis globais
let currentFilters = {};
let refreshInterval;

// Inicialização
document.addEventListener('DOMContentLoaded', function() {
    initializeCharts();
    loadAlerts();
    
    // Auto-refresh a cada 30 segundos
    refreshInterval = setInterval(function() {
        refreshDashboard();
    }, 30000);
});

// Inicializa os gráficos
function initializeCharts() {
    const chartData = <?= json_encode($chartData) ?>;
    
    // Gráfico de Severidade
    const severityCtx = document.getElementById('severityChart').getContext('2d');
    new Chart(severityCtx, {
        type: 'doughnut',
        data: {
            labels: chartData.severity_chart.map(item => item.label),
            datasets: [{
                data: chartData.severity_chart.map(item => item.data),
                backgroundColor: chartData.severity_chart.map(item => item.color),
                borderWidth: 2
            }]
        },
        options: {
            responsive: true,
            maintainAspectRatio: false,
            plugins: {
                legend: {
                    position: 'bottom'
                }
            }
        }
    });
    
    // Gráfico por Hora
    const hourlyCtx = document.getElementById('hourlyChart').getContext('2d');
    new Chart(hourlyCtx, {
        type: 'line',
        data: {
            labels: chartData.hourly_chart.map(item => item.hour),
            datasets: [{
                label: 'Eventos',
                data: chartData.hourly_chart.map(item => item.events),
                borderColor: '#007bff',
                backgroundColor: 'rgba(0, 123, 255, 0.1)',
                tension: 0.1,
                fill: true
            }]
        },
        options: {
            responsive: true,
            maintainAspectRatio: false,
            scales: {
                y: {
                    beginAtZero: true,
                    ticks: {
                        stepSize: 1
                    }
                }
            }
        }
    });
}

// Carrega alertas recentes
function loadAlerts() {
    fetch('?action=get_alerts')
        .then(response => response.json())
        .then(alerts => {
            const container = document.getElementById('alerts-container');
            
            if (alerts.length === 0) {
                container.innerHTML = `
                    <div class="text-center text-muted">
                        <i class="fas fa-check-circle fa-3x mb-3 text-success"></i>
                        <p>Nenhum alerta nas últimas 24 horas</p>
                    </div>
                `;
                return;
            }
            
            let html = '';
            alerts.forEach(alert => {
                const severity = alert.details?.severity || alert.severity || 'INFO';
                html += `
                    <div class="alert alert-${getSeverityBootstrapClass(severity)} alert-dismissible fade show mb-2">
                        <div class="d-flex justify-content-between">
                            <div>
                                <strong>${alert.event_type || 'Alerta'}</strong>
                                <br>
                                <small class="text-muted">${new Date(alert.timestamp).toLocaleString()}</small>
                            </div>
                            <span class="badge bg-${getSeverityBootstrapClass(severity)}">${severity}</span>
                        </div>
                        ${alert.details?.description ? `<p class="mb-0 mt-2">${alert.details.description}</p>` : ''}
                    </div>
                `;
            });
            
            container.innerHTML = html;
        })
        .catch(error => {
            console.error('Erro ao carregar alertas:', error);
            document.getElementById('alerts-container').innerHTML = `
                <div class="alert alert-danger">
                    Erro ao carregar alertas
                </div>
            `;
        });
}

// Executa análise de anomalias
function runAnalysis() {
    const container = document.getElementById('anomalies-container');
    container.innerHTML = `
        <div class="text-center">
            <div class="spinner-border text-warning" role="status">
                <span class="visually-hidden">Analisando...</span>
            </div>
            <p class="mt-2">Executando análise de anomalias...</p>
        </div>
    `;
    
    fetch('?action=run_analysis')
        .then(response => response.json())
        .then(data => {
            if (data.total_anomalies === 0) {
                container.innerHTML = `
                    <div class="text-center text-muted">
                        <i class="fas fa-check-circle fa-3x mb-3 text-success"></i>
                        <p>Nenhuma anomalia detectada</p>
                        <small>Análise concluída em ${data.analysis_timestamp}</small>
                    </div>
                `;
                return;
            }
            
            let html = `
                <div class="mb-3">
                    <h6 class="text-warning">
                        <i class="fas fa-exclamation-triangle"></i>
                        ${data.total_anomalies} anomalia(s) detectada(s)
                    </h6>
                    <small class="text-muted">Análise: ${data.analysis_timestamp}</small>
                </div>
            `;
            
            data.anomalies.forEach(anomaly => {
                html += `
                    <div class="card anomaly-card mb-2">
                        <div class="card-body p-3">
                            <div class="d-flex justify-content-between">
                                <h6 class="mb-1">${anomaly.type.replace(/_/g, ' ').toUpperCase()}</h6>
                                <span class="badge bg-${getSeverityBootstrapClass(anomaly.severity)}">${anomaly.severity}</span>
                            </div>
                            <p class="mb-0 small">${anomaly.description || 'Anomalia detectada'}</p>
                        </div>
                    </div>
                `;
            });
            
            container.innerHTML = html;
        })
        .catch(error => {
            console.error('Erro na análise:', error);
            container.innerHTML = `
                <div class="alert alert-danger">
                    Erro ao executar análise
                </div>
            `;
        });
}

// Atualiza dashboard
function refreshDashboard() {
    const btn = document.querySelector('[onclick="refreshDashboard()"] i');
    btn.classList.add('refresh-btn');
    
    // Recarrega dados
    loadEvents();
    loadAlerts();
    
    // Atualiza timestamp
    document.getElementById('last-update').textContent = new Date().toLocaleTimeString();
    
    setTimeout(() => {
        btn.classList.remove('refresh-btn');
    }, 1000);
}

// Carrega eventos com filtros
function loadEvents() {
    const params = new URLSearchParams(currentFilters);
    params.set('action', 'get_events');
    
    fetch('?' + params.toString())
        .then(response => response.json())
        .then(events => {
            updateEventsTable(events);
        })
        .catch(error => {
            console.error('Erro ao carregar eventos:', error);
        });
}

// Atualiza tabela de eventos
function updateEventsTable(events) {
    const tbody = document.getElementById('events-table-body');
    
    if (events.length === 0) {
        tbody.innerHTML = `
            <tr>
                <td colspan="6" class="text-center text-muted">
                    Nenhum evento encontrado
                </td>
            </tr>
        `;
        return;
    }
    
    let html = '';
    events.slice(0, 20).forEach(event => {
        html += `
            <tr class="event-row">
                <td>
                    <small>${new Date(event.timestamp).toLocaleString()}</small>
                    <br>
                    <small class="text-muted">${timeAgo(event.timestamp)}</small>
                </td>
                <td>
                    <span class="badge severity-badge bg-${getSeverityBootstrapClass(event.severity)}">
                        ${event.severity}
                    </span>
                </td>
                <td>${event.event_type.replace(/_/g, ' ')}</td>
                <td><code>${event.source_ip}</code></td>
                <td>${event.username}</td>
                <td>
                    ${event.details ? `
                        <button class="btn btn-sm btn-outline-info" 
                                onclick="showEventDetails('${JSON.stringify(event).replace(/'/g, '\\\'').replace(/"/g, '\\"')}')">
                            <i class="fas fa-info-circle"></i>
                        </button>
                    ` : ''}
                </td>
            </tr>
        `;
    });
    
    tbody.innerHTML = html;
}

// Aplica filtros
function filterEvents(filterType, value) {
    currentFilters[filterType] = value;
    loadEvents();
}

// Limpa filtros
function clearFilters() {
    currentFilters = {};
    loadEvents();
}

// Mostra detalhes do evento
function showEventDetails(eventJson) {
    const event = JSON.parse(eventJson);
    
    let html = `
        <div class="row">
            <div class="col-md-6">
                <h6>Informações Básicas</h6>
                <table class="table table-sm">
                    <tr><td><strong>ID:</strong></td><td><code>${event.event_id}</code></td></tr>
                    <tr><td><strong>Timestamp:</strong></td><td>${new Date(event.timestamp).toLocaleString()}</td></tr>
                    <tr><td><strong>Tipo:</strong></td><td>${event.event_type}</td></tr>
                    <tr><td><strong>Severidade:</strong></td><td>
                        <span class="badge bg-${getSeverityBootstrapClass(event.severity)}">${event.severity}</span>
                    </td></tr>
                </table>
            </div>
            <div class="col-md-6">
                <h6>Contexto</h6>
                <table class="table table-sm">
                    <tr><td><strong>IP:</strong></td><td><code>${event.source_ip}</code></td></tr>
                    <tr><td><strong>Usuário:</strong></td><td>${event.username}</td></tr>
                    <tr><td><strong>Sessão:</strong></td><td><code>${event.session_id}</code></td></tr>
                    <tr><td><strong>URI:</strong></td><td><code>${event.request_uri || 'N/A'}</code></td></tr>
                </table>
            </div>
        </div>
    `;
    
    if (event.details && Object.keys(event.details).length > 0) {
        html += `
            <div class="mt-3">
                <h6>Detalhes Adicionais</h6>
                <pre class="bg-light p-3 rounded"><code>${JSON.stringify(event.details, null, 2)}</code></pre>
            </div>
        `;
    }
    
    document.getElementById('event-details-content').innerHTML = html;
    new bootstrap.Modal(document.getElementById('eventDetailsModal')).show();
}

// Funções auxiliares
function getSeverityBootstrapClass(severity) {
    switch (severity) {
        case 'CRITICAL': return 'danger';
        case 'HIGH': return 'warning';
        case 'MEDIUM': return 'info';
        case 'LOW': return 'secondary';
        default: return 'light';
    }
}

function timeAgo(timestamp) {
    const diff = Math.floor((new Date() - new Date(timestamp)) / 1000);
    
    if (diff < 60) return 'Agora mesmo';
    if (diff < 3600) return Math.floor(diff/60) + ' min atrás';
    if (diff < 86400) return Math.floor(diff/3600) + ' h atrás';
    return Math.floor(diff/86400) + ' dias atrás';
}
</script>

</body>
</html>