<?php
/**
 * Setup do Sistema SIEM
 * 
 * Script de instalação e configuração do sistema SIEM
 * Execute este script uma vez para configurar o ambiente
 */

echo "=== SETUP DO SISTEMA SIEM ===\n\n";

// Verifica se está sendo executado via CLI (recomendado)
if (php_sapi_name() !== 'cli') {
    echo "<h1>Setup do Sistema SIEM</h1>\n";
    echo "<p><strong>Aviso:</strong> É recomendado executar este script via linha de comando.</p>\n";
}

$baseDir = __DIR__;

// Inclui arquivos necessários
require_once $baseDir . DIRECTORY_SEPARATOR . 'siem_config.php';

/**
 * Função para imprimir mensagens
 */
function printMessage($message, $type = 'INFO') {
    $timestamp = date('Y-m-d H:i:s');
    
    if (php_sapi_name() === 'cli') {
        $colors = [
            'INFO' => "\033[0;32m",    // Verde
            'WARNING' => "\033[0;33m", // Amarelo
            'ERROR' => "\033[0;31m",   // Vermelho
            'SUCCESS' => "\033[1;32m", // Verde brilhante
            'RESET' => "\033[0m"       // Reset
        ];
        
        $color = $colors[$type] ?? $colors['INFO'];
        echo "{$color}[{$timestamp}] [{$type}]{$colors['RESET']} {$message}\n";
    } else {
        $colorClass = strtolower($type);
        echo "<p class='{$colorClass}'>[{$timestamp}] [{$type}] {$message}</p>\n";
    }
}

/**
 * Verifica requisitos do sistema
 */
function checkRequirements() {
    printMessage("Verificando requisitos do sistema...");
    
    $errors = [];
    $warnings = [];
    
    // Verifica versão do PHP
    if (version_compare(PHP_VERSION, '7.4.0', '<')) {
        $errors[] = "PHP 7.4 ou superior é necessário. Versão atual: " . PHP_VERSION;
    } else {
        printMessage("✓ PHP " . PHP_VERSION . " OK");
    }
    
    // Verifica extensões necessárias
    $requiredExtensions = ['json', 'mbstring', 'openssl'];
    foreach ($requiredExtensions as $ext) {
        if (!extension_loaded($ext)) {
            $errors[] = "Extensão PHP necessária não encontrada: {$ext}";
        } else {
            printMessage("✓ Extensão {$ext} OK");
        }
    }
    
    // Verifica extensões opcionais
    $optionalExtensions = ['curl', 'ldap'];
    foreach ($optionalExtensions as $ext) {
        if (!extension_loaded($ext)) {
            $warnings[] = "Extensão PHP opcional não encontrada: {$ext} (funcionalidade limitada)";
        } else {
            printMessage("✓ Extensão {$ext} OK");
        }
    }
    
    // Verifica permissões de escrita
    $logDir = SiemConfig::LOG_DIRECTORY;
    if (!is_dir($logDir)) {
        if (!mkdir($logDir, 0755, true)) {
            $errors[] = "Não foi possível criar diretório de logs: {$logDir}";
        }
    }
    
    if (!is_writable($logDir)) {
        $errors[] = "Diretório de logs não é gravável: {$logDir}";
    } else {
        printMessage("✓ Diretório de logs gravável: {$logDir}");
    }
    
    // Mostra avisos
    foreach ($warnings as $warning) {
        printMessage($warning, 'WARNING');
    }
    
    // Mostra erros e para se houver algum
    if (!empty($errors)) {
        foreach ($errors as $error) {
            printMessage($error, 'ERROR');
        }
        printMessage("Setup interrompido devido a erros. Corrija os problemas acima e execute novamente.", 'ERROR');
        return false;
    }
    
    printMessage("Todos os requisitos foram atendidos!", 'SUCCESS');
    return true;
}

/**
 * Cria estrutura de diretórios
 */
function createDirectories() {
    printMessage("Criando estrutura de diretórios...");
    
    $directories = [
        SiemConfig::LOG_DIRECTORY,
        SiemConfig::LOG_DIRECTORY . 'archive' . DIRECTORY_SEPARATOR,
        SiemConfig::LOG_DIRECTORY . 'reports' . DIRECTORY_SEPARATOR
    ];
    
    foreach ($directories as $dir) {
        if (!is_dir($dir)) {
            if (mkdir($dir, 0755, true)) {
                printMessage("✓ Criado diretório: {$dir}");
            } else {
                printMessage("✗ Erro ao criar diretório: {$dir}", 'ERROR');
                return false;
            }
        } else {
            printMessage("✓ Diretório já existe: {$dir}");
        }
    }
    
    return true;
}

/**
 * Cria arquivos de log iniciais
 */
function createLogFiles() {
    printMessage("Criando arquivos de log iniciais...");
    
    $logFiles = [
        SiemConfig::SIEM_LOG_FILE,
        SiemConfig::SECURITY_LOG_FILE,
        SiemConfig::ANOMALY_LOG_FILE,
        SiemConfig::ALERTS_LOG_FILE
    ];
    
    foreach ($logFiles as $logFile) {
        $filePath = SiemConfig::LOG_DIRECTORY . $logFile;
        
        if (!file_exists($filePath)) {
            // Cria arquivo com entrada inicial
            $initialEntry = json_encode([
                'event_id' => 'SETUP_' . uniqid(),
                'timestamp' => date('Y-m-d H:i:s'),
                'event_type' => 'SYSTEM_SETUP',
                'severity' => 'INFO',
                'source_ip' => 'localhost',
                'user_agent' => 'SIEM Setup',
                'username' => 'system',
                'session_id' => 'setup',
                'request_uri' => 'setup',
                'http_method' => 'CLI',
                'referer' => 'setup',
                'details' => [
                    'setup_stage' => 'log_file_creation',
                    'log_file' => $logFile,
                    'description' => 'Arquivo de log criado durante o setup do sistema SIEM'
                ]
            ], JSON_UNESCAPED_UNICODE) . "\n";
            
            if (file_put_contents($filePath, $initialEntry, LOCK_EX)) {
                printMessage("✓ Criado arquivo de log: {$logFile}");
            } else {
                printMessage("✗ Erro ao criar arquivo de log: {$logFile}", 'ERROR');
                return false;
            }
        } else {
            printMessage("✓ Arquivo de log já existe: {$logFile}");
        }
    }
    
    return true;
}

/**
 * Valida configurações
 */
function validateConfiguration() {
    printMessage("Validando configurações...");
    
    $errors = SiemConfigValidator::validate();
    
    if (!empty($errors)) {
        foreach ($errors as $error) {
            printMessage($error, 'ERROR');
        }
        return false;
    }
    
    printMessage("✓ Configurações válidas");
    return true;
}

/**
 * Testa funcionalidades básicas
 */
function testBasicFunctionality() {
    printMessage("Testando funcionalidades básicas...");
    
    try {
        // Testa logger
        require_once 'siem_logger.php';
        $logger = SiemLogger::getInstance();
        
        $eventId = $logger->logSecurityEvent(
            'SETUP_TEST',
            SiemConfig::SEVERITY_INFO,
            [
                'test_type' => 'functionality_test',
                'description' => 'Teste durante setup do sistema SIEM'
            ]
        );
        
        if ($eventId) {
            printMessage("✓ Logger funcionando - Event ID: {$eventId}");
        } else {
            printMessage("✗ Erro no logger", 'ERROR');
            return false;
        }
        
        // Testa detector
        require_once 'siem_detector.php';
        $detector = new SiemAnomalyDetector();
        printMessage("✓ Detector de anomalias carregado");
        
        // Testa alerter
        require_once 'siem_alerts.php';
        $alerter = new SiemAlerter();
        printMessage("✓ Sistema de alertas carregado");
        
        // Testa estatísticas
        $stats = $logger->getEventStatistics(1);
        if (isset($stats['total_events']) && $stats['total_events'] > 0) {
            printMessage("✓ Sistema de estatísticas funcionando - {$stats['total_events']} evento(s) encontrado(s)");
        }
        
    } catch (Exception $e) {
        printMessage("✗ Erro no teste de funcionalidade: " . $e->getMessage(), 'ERROR');
        return false;
    }
    
    return true;
}

/**
 * Cria arquivo de exemplo para integração
 */
function createIntegrationExample() {
    printMessage("Criando exemplo de integração...");
    
    $exampleContent = '<?php
/**
 * Exemplo de integração com o sistema SIEM
 * 
 * Este arquivo demonstra como integrar o SIEM em suas aplicações
 */

// Inclui o middleware do SIEM (detecção automática de ameaças)
require_once __DIR__ . \'/siem_middleware.php\';

// Exemplo 1: Logging manual de evento de segurança
function exemploLogEventoSeguranca() {
    require_once \'siem_logger.php\';
    
    $logger = SiemLogger::getInstance();
    $eventId = $logger->logSecurityEvent(
        \'FILE_ACCESS\',
        SiemConfig::SEVERITY_INFO,
        [
            \'filename\' => \'documento_sensivel.pdf\',
            \'action\' => \'download\',
            \'user_id\' => $_SESSION[\'user_id\'] ?? \'anonymous\'
        ]
    );
    
    echo "Evento registrado com ID: {$eventId}";
}

// Exemplo 2: Verificação manual de padrões suspeitos
function exemploVerificacaoSuspeita($input) {
    require_once \'siem_config.php\';
    
    if (SiemConfig::isSuspiciousPattern($input, \'sql_injection\')) {
        // Log da tentativa
        siemLogThreat(
            SiemConfig::EVENT_SQL_INJECTION,
            SiemConfig::SEVERITY_HIGH,
            [\'payload\' => $input, \'detected_by\' => \'manual_check\']
        );
        
        return false; // Bloqueia processamento
    }
    
    return true; // OK para processar
}

// Exemplo 3: Monitoramento de arquivo específico
function exemploMonitoramentoArquivo() {
    SiemMiddleware::monitorFileAccess(\'arquivo_critico.php\');
}

// Exemplo 4: Análise de anomalias sob demanda
function exemploAnaliseAnomalias() {
    require_once \'siem_detector.php\';
    
    $detector = new SiemAnomalyDetector();
    $anomalias = $detector->analyzeHistoricalData(24); // Últimas 24 horas
    
    if (!empty($anomalias)) {
        echo "Detectadas " . count($anomalias) . " anomalias";
        foreach ($anomalias as $anomalia) {
            echo "- {$anomalia[\'type\']}: {$anomalia[\'description\']}";
        }
    }
}

// Exemplo 5: Envio de alerta customizado
function exemploEnvioAlerta() {
    require_once \'siem_alerts.php\';
    
    $alerter = new SiemAlerter();
    $detection = [
        \'type\' => \'CUSTOM_THREAT\',
        \'severity\' => SiemConfig::SEVERITY_HIGH,
        \'details\' => [
            \'description\' => \'Atividade suspeita detectada manualmente\',
            \'location\' => \'funcao_customizada\',
            \'timestamp\' => date(\'Y-m-d H:i:s\')
        ]
    ];
    
    $alerter->sendAlert($detection);
}
';
    
    $exampleFile = $baseDir . DIRECTORY_SEPARATOR . 'siem_integration_example.php';
    
    if (file_put_contents($exampleFile, $exampleContent)) {
        printMessage("✓ Criado arquivo de exemplo: siem_integration_example.php");
    } else {
        printMessage("✗ Erro ao criar arquivo de exemplo", 'WARNING');
    }
}

/**
 * Gera relatório de configuração
 */
function generateSetupReport() {
    printMessage("Gerando relatório de configuração...");
    
    $report = "RELATÓRIO DE CONFIGURAÇÃO DO SISTEMA SIEM\n";
    $report .= str_repeat("=", 50) . "\n\n";
    $report .= "Data do Setup: " . date('Y-m-d H:i:s') . "\n";
    $report .= "Versão do PHP: " . PHP_VERSION . "\n";
    $report .= "Sistema Operacional: " . PHP_OS . "\n";
    $report .= "Diretório de Logs: " . SiemConfig::LOG_DIRECTORY . "\n\n";
    
    $report .= "CONFIGURAÇÕES PRINCIPAIS:\n";
    $report .= str_repeat("-", 25) . "\n";
    $report .= "• Retenção de Logs: " . SiemConfig::LOG_RETENTION_DAYS . " dias\n";
    $report .= "• Max Falhas de Login/Min: " . SiemConfig::MAX_LOGIN_FAILURES_PER_MINUTE . "\n";
    $report .= "• Max Falhas de Login/Hora: " . SiemConfig::MAX_LOGIN_FAILURES_PER_HOUR . "\n";
    $report .= "• Alertas por Email: " . (SiemConfig::ALERT_EMAIL_ENABLED ? 'Habilitado' : 'Desabilitado') . "\n";
    $report .= "• Refresh do Dashboard: " . SiemConfig::DASHBOARD_REFRESH_INTERVAL . " segundos\n\n";
    
    $report .= "ARQUIVOS CRIADOS:\n";
    $report .= str_repeat("-", 16) . "\n";
    $report .= "• siem_config.php - Configurações do sistema\n";
    $report .= "• siem_logger.php - Sistema de logging\n";
    $report .= "• siem_detector.php - Detector de anomalias\n";
    $report .= "• siem_alerts.php - Sistema de alertas\n";
    $report .= "• siem_dashboard.php - Dashboard web\n";
    $report .= "• siem_middleware.php - Middleware de segurança\n";
    $report .= "• siem_setup.php - Script de setup (este arquivo)\n";
    $report .= "• siem_integration_example.php - Exemplos de integração\n\n";
    
    $report .= "PRÓXIMOS PASSOS:\n";
    $report .= str_repeat("-", 15) . "\n";
    $report .= "1. Configure as variáveis de ambiente ou arquivo .env para alertas\n";
    $report .= "2. Adicione 'require_once \"siem_middleware.php\";' nos seus scripts PHP\n";
    $report .= "3. Acesse o dashboard em: http://seudominio/siem_dashboard.php\n";
    $report .= "4. Configure um cron job para limpeza automática de logs\n";
    $report .= "5. Teste o sistema com algumas ações e verifique os logs\n\n";
    
    $report .= "COMANDOS ÚTEIS:\n";
    $report .= str_repeat("-", 15) . "\n";
    $report .= "# Verificar logs de segurança\n";
    $report .= "tail -f " . SiemConfig::LOG_DIRECTORY . "security_events.log\n\n";
    $report .= "# Verificar alertas\n";
    $report .= "tail -f " . SiemConfig::LOG_DIRECTORY . "alerts.log\n\n";
    $report .= "# Limpeza manual de logs antigos\n";
    $report .= "php -c 'require \"siem_logger.php\"; SiemLogger::getInstance()->cleanOldLogs();'\n\n";
    
    $reportFile = SiemConfig::LOG_DIRECTORY . 'setup_report.txt';
    
    if (file_put_contents($reportFile, $report)) {
        printMessage("✓ Relatório salvo em: {$reportFile}");
        
        if (php_sapi_name() === 'cli') {
            echo "\n" . $report;
        }
    } else {
        printMessage("✗ Erro ao salvar relatório", 'WARNING');
    }
}

/**
 * Execução principal do setup
 */
function runSetup() {
    printMessage("Iniciando setup do sistema SIEM...", 'SUCCESS');
    
    // Verifica requisitos
    if (!checkRequirements()) {
        return false;
    }
    
    // Cria diretórios
    if (!createDirectories()) {
        return false;
    }
    
    // Cria arquivos de log
    if (!createLogFiles()) {
        return false;
    }
    
    // Valida configurações
    if (!validateConfiguration()) {
        return false;
    }
    
    // Testa funcionalidades
    if (!testBasicFunctionality()) {
        return false;
    }
    
    // Cria exemplo de integração
    createIntegrationExample();
    
    // Gera relatório
    generateSetupReport();
    
    printMessage("Setup concluído com sucesso! ✓", 'SUCCESS');
    printMessage("O sistema SIEM está pronto para uso.", 'SUCCESS');
    
    return true;
}

// Executa setup
if (runSetup()) {
    if (php_sapi_name() !== 'cli') {
        echo "<h2 style='color: green;'>✓ Setup concluído com sucesso!</h2>";
        echo "<p>Acesse o <a href='siem_dashboard.php'>Dashboard SIEM</a> para começar a monitorar.</p>";
    }
} else {
    if (php_sapi_name() !== 'cli') {
        echo "<h2 style='color: red;'>✗ Setup falhou</h2>";
        echo "<p>Verifique as mensagens de erro acima.</p>";
    }
}