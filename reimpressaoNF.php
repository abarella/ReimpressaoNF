<?php
/**
 * Sistema de Reimpressão de Notas Fiscais
 * Conversão do programa Python reimpressaoNF.py para PHP
 */

// Middleware de segurança SIEM
require_once __DIR__ . DIRECTORY_SEPARATOR . 'siem_middleware.php';

// Define encoding UTF-8
mb_internal_encoding('UTF-8');
mb_http_output('UTF-8');

// Função helper para garantir encoding UTF-8 correto em strings
function utf8($str) {
    if (!mb_check_encoding($str, 'UTF-8')) {
        return mb_convert_encoding($str, 'UTF-8', 'ISO-8859-1');
    }
    return $str;
}

// Define header de encoding antes de qualquer output
if (!headers_sent()) {
    header('Content-Type: text/html; charset=UTF-8');
}

// Inicia output buffering para evitar problemas com headers
while (ob_get_level() > 0) {
    ob_end_clean();
}
ob_start(function($buffer) {
    // Garante que o buffer está em UTF-8
    if (!mb_check_encoding($buffer, 'UTF-8')) {
        $buffer = mb_convert_encoding($buffer, 'UTF-8', mb_detect_encoding($buffer));
    }
    return $buffer;
});

// Configurações para evitar que o servidor PHP embutido pare
ini_set('display_errors', '0');
ini_set('log_errors', '1');
error_reporting(E_ALL & ~E_NOTICE & ~E_WARNING);

// Handler de erro personalizado para evitar que o servidor pare
set_error_handler(function($severity, $message, $file, $line) {
    // Log do erro mas não interrompe a execução
    error_log("PHP Error: {$message} in {$file} on line {$line}");
    return true; // Retorna true para indicar que o erro foi tratado
}, E_ALL & ~E_NOTICE & ~E_WARNING);

// Handler de exceções não capturadas
set_exception_handler(function($exception) {
    error_log("Uncaught Exception: " . $exception->getMessage());
    if (ob_get_level() > 0) {
        ob_clean();
    }
    if (!headers_sent()) {
        header('Content-Type: application/json; charset=UTF-8');
    }
    echo json_encode([
        'success' => false,
        'error' => 'Erro interno do servidor'
    ], JSON_UNESCAPED_UNICODE);
    exit;
});

// Handler de shutdown para limpar recursos em caso de erro fatal
register_shutdown_function(function() {
    $error = error_get_last();
    if ($error !== NULL && in_array($error['type'], [E_ERROR, E_CORE_ERROR, E_COMPILE_ERROR, E_PARSE])) {
        error_log("Fatal Error: {$error['message']} in {$error['file']} on line {$error['line']}");
        if (ob_get_level() > 0) {
            ob_clean();
        }
        if (!headers_sent()) {
            header('Content-Type: application/json; charset=UTF-8');
        }
        echo json_encode([
            'success' => false,
            'error' => 'Erro fatal no servidor'
        ], JSON_UNESCAPED_UNICODE);
    }
});

// Carrega configurações do banco de dados de forma segura
// As credenciais são carregadas de variáveis de ambiente ou arquivo .env
require_once __DIR__ . DIRECTORY_SEPARATOR . 'config.php';

// Carrega sistema de autenticação
require_once __DIR__ . DIRECTORY_SEPARATOR . 'auth.php';

// Processa logout se solicitado
if (isset($_GET['logout']) && $_GET['logout'] === '1') {
    fazerLogout();
    header('Location: login.php?logout=1');
    exit;
}

// Requer autenticação para TODAS as requisições (incluindo AJAX)
// Apenas a página de login não requer autenticação
requerAutenticacao();

// Impressoras disponíveis
$IMPRESSORAS = [
    "PDF" => "\\\\10.0.22.51\\pdf_entrada",
    "Impressora CTER" => "\\\\10.0.22.51\\CTR",
    "Impressora ENTRADA" => "\\\\10.0.22.51\\ENTRADA",
    "Impressora IMPORTAÇÃO" => "\\\\10.0.22.51\\IMPORTACAO",
    "Impressora ALMOXARIFADO" => "\\\\10.0.22.51\\PEDRO",
];

/**
 * Conecta ao banco de dados SQL Server
 */
function conectarBanco() {
    // Opções PDO compatíveis com sqlsrv
    // NOTA: PDO::ATTR_TIMEOUT não é suportado pelo driver sqlsrv
    // O timeout deve ser configurado no DSN usando LoginTimeout
    $options = [
        PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION,
        PDO::ATTR_DEFAULT_FETCH_MODE => PDO::FETCH_ASSOC
    ];
    
    // Extrai servidor e porta do DB_SERVER
    // Suporta formatos: "servidor", "servidor,porta", "servidor\instancia,porta"
    $server = DB_SERVER;
    $port = null;
    
    // Verifica se há porta especificada (formato: servidor,porta)
    if (strpos($server, ',') !== false) {
        $parts = explode(',', $server, 2);
        $server = trim($parts[0]);
        $port = trim($parts[1]);
    }
    
    // Se não especificou porta, tenta detectar do formato servidor:porta
    if (!$port && strpos($server, ':') !== false) {
        $parts = explode(':', $server, 2);
        $server = trim($parts[0]);
        $port = trim($parts[1]);
    }
    
    // Porta padrão do SQL Server
    if (!$port) {
        $port = '1433';
    }
    
    // Prepara string do servidor com porta para TCP/IP
    $serverWithPort = $server . ',' . $port;
    
    // Tenta diferentes configurações de conexão
    // LoginTimeout reduzido para 5 segundos para evitar timeouts longos
    // Prioriza conexões SEM TrustServerCertificate primeiro
    $configs = [
        // Configuração 1: TCP/IP com porta, SEM TrustServerCertificate (mais rápida)
        "sqlsrv:Server={$serverWithPort};Database=" . DB_DATABASE . ";LoginTimeout=5",
        
        // Configuração 2: Servidor original SEM TrustServerCertificate
        "sqlsrv:Server=" . DB_SERVER . ";Database=" . DB_DATABASE . ";LoginTimeout=5",
        
        // Configuração 3: TCP/IP com porta, sem criptografia, SEM TrustServerCertificate
        "sqlsrv:Server={$serverWithPort};Database=" . DB_DATABASE . ";Encrypt=no;LoginTimeout=5",
        
        // Configuração 4: TCP/IP apenas com servidor (sem porta explícita), SEM TrustServerCertificate
        "sqlsrv:Server={$server};Database=" . DB_DATABASE . ";LoginTimeout=5",
        
        // Configuração 5: TCP/IP com porta, COM TrustServerCertificate (fallback)
        "sqlsrv:Server={$serverWithPort};Database=" . DB_DATABASE . ";TrustServerCertificate=yes;Encrypt=no;LoginTimeout=5",
        
        // Configuração 6: Servidor original COM TrustServerCertificate (fallback)
        "sqlsrv:Server=" . DB_SERVER . ";Database=" . DB_DATABASE . ";TrustServerCertificate=yes;Encrypt=no;LoginTimeout=5",
        
        // Configuração 7: TCP/IP com porta, COM TrustServerCertificate (fallback)
        "sqlsrv:Server={$serverWithPort};Database=" . DB_DATABASE . ";TrustServerCertificate=yes;LoginTimeout=5",
    ];
    
    $errors = [];
    foreach ($configs as $index => $dsn) {
        try {
            // Define timeout de conexão mais curto para evitar esperas longas
            $pdo = new PDO($dsn, DB_USER, DB_PASSWORD, $options);
            
            // Testa a conexão executando uma query simples com timeout
            $stmt = $pdo->query("SELECT 1");
            if ($stmt) {
                return $pdo;
            }
        } catch (PDOException $e) {
            $errorMsg = $e->getMessage();
            // Não adiciona timeout como erro crítico, apenas continua tentando
            if (strpos($errorMsg, 'timeout') === false && strpos($errorMsg, 'timed out') === false) {
                $errors[] = "Tentativa " . ($index + 1) . ": " . $errorMsg;
            }
            continue;
        }
    }
    
    // Se todas as tentativas falharam, monta mensagem de erro detalhada
    $errorMessage = "Erro ao conectar ao banco de dados após tentar " . count($configs) . " configurações diferentes.\n";
    $errorMessage .= "Servidor configurado: " . DB_SERVER . "\n";
    $errorMessage .= "Banco de dados: " . DB_DATABASE . "\n";
    $errorMessage .= "Últimas tentativas:\n" . implode("\n", array_slice($errors, -3));
    
    throw new Exception($errorMessage);
}

/**
 * Traduz código de erro do robocopy para descrição legível
 */
function traduzirErroRobocopy($codigo) {
    $erros = [
        0 => 'Nenhum erro',
        1 => 'Um ou mais arquivos foram copiados com sucesso',
        2 => 'Alguns arquivos extras foram encontrados no destino',
        3 => 'Alguns arquivos foram copiados e alguns arquivos extras foram encontrados',
        4 => 'Alguns arquivos foram ignorados',
        5 => 'Alguns arquivos foram copiados e alguns ignorados',
        6 => 'Arquivos extras e alguns ignorados',
        7 => 'Arquivos copiados, extras e ignorados',
        8 => 'Vários arquivos não foram copiados',
        16 => 'ERRO: Acesso Negado (Permissão insuficiente)',
    ];
    
    if (isset($erros[$codigo])) {
        return $erros[$codigo];
    }
    
    if ($codigo >= 8 && $codigo < 16) {
        return "Erro: {$codigo} - Um ou mais arquivos não foram copiados";
    }
    
    if ($codigo >= 16) {
        return "Erro: {$codigo} - Erro grave (possivelmente permissão ou acesso negado)";
    }
    
    return "Código desconhecido: {$codigo}";
}

/**
 * Obtém informações do usuário atual do sistema
 */
function obterUsuarioSistema() {
    if (php_sapi_name() === 'cli') {
        return [
            'usuario' => get_current_user() ?: 'sistema',
            'usuario_windows' => getenv('USERNAME') ?: getenv('USER') ?: 'desconhecido',
            'contexto' => 'CLI'
        ];
    } else {
        // Em ambiente web/IIS
        $usuario_php = get_current_user() ?: 'desconhecido';
        $usuario_windows = getenv('USERNAME') ?: 'IUSR';
        
        return [
            'usuario' => $usuario_php,
            'usuario_windows' => $usuario_windows,
            'contexto' => 'WEB/IIS',
            'app_pool' => getenv('APP_POOL_ID') ?: 'desconhecido'
        ];
    }
}

/**
 * Registra eventos de impressão no log
 */
function registrarEventoImpressao($evento, $detalhes = []) {
    $timestamp = date('Y-m-d H:i:s');
    
    // Tenta obter usuário, mas não falha se não houver sessão (CLI)
    $username = 'desconhecido';
    $ip = 'desconhecido';
    
    if (php_sapi_name() !== 'cli') {
        // Apenas tenta obter usuário se não for CLI
        try {
            $usuario = obterUsuario();
            $username = $usuario ? ($usuario['displayName'] ?? $usuario['username'] ?? 'desconhecido') : 'desconhecido';
            $ip = $_SERVER['REMOTE_ADDR'] ?? 'desconhecido';
        } catch (Exception $e) {
            // Ignora erros ao obter usuário
            $username = 'erro_obter_usuario';
        }
    } else {
        // Em CLI, usa informações do sistema
        $username = get_current_user() ?: 'sistema';
        $ip = 'CLI';
    }
    
    // Obtém informações do usuário do sistema
    $infoSistema = obterUsuarioSistema();
    
    // Monta mensagem de log
    $logMessage = "[{$timestamp}] IMPRESSAO - Evento: {$evento} - Usuario: {$username} - IP: {$ip}";
    $logMessage .= " - UsuarioSistema: {$infoSistema['usuario_windows']} - Contexto: {$infoSistema['contexto']}";
    
    // Adiciona detalhes se fornecidos
    if (!empty($detalhes)) {
        $detalhesStr = [];
        foreach ($detalhes as $chave => $valor) {
            // Escapa valores que podem conter caracteres especiais
            $valorEscapado = is_string($valor) ? str_replace(["\r", "\n"], ['\\r', '\\n'], $valor) : $valor;
            
            // Se for erro_level e for um código numérico, adiciona tradução
            if ($chave === 'erro_level' && is_numeric($valor) && $valor >= 8) {
                $traducao = traduzirErroRobocopy((int)$valor);
                $detalhesStr[] = "{$chave}: {$valorEscapado} ({$traducao})";
            } else {
                $detalhesStr[] = "{$chave}: {$valorEscapado}";
            }
        }
        $logMessage .= " - " . implode(" | ", $detalhesStr);
    }
    
    $logMessage .= PHP_EOL;
    
    // Cria diretório de logs se não existir
    $logDir = __DIR__ . DIRECTORY_SEPARATOR . 'logs';
    if (!is_dir($logDir)) {
        @mkdir($logDir, 0755, true);
    }
    
    $logFile = $logDir . DIRECTORY_SEPARATOR . 'impressao.log';
    @file_put_contents($logFile, $logMessage, FILE_APPEND | LOCK_EX);
}

/**
 * Busca número da nota antiga por lote
 */
function buscar_numero_nota_antiga($lote, $pdo) {
    try {
        $stmt = $pdo->prepare("SELECT no_nota FROM ipenfat..notafis WHERE val_total > 1394.03 AND MV100CHV = ?");
        $stmt->execute([$lote]);
        $row = $stmt->fetch(PDO::FETCH_ASSOC);
        return $row ? $row['no_nota'] : null;
    } catch (PDOException $e) {
        throw new Exception("Erro ao buscar nota antiga: " . $e->getMessage());
    }
}

/**
 * Busca número da nota antiga por remessa
 */
function buscar_numero_nota_antiga_remessa($lote, $pdo) {
    try {
        $stmt = $pdo->prepare("SELECT no_nota FROM ipenfat..notafis WHERE val_total = 1394.03 AND MV100CHV = ?");
        $stmt->execute([$lote]);
        $row = $stmt->fetch(PDO::FETCH_ASSOC);
        return $row ? $row['no_nota'] : null;
    } catch (PDOException $e) {
        throw new Exception("Erro ao buscar nota antiga remessa: " . $e->getMessage());
    }
}

/**
 * Busca número da nota por lote
 */
function buscar_numero_nota_por_lote($lote, $pdo) {
    try {
        $stmt = $pdo->prepare("SELECT p110fisc FROM vendaspelicano.dbo.tcacp110 WHERE p110chve = ?");
        $stmt->execute([$lote]);
        $row = $stmt->fetch(PDO::FETCH_ASSOC);
        return $row ? $row['p110fisc'] : null;
    } catch (PDOException $e) {
        throw new Exception("Erro ao buscar nota por lote: " . $e->getMessage());
    }
}

/**
 * Busca número da nota por lote remessa
 */
function buscar_numero_nota_por_lote_remessa($loteR, $pdo) {
    try {
        $stmt = $pdo->prepare("SELECT p110fisc FROM vendaspelicano.dbo.tcacp110 WHERE p110lotekt = ?");
        $stmt->execute([$loteR]);
        $row = $stmt->fetch(PDO::FETCH_ASSOC);
        return $row ? $row['p110fisc'] : null;
    } catch (PDOException $e) {
        throw new Exception("Erro ao buscar nota por lote remessa: " . $e->getMessage());
    }
}

/**
 * Busca o emissor da nota
 */
function buscar_emissor($numero_nota, $pdo) {
    try {
        $stmt = $pdo->prepare("SELECT emissor = ISNULL(emissor, '') FROM ipenfat.dbo.notafis WHERE no_nota = ?");
        $stmt->execute([$numero_nota]);
        $row = $stmt->fetch(PDO::FETCH_ASSOC);
        return $row ? $row['emissor'] : "";
    } catch (PDOException $e) {
        throw new Exception("Erro ao buscar emissor: " . $e->getMessage());
    }
}

/**
 * Processa a requisição AJAX para buscar nota
 */
if (isset($_POST['acao']) && $_POST['acao'] === 'buscar_nota') {
    // Valida token CSRF
    requerCSRF();
    
    // Limpa qualquer output anterior
    if (ob_get_level() > 0) {
        ob_clean();
    }
    
    header('Content-Type: application/json; charset=UTF-8');
    
    $pdo = null;
    $resposta = null;
    
    try {
        $opcao = $_POST['opcao'] ?? '';
        $entrada = trim($_POST['entrada'] ?? '');
        
        if (empty($entrada) || !in_array($opcao, ['2', '3'])) {
            $resposta = json_encode(['success' => false, 'nota' => null], JSON_UNESCAPED_UNICODE);
        } else {
            $pdo = conectarBanco();
            
            if ($opcao == '2') {
                $numero_nota = buscar_numero_nota_antiga($entrada, $pdo);
            } elseif ($opcao == '3') {
                $numero_nota = buscar_numero_nota_antiga_remessa($entrada, $pdo);
            } else {
                $numero_nota = null;
            }
            
            $resposta = json_encode(['success' => true, 'nota' => $numero_nota], JSON_UNESCAPED_UNICODE);
        }
    } catch (Exception $e) {
        $resposta = json_encode(['success' => false, 'error' => $e->getMessage()], JSON_UNESCAPED_UNICODE);
    } finally {
        // Fecha conexão
        if ($pdo) {
            $pdo = null;
        }
        
        // Envia resposta
        if ($resposta) {
            // Limpa qualquer output anterior antes de enviar JSON
            while (ob_get_level() > 0) {
                ob_end_clean();
            }
            echo $resposta;
            flush();
        }
    }
    exit;
}

/**
 * Processa a execução principal
 */
if (isset($_POST['acao']) && $_POST['acao'] === 'executar') {
    // Valida token CSRF
    requerCSRF();
    
    // Define timeout máximo de 2 minutos para evitar travamento
    set_time_limit(120);
    ini_set('max_execution_time', 120);
    
    // Limpa qualquer output anterior
    if (ob_get_level() > 0) {
        ob_clean();
    }
    
    header('Content-Type: application/json; charset=UTF-8');
    
    $pdo = null;
    $stmt = null;
    $arquivo = null;
    
    try {
        $opcao = $_POST['opcao'] ?? '';
        $entrada = trim($_POST['entrada'] ?? '');
        $nome_impressora = $_POST['impressora'] ?? '';
        $tipo_cr1 = $_POST['tipo_cr1'] ?? '1';
        
        global $IMPRESSORAS;
        $destino_impressora = $IMPRESSORAS[$nome_impressora] ?? null;
        
        if (empty($entrada)) {
            throw new Exception("Campo obrigatório vazio.");
        }
        
        if (!$destino_impressora) {
            throw new Exception("Selecione uma impressora válida.");
        }
        
        $pdo = conectarBanco();
        
        // Determina número da nota e função conforme opção
        $numero_nota = null;
        $nome_funcao = '';
        $serie = '1';
        
        switch ($opcao) {
            case '1':
                $numero_nota = $entrada;
                $nome_funcao = "dbo.teste_nfe_NET";
                $serie = "1";
                break;
            case '2':
                $numero_nota = buscar_numero_nota_por_lote($entrada, $pdo);
                $nome_funcao = "dbo.teste_nfe_NET";
                $serie = "1";
                break;
            case '3':
                $numero_nota = buscar_numero_nota_por_lote_remessa($entrada, $pdo);
                $nome_funcao = "dbo.teste_nfe_geral";
                $serie = "1";
                break;
            case '4':
                $numero_nota = $entrada;
                $nome_funcao = "dbo.teste_nfe_CTR";
                $serie = "1";
                break;
            case '5':
                $numero_nota = $entrada;
                $nome_funcao = "dbo.teste_nfe_geral";
                $serie = "1";
                break;
            case '6':
                $numero_nota = $entrada;
                $nome_funcao = "dbo.teste_nfe_geral";
                $serie = "2";
                break;
            default:
                throw new Exception("Opção inválida.");
        }
        
        if (!$numero_nota) {
            if ($opcao == '2' || $opcao == '3') {
                throw new Exception("Lote não encontrado: {$entrada}.");
            } else {
                throw new Exception("Nota não encontrada para entrada: {$entrada}.");
            }
        }
        
        $emissor = strtoupper(buscar_emissor($numero_nota, $pdo));
        
        // Define tipo conforme emissor
        if ($emissor == "CR1") {
            $tipo = $tipo_cr1;
        } elseif (in_array($emissor, ["ALM", "IMP"])) {
            $tipo = "0";
        } elseif ($emissor == "CTR") {
            $tipo = "0";
        } else {
            $tipo = "0";
        }
        
        $data_hoje = date('d/m/Y');
        
        // Gera um nome de arquivo único para evitar conflitos com múltiplos usuários
        $nome_arquivo_unico = 'nota_' . time() . '_' . uniqid() . '.txt';
        $nome_arquivo_destino = 'nota.txt'; // Nome final na impressora
        
        // Executa a função do banco
        $query = "SELECT seq, texto FROM {$nome_funcao}(?, ?, ?, ?)";
        $stmt = $pdo->prepare($query);
        $stmt->execute([$numero_nota, $data_hoje, $tipo, $serie]);
        
        // Escreve o arquivo com encoding ANSI (como no Python original)
        $arquivo = fopen($nome_arquivo_unico, 'w');
        if (!$arquivo) {
            throw new Exception("Erro ao criar arquivo.");
        }
        
        try {
            while ($row = $stmt->fetch(PDO::FETCH_ASSOC)) {
                // Converte de UTF-8 para Windows-1252 (ANSI) para manter compatibilidade
                $texto = mb_convert_encoding($row['texto'], 'Windows-1252', 'UTF-8');
                fwrite($arquivo, $texto . "\n");
            }
        } finally {
            if ($arquivo) {
                fclose($arquivo);
                $arquivo = null;
            }
            // Fecha o statement após ler todos os dados
            if ($stmt) {
                $stmt->closeCursor();
                $stmt = null;
            }
        }
        
        // Obtém o caminho absoluto do arquivo
        $caminho_arquivo = realpath($nome_arquivo_unico);
        if (!$caminho_arquivo) {
            $caminho_arquivo = __DIR__ . DIRECTORY_SEPARATOR . $nome_arquivo_unico;
        }
        
        // Verifica se o arquivo foi criado
        if (!file_exists($caminho_arquivo)) {
            registrarEventoImpressao('ERRO_ARQUIVO_NAO_ENCONTRADO', [
                'numero_nota' => $numero_nota,
                'caminho_arquivo' => $caminho_arquivo,
                'nome_arquivo_unico' => $nome_arquivo_unico
            ]);
            throw new Exception("Arquivo não encontrado: {$caminho_arquivo}");
        }
        
        // Garante que o arquivo nao tenha atributos de somente leitura
        // Isso facilita a remocao posterior
        if (strtoupper(substr(PHP_OS, 0, 3)) === 'WIN') {
            @chmod($caminho_arquivo, 0666);
            $caminho_escaped = escapeshellarg($caminho_arquivo);
            @exec("attrib -r -s -h {$caminho_escaped} >nul 2>&1");
        } else {
            @chmod($caminho_arquivo, 0666);
        }
        
        // Log: arquivo criado com sucesso
        $tamanho_arquivo = filesize($caminho_arquivo);
        registrarEventoImpressao('ARQUIVO_CRIADO', [
            'numero_nota' => $numero_nota,
            'caminho_arquivo' => $caminho_arquivo,
            'tamanho_bytes' => $tamanho_arquivo,
            'nome_arquivo_unico' => $nome_arquivo_unico
        ]);
        
        // Validação de segurança: verifica se a impressora está na lista permitida
        global $IMPRESSORAS;
        if (!array_key_exists($nome_impressora, $IMPRESSORAS)) {
            registrarEventoImpressao('ERRO_IMPRESSORA_INVALIDA', [
                'numero_nota' => $numero_nota,
                'impressora_solicitada' => $nome_impressora
            ]);
            throw new Exception("Impressora inválida selecionada.");
        }
        
        // IMPORTANTE: O destino é uma IMPRESSORA de rede, não um compartilhamento de arquivos
        // Para impressoras, simplesmente copiamos o arquivo diretamente para o caminho da impressora
        // O Windows trata isso como uma fila de impressão - não precisa renomear
        $destino_impressora_final = rtrim($destino_impressora, '\\');
        
        // Log: início do processo de envio para impressora
        registrarEventoImpressao('INICIO_ENVIO_IMPRESSORA', [
            'numero_nota' => $numero_nota,
            'impressora' => $nome_impressora,
            'destino_impressora' => $destino_impressora,
            'arquivo_origem' => $caminho_arquivo,
            'tipo_destino' => 'IMPRESSORA_NETWORK',
            'nota' => 'Enviando arquivo diretamente para fila de impressão'
        ]);
        
        // Fecha conexão do banco ANTES de iniciar cópia
        if (isset($stmt) && $stmt) {
            @$stmt->closeCursor();
            $stmt = null;
        }
        if (isset($pdo) && $pdo) {
            $pdo = null;
        }
        
        // Executa cópia de forma síncrona (espera completar)
        // Isso garante que podemos limpar os arquivos imediatamente após o sucesso
        $destino_impressora_final = rtrim($destino_impressora, '\\');
        $caminho_arquivo_escaped_cmd = escapeshellarg($caminho_arquivo);
        $destino_impressora_escaped_cmd = escapeshellarg($destino_impressora_final);
        
        // Tenta copiar usando comando COPY do Windows
        $comando_copy = "copy /B {$caminho_arquivo_escaped_cmd} {$destino_impressora_escaped_cmd} 2>&1";
        $output_copy = [];
        $return_code_copy = 0;
        @exec($comando_copy, $output_copy, $return_code_copy);
        
        // Para impressoras, código 0 ou 1 indica sucesso (1 = arquivo enviado para fila)
        $sucesso_copy = ($return_code_copy <= 1);
        
        if (!$sucesso_copy) {
            // Fallback: tenta usar PHP copy
            registrarEventoImpressao('TENTATIVA_PHP_COPY', [
                'numero_nota' => $numero_nota,
                'impressora' => $nome_impressora,
                'destino_impressora' => $destino_impressora_final,
                'arquivo_origem' => $caminho_arquivo,
                'erro_copy' => $return_code_copy
            ]);
            
            $sucesso_php = @copy($caminho_arquivo, $destino_impressora_final);
            
            if (!$sucesso_php) {
                registrarEventoImpressao('ERRO_ENVIO_IMPRESSORA', [
                    'numero_nota' => $numero_nota,
                    'impressora' => $nome_impressora,
                    'destino_impressora' => $destino_impressora_final,
                    'arquivo_origem' => $caminho_arquivo,
                    'erro_copy' => $return_code_copy,
                    'erro_php' => 'copy() falhou'
                ]);
                throw new Exception("Erro ao enviar arquivo para impressora. Código de erro: {$return_code_copy}");
            } else {
                registrarEventoImpressao('SUCESSO_PHP_COPY', [
                    'numero_nota' => $numero_nota,
                    'impressora' => $nome_impressora,
                    'destino_impressora' => $destino_impressora_final,
                    'arquivo_origem' => $caminho_arquivo,
                    'metodo' => 'php_copy'
                ]);
            }
        } else {
            registrarEventoImpressao('SUCESSO_COPY_IMPRESSORA', [
                'numero_nota' => $numero_nota,
                'impressora' => $nome_impressora,
                'destino_impressora' => $destino_impressora_final,
                'arquivo_origem' => $caminho_arquivo,
                'metodo' => 'copy',
                'erro_level' => $return_code_copy
            ]);
        }
        
        // REMOVE ARQUIVOS TEMPORÁRIOS IMEDIATAMENTE após sucesso
        $arquivos_removidos = [];
        
        // Remove atributos e deleta arquivo .txt
        if (file_exists($caminho_arquivo)) {
            if (strtoupper(substr(PHP_OS, 0, 3)) === 'WIN') {
                $caminho_escaped = escapeshellarg($caminho_arquivo);
                @exec("attrib -r -s -h {$caminho_escaped} >nul 2>&1");
            }
            @chmod($caminho_arquivo, 0666);
            
            // Tenta deletar várias vezes
            $tentativas = 0;
            while (file_exists($caminho_arquivo) && $tentativas < 5) {
                @unlink($caminho_arquivo);
                if (file_exists($caminho_arquivo)) {
                    usleep(200000); // 0.2 segundos
                }
                $tentativas++;
            }
            
            if (!file_exists($caminho_arquivo)) {
                $arquivos_removidos[] = basename($caminho_arquivo);
                registrarEventoImpressao('ARQUIVO_REMOVIDO', [
                    'numero_nota' => $numero_nota,
                    'arquivo' => basename($caminho_arquivo),
                    'tentativas' => $tentativas
                ]);
            }
        }
        
        // Prepara resposta de sucesso
        $mensagem_sucesso = "✓ Nota Fiscal {$numero_nota} processada com sucesso!\n";
        $mensagem_sucesso .= "Arquivo enviado para a impressora: {$nome_impressora}";
        
        $resposta = json_encode([
            'success' => true,
            'message' => $mensagem_sucesso,
            'numero_nota' => $numero_nota
        ], JSON_UNESCAPED_UNICODE);
        
        // Envia resposta após limpeza
        // Limpa qualquer output anterior antes de enviar JSON
        try {
            while (ob_get_level() > 0) {
                ob_end_clean();
            }
        } catch (Exception $e) {
            // Ignora erros ao limpar buffer
        }
        
        // Envia resposta
        echo $resposta;
        
        // Força o envio da resposta
        if (ob_get_level() > 0) {
            ob_end_flush();
        }
        flush();
        
        // Arquivos temporarios ja foram removidos acima
        // Nao precisa mais de processo batch em background
        
    } catch (Exception $e) {
        // Log do erro
        $numero_nota_log = isset($numero_nota) ? $numero_nota : 'N/A';
        $nome_impressora_log = isset($nome_impressora) ? $nome_impressora : 'N/A';
        registrarEventoImpressao('ERRO_EXECUCAO', [
            'numero_nota' => $numero_nota_log,
            'impressora' => $nome_impressora_log,
            'erro' => $e->getMessage(),
            'arquivo' => $e->getFile(),
            'linha' => $e->getLine()
        ]);
        
        try {
            $resposta = json_encode([
                'success' => false,
                'error' => $e->getMessage()
            ], JSON_UNESCAPED_UNICODE);
        } catch (Exception $jsonError) {
            // Se houver erro ao codificar JSON, cria resposta simples
            $resposta = json_encode([
                'success' => false,
                'error' => 'Erro ao processar requisição: ' . $e->getMessage()
            ], JSON_UNESCAPED_UNICODE | JSON_PARTIAL_OUTPUT_ON_ERROR);
        }
        
        // Envia resposta de erro imediatamente
        try {
            while (ob_get_level() > 0) {
                ob_end_clean();
            }
        } catch (Exception $e) {
            // Ignora erros ao limpar buffer
        }
        
        echo $resposta;
        flush();
        
        if (function_exists('fastcgi_finish_request')) {
            @fastcgi_finish_request();
        }
    } catch (Throwable $e) {
        // Captura qualquer erro fatal ou throwable
        try {
            $resposta = json_encode([
                'success' => false,
                'error' => 'Erro fatal: ' . $e->getMessage()
            ], JSON_UNESCAPED_UNICODE);
        } catch (Exception $jsonError) {
            $resposta = '{"success":false,"error":"Erro ao processar requisição"}';
        }
        
        // Envia resposta de erro imediatamente
        try {
            while (ob_get_level() > 0) {
                ob_end_clean();
            }
        } catch (Exception $e) {
            // Ignora erros ao limpar buffer
        }
        
        echo $resposta;
        flush();
        
        if (function_exists('fastcgi_finish_request')) {
            @fastcgi_finish_request();
        }
    } finally {
        // Fecha recursos (apenas se ainda não foram fechados)
        try {
            if (isset($stmt) && $stmt) {
                @$stmt->closeCursor();
            }
            if (isset($pdo) && $pdo) {
                $pdo = null;
            }
        } catch (Exception $e) {
            // Ignora erros ao fechar recursos
        }
    }
    exit;
}

// Se não for uma requisição POST, exibe a interface HTML
// Verifica se está sendo executado via web (não incluído)
if (!isset($_POST['acao']) && php_sapi_name() !== 'cli' && isset($_SERVER['REQUEST_METHOD'])) {
    // Limpa qualquer output buffer antes de exibir HTML
    try {
        while (ob_get_level() > 0) {
            ob_end_clean();
        }
    } catch (Exception $e) {
        // Ignora erros ao limpar buffer
    }
    
    header('Content-Type: text/html; charset=UTF-8');
    
    // Nota: A sessão já foi iniciada em requerAutenticacao() acima
    // gerarTokenCSRF() será chamado no HTML e iniciará a sessão se necessário
}
?>
<!DOCTYPE html>
<html lang="pt-BR">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title><?php echo htmlspecialchars(utf8('Reimpressão de Notas Fiscais'), ENT_QUOTES, 'UTF-8'); ?></title>
    <style>
        * {
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }
        
        body {
            font-family: Arial, sans-serif;
            background-color: #e5e3f4;
            padding: 0;
            margin: 0;
        }
        
        .main-header {
            background: linear-gradient(to bottom, #4a90e2, #357abd);
            padding: 0.5rem 1rem;
            display: flex;
            align-items: center;
            justify-content: space-between;
            box-shadow: 0 0.125rem 0.25rem rgba(0,0,0,0.075);
            position: relative;
        }
        
        .main-header::after {
            content: '';
            position: absolute;
            bottom: 0;
            left: 0;
            right: 0;
            height: 3px;
            background-color: #ff6b35;
        }
        
        .navbar-nav {
            display: flex;
            flex-direction: row;
            list-style: none;
            margin: 0;
            padding: 0;
        }
        
        .applicationname-light {
            position: absolute;
            left: 50%;
            transform: translateX(-50%);
            font-size: 1.25rem;
            font-weight: 600;
            color: white;
            text-shadow: 0 1px 2px rgba(0,0,0,0.2);
            white-space: nowrap;
        }
        
        .brand-link {
            display: flex;
            align-items: center;
            padding: 0.5rem 1rem;
            text-decoration: none;
            color: white;
        }
        
        .brand-image {
            height: 40px;
            width: auto;
            margin-right: 5px;
        }
        
        .brand-text {
            display: flex;
            align-items: center;
        }
        
        .container {
            max-width: 950px;
            margin: 30px auto;
            background-color: white;
            border-radius: 10px;
            padding: 30px;
            box-shadow: 0 2px 10px rgba(0,0,0,0.1);
        }
        
        h1 {
            color: #180a7b;
            text-align: center;
            margin-bottom: 30px;
            font-size: 24px;
        }
        
        .form-group {
            margin-bottom: 20px;
        }
        
        label {
            display: block;
            margin-bottom: 8px;
            font-weight: bold;
            color: #333;
        }
        
        .radio-group {
            display: grid;
            grid-template-columns: 1fr 1fr;
            gap: 8px;
            margin-top: 10px;
        }
        
        .radio-option {
            display: flex;
            align-items: center;
            gap: 8px;
        }
        
        .radio-option input[type="radio"] {
            margin: 0;
        }
        
        input[type="text"],
        select {
            width: 100%;
            padding: 10px;
            border: 1px solid #ddd;
            border-radius: 5px;
            font-size: 14px;
        }
        
        .nota-info {
            color: red;
            font-weight: bold;
            margin-top: 5px;
        }
        
        .tipos-section {
            margin-top: 20px;
            padding: 15px;
            background-color: #f9f9f9;
            border-radius: 5px;
        }
        
        .tipos-section h3 {
            margin-bottom: 10px;
            color: #180a7b;
        }
        
        .tipos-radio {
            display: flex;
            flex-wrap: wrap;
            gap: 15px;
            margin-top: 10px;
        }
        
        .tipos-radio label {
            font-weight: normal;
            margin-bottom: 0;
        }
        
        .buttons {
            display: flex;
            gap: 15px;
            justify-content: center;
            margin-top: 30px;
        }
        
        button {
            padding: 12px 30px;
            font-size: 14px;
            font-weight: bold;
            border: none;
            border-radius: 5px;
            cursor: pointer;
            transition: background-color 0.3s;
        }
        
        .btn-executar {
            background-color: #180a7b;
            color: white;
        }
        
        .btn-executar:hover {
            background-color: #2a1ba8;
        }
        
        .btn-sair {
            background-color: #d32f2f;
            color: white;
        }
        
        .btn-sair:hover {
            background-color: #b71c1c;
        }
        
        .alert {
            padding: 15px;
            margin-bottom: 20px;
            border-radius: 5px;
            display: none;
            white-space: pre-line;
            word-wrap: break-word;
            font-size: 14px;
            line-height: 1.5;
            min-height: 50px;
            box-shadow: 0 2px 4px rgba(0,0,0,0.1);
        }
        
        .alert-success {
            background-color: #d4edda;
            color: #155724;
            border: 1px solid #c3e6cb;
        }
        
        .alert-error {
            background-color: #f8d7da;
            color: #721c24;
            border: 1px solid #f5c6cb;
        }
        
        .alert.show {
            display: block !important;
            animation: fadeIn 0.3s ease-in;
            visibility: visible;
            opacity: 1;
        }
        
        @keyframes fadeIn {
            from { opacity: 0; }
            to { opacity: 1; }
        }
    </style>
</head>
<body>
    <!-- Navbar -->
    <nav class="main-header navbar navbar-expand navbar-light">
        <!-- Left navbar links -->
        <ul class="navbar-nav">
            <li class="nav-item">
                <a href="#" class="brand-link">
                    <?php 
                    $logoPath1 = 'logo_novopP1.png';
                    $logoPath2 = 'logo_novopP2.png';
                    // Verifica arquivos sem bloquear (usa @ para suprimir warnings)
                    $logo1_exists = @file_exists($logoPath1);
                    $logo2_exists = @file_exists($logoPath2);
                    if ($logo1_exists): ?>
                        <img src="<?php echo $logoPath1; ?>" class="brand-image" alt="Logo" />
                        <?php if ($logo2_exists): ?>
                            <img src="<?php echo $logoPath2; ?>" class="brand-image" alt="Logo" />
                        <?php endif; ?>
                    <?php else: ?>
                        <span style="color: white; font-weight: bold; font-size: 1.2rem;">IPEN</span>
                    <?php endif; ?>
                </a>
            </li>
        </ul>
        <div class="applicationname-light flex-grow-1 text-center"><?php echo htmlspecialchars(utf8('Reimpressão de Notas Fiscais'), ENT_QUOTES, 'UTF-8'); ?></div>
        <!-- Right navbar links -->
        <ul class="navbar-nav ml-auto">
            <li class="nav-item" style="display: flex; align-items: center; gap: 10px;">
                <?php 
                $usuario = obterUsuario();
                if ($usuario): 
                ?>
                    <span style="color: white; font-size: 0.9rem;">
                        <?php echo htmlspecialchars($usuario['displayName'] ?? $usuario['username'], ENT_QUOTES, 'UTF-8'); ?>
                    </span>
                    <a href="?logout=1" style="color: white; text-decoration: none; padding: 5px 10px; background-color: rgba(255,255,255,0.2); border-radius: 3px; font-size: 0.85rem;">
                        Sair
                    </a>
                <?php endif; ?>
            </li>
        </ul>
    </nav>
    <!-- /.navbar -->
    
    <div class="container">
        
        <div id="alert" class="alert"></div>
        
        <form id="formImpressao">
            <input type="hidden" name="csrf_token" id="csrf_token" value="<?php echo htmlspecialchars(gerarTokenCSRF(), ENT_QUOTES, 'UTF-8'); ?>">
            <div class="form-group">
                <label><?php echo htmlspecialchars(utf8('Escolha a opção de busca:'), ENT_QUOTES, 'UTF-8'); ?></label>
                <div class="radio-group">
                    <div class="radio-option">
                        <input type="radio" name="opcao" value="1" id="opcao1" checked>
                        <label for="opcao1"><?php echo htmlspecialchars(utf8('Nota Fiscal'), ENT_QUOTES, 'UTF-8'); ?></label>
                    </div>
                    <div class="radio-option">
                        <input type="radio" name="opcao" value="5" id="opcao5">
                        <label for="opcao5">ALM / IMP</label>
                    </div>
                    <div class="radio-option">
                        <input type="radio" name="opcao" value="3" id="opcao3">
                        <label for="opcao3"><?php echo htmlspecialchars(utf8('Lote REMESSA'), ENT_QUOTES, 'UTF-8'); ?></label>
                    </div>
                    <div class="radio-option">
                        <input type="radio" name="opcao" value="4" id="opcao4">
                        <label for="opcao4">CTER</label>
                    </div>
                    <div class="radio-option">
                        <input type="radio" name="opcao" value="2" id="opcao2">
                        <label for="opcao2"><?php echo htmlspecialchars(utf8('Lote GERADOR'), ENT_QUOTES, 'UTF-8'); ?></label>
                    </div>
                    <div class="radio-option">
                        <input type="radio" name="opcao" value="6" id="opcao6">
                        <label for="opcao6"><?php echo htmlspecialchars(utf8('Serviço'), ENT_QUOTES, 'UTF-8'); ?></label>
                    </div>
                </div>
            </div>
            
            <div class="form-group">
                <label for="entrada"><?php echo htmlspecialchars(utf8('Digite o valor:'), ENT_QUOTES, 'UTF-8'); ?></label>
                <input type="text" id="entrada" name="entrada" required>
                <div id="notaInfo" class="nota-info"></div>
            </div>
            
            <div class="form-group">
                <label for="impressora"><?php echo htmlspecialchars(utf8('Selecione a impressora:'), ENT_QUOTES, 'UTF-8'); ?></label>
                <select id="impressora" name="impressora" required>
                    <?php foreach ($IMPRESSORAS as $nome => $caminho): ?>
                        <option value="<?php echo htmlspecialchars($nome, ENT_QUOTES, 'UTF-8'); ?>" <?php echo $nome === 'PDF' ? 'selected' : ''; ?>>
                            <?php echo htmlspecialchars($nome, ENT_QUOTES, 'UTF-8'); ?>
                        </option>
                    <?php endforeach; ?>
                </select>
            </div>
            
            <div class="tipos-section">
                <div class="tipos-radio">
                    <div class="radio-option">
                        <input type="radio" name="tipo_cr1" value="0" id="tipo0" checked>
                        <label for="tipo0"><?php echo htmlspecialchars(utf8('Jogo completo'), ENT_QUOTES, 'UTF-8'); ?></label>
                    </div>
                    <div class="radio-option">
                        <input type="radio" name="tipo_cr1" value="2" id="tipo2">
                        <label for="tipo2"><?php echo htmlspecialchars(utf8('2ª via NF'), ENT_QUOTES, 'UTF-8'); ?></label>
                    </div>
                    <div class="radio-option">
                        <input type="radio" name="tipo_cr1" value="3" id="tipo3">
                        <label for="tipo3">IATA</label>
                    </div>
                    <div class="radio-option">
                        <input type="radio" name="tipo_cr1" value="4" id="tipo4">
                        <label for="tipo4"><?php echo htmlspecialchars(utf8('Guia de Monitoração'), ENT_QUOTES, 'UTF-8'); ?></label>
                    </div>
                    <div class="radio-option">
                        <input type="radio" name="tipo_cr1" value="5" id="tipo5">
                        <label for="tipo5"><?php echo htmlspecialchars(utf8('Ficha de Emergência'), ENT_QUOTES, 'UTF-8'); ?></label>
                    </div>
                    <div class="radio-option">
                        <input type="radio" name="tipo_cr1" value="6" id="tipo6">
                        <label for="tipo6">Boleto</label>
                    </div>
                </div>
            </div>
            
            <div class="buttons">
                <button type="submit" class="btn-executar"><?php echo htmlspecialchars(utf8('Executar'), ENT_QUOTES, 'UTF-8'); ?></button>
                <button type="button" class="btn-sair" onclick="window.close()"><?php echo htmlspecialchars(utf8('SAIR'), ENT_QUOTES, 'UTF-8'); ?></button>
            </div>
        </form>
    </div>
    
    <script>
        const form = document.getElementById('formImpressao');
        const entrada = document.getElementById('entrada');
        const notaInfo = document.getElementById('notaInfo');
        const alertDiv = document.getElementById('alert');
        let timeoutId = null;
        
        // Busca nota quando o campo perder o foco (opções 2 ou 3)
        entrada.addEventListener('blur', function() {
            const opcao = document.querySelector('input[name="opcao"]:checked').value;
            const valor = entrada.value.trim();
            
            if (valor && (opcao === '2' || opcao === '3')) {
                buscarNota();
            } else {
                notaInfo.textContent = '';
            }
        });
        
        // Busca nota quando mudar a opção
        document.querySelectorAll('input[name="opcao"]').forEach(radio => {
            radio.addEventListener('change', function() {
                const valor = entrada.value.trim();
                if (valor && (this.value === '2' || this.value === '3')) {
                    buscarNota();
                } else {
                    notaInfo.textContent = '';
                }
            });
        });
        
        function buscarNota() {
            const opcao = document.querySelector('input[name="opcao"]:checked').value;
            const valor = entrada.value.trim();
            
            if (!valor) {
                notaInfo.textContent = '';
                return;
            }
            
            const formData = new FormData();
            formData.append('acao', 'buscar_nota');
            formData.append('opcao', opcao);
            formData.append('entrada', valor);
            formData.append('csrf_token', document.getElementById('csrf_token').value);
            
            fetch('', {
                method: 'POST',
                body: formData
            })
            .then(response => response.json())
            .then(data => {
                if (data.success && data.nota) {
                    notaInfo.textContent = 'NF: ' + data.nota;
                } else {
                    // Não exibe mensagem para lotes não encontrados
                    notaInfo.textContent = '';
                }
            })
            .catch(error => {
                // Não exibe mensagem de erro para lotes
                notaInfo.textContent = '';
            });
        }
        
        function mostrarAlerta(mensagem, tipo) {
            if (!mensagem) {
                console.error('Mensagem vazia recebida');
                return;
            }
            
            // Limpa qualquer timeout anterior
            if (timeoutId) {
                clearTimeout(timeoutId);
                timeoutId = null;
            }
            
            // Remove a classe 'show' primeiro para garantir animação
            alertDiv.classList.remove('show');
            
            // Aguarda um frame para garantir que a remoção foi processada
            setTimeout(() => {
                alertDiv.textContent = mensagem;
                alertDiv.className = 'alert alert-' + tipo;
                // Força reflow para garantir que a classe foi aplicada
                alertDiv.offsetHeight;
                // Adiciona a classe 'show' para exibir
                alertDiv.classList.add('show');
                
                if (tipo === 'success') {
                    timeoutId = setTimeout(() => {
                        alertDiv.classList.remove('show');
                    }, 5000); // Aumentado para 5 segundos para dar mais tempo de leitura
                }
            }, 10);
        }
        
        form.addEventListener('submit', function(e) {
            e.preventDefault();
            
            // Desabilita o botão durante o processamento
            const btnSubmit = form.querySelector('button[type="submit"]');
            const btnTextOriginal = btnSubmit.textContent;
            btnSubmit.disabled = true;
            btnSubmit.textContent = 'Processando...';
            
            // Timeout para evitar que fique travado indefinidamente
            const timeoutId = setTimeout(() => {
                btnSubmit.disabled = false;
                btnSubmit.textContent = btnTextOriginal;
                mostrarAlerta('Timeout: A requisição demorou muito para responder. Tente novamente.', 'error');
            }, 120000); // 2 minutos de timeout
            
            const formData = new FormData(form);
            formData.append('acao', 'executar');
            // CSRF token já está incluído no formData via campo hidden
            
            fetch('', {
                method: 'POST',
                body: formData,
                signal: AbortSignal.timeout(120000) // Timeout de 2 minutos
            })
            .then(response => {
                clearTimeout(timeoutId);
                
                // Verifica se a resposta é JSON válido
                const contentType = response.headers.get('content-type');
                if (!contentType || !contentType.includes('application/json')) {
                    return response.text().then(text => {
                        console.error('Resposta não é JSON:', text);
                        throw new Error('Resposta inválida do servidor. Verifique o console para detalhes.');
                    });
                }
                
                if (!response.ok) {
                    throw new Error('Erro na resposta do servidor: ' + response.status);
                }
                return response.json();
            })
            .then(data => {
                // Garante que o botão seja reabilitado após receber a resposta
                btnSubmit.disabled = false;
                btnSubmit.textContent = btnTextOriginal;
                clearTimeout(timeoutId);
                
                if (!data) {
                    throw new Error('Resposta vazia do servidor');
                }
                
                if (data.success) {
                    // Exibe a mensagem completa que já vem do servidor com o número da nota
                    const mensagem = data.message || 'Nota fiscal emitida com sucesso!';
                    mostrarAlerta(mensagem, 'success');
                    entrada.value = '';
                    notaInfo.textContent = '';
                } else {
                    mostrarAlerta(data.error || 'Erro ao processar requisição', 'error');
                }
            })
            .catch(error => {
                // Garante que o botão seja reabilitado em caso de erro
                btnSubmit.disabled = false;
                btnSubmit.textContent = btnTextOriginal;
                clearTimeout(timeoutId);
                console.error('Erro completo:', error);
                
                let mensagemErro = 'Erro ao processar requisição';
                if (error.name === 'AbortError' || error.name === 'TimeoutError') {
                    mensagemErro = 'Timeout: A requisição demorou muito. Verifique sua conexão e tente novamente.';
                } else if (error.message) {
                    mensagemErro = error.message;
                }
                
                mostrarAlerta(mensagemErro, 'error');
            });
        });
    </script>
</body>
</html>
