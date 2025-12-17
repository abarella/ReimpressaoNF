<?php
/**
 * Script auxiliar para logging de eventos de impressão
 * Chamado via linha de comando pelo script batch
 */

// Previne acesso direto via web
if (php_sapi_name() !== 'cli' && isset($_SERVER['REQUEST_METHOD'])) {
    http_response_code(403);
    die('Acesso negado');
}

// Traduz código de erro do robocopy para descrição legível
function traduzirErroRobocopyHelper($codigo) {
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

// Define função de logging diretamente aqui para evitar problemas de dependência
function registrarEventoImpressaoHelper($evento, $detalhes = []) {
    $timestamp = date('Y-m-d H:i:s');
    $username = get_current_user() ?: 'sistema';
    $usuario_windows = getenv('USERNAME') ?: getenv('USER') ?: 'IUSR';
    $ip = 'CLI';
    
    // Monta mensagem de log
    $logMessage = "[{$timestamp}] IMPRESSAO - Evento: {$evento} - Usuario: {$username} - IP: {$ip}";
    $logMessage .= " - UsuarioSistema: {$usuario_windows} - Contexto: CLI/IIS";
    
    // Adiciona detalhes se fornecidos
    if (!empty($detalhes)) {
        $detalhesStr = [];
        foreach ($detalhes as $chave => $valor) {
            // Escapa valores que podem conter caracteres especiais
            $valorEscapado = is_string($valor) ? str_replace(["\r", "\n"], ['\\r', '\\n'], $valor) : $valor;
            
            // Se for erro_level e for um código numérico, adiciona tradução
            if ($chave === 'erro_level' && is_numeric($valor) && $valor >= 8) {
                $traducao = traduzirErroRobocopyHelper((int)$valor);
                $detalhesStr[] = "{$chave}: {$valorEscapado} ({$traducao})";
            } elseif ($chave === 'erro' && is_string($valor)) {
                // Adiciona informação sobre erro
                $detalhesStr[] = "{$chave}: {$valorEscapado}";
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

// Obtém parâmetros da linha de comando
$evento = $argv[1] ?? 'EVENTO_DESCONHECIDO';
$numero_nota = $argv[2] ?? '';
$impressora = $argv[3] ?? '';
$destino_impressora = $argv[4] ?? '';
$arquivo_origem = $argv[5] ?? '';
$arquivo_destino = $argv[6] ?? '';
$metodo = $argv[7] ?? '';
$erro_level = $argv[8] ?? '';

// Prepara detalhes
$detalhes = [];
if ($numero_nota) $detalhes['numero_nota'] = $numero_nota;
if ($impressora) $detalhes['impressora'] = $impressora;
if ($destino_impressora) $detalhes['destino_impressora'] = $destino_impressora;
if ($arquivo_origem) $detalhes['arquivo_origem'] = $arquivo_origem;
if ($arquivo_destino) $detalhes['arquivo_destino'] = $arquivo_destino;
if ($metodo) $detalhes['metodo'] = $metodo;
if ($erro_level) $detalhes['erro_level'] = $erro_level;

// Registra o evento
registrarEventoImpressaoHelper($evento, $detalhes);
