<?php
/**
 * Script de limpeza de arquivos temporarios
 * Remove arquivos copy_background_*.bat e nota_*.txt antigos
 * 
 * Pode ser executado manualmente ou via Task Scheduler do Windows
 * Recomendado: executar diariamente ou semanalmente
 */

// Previne acesso direto via web (opcional - descomente se quiser proteger)
// if (php_sapi_name() !== 'cli' && isset($_SERVER['REQUEST_METHOD'])) {
//     http_response_code(403);
//     die('Acesso negado');
// }

// Carrega funcao de logging se disponivel
if (file_exists(__DIR__ . DIRECTORY_SEPARATOR . 'reimpressaoNF.php')) {
    require_once __DIR__ . DIRECTORY_SEPARATOR . 'reimpressaoNF.php';
}

$diretorio = __DIR__;
$arquivos_removidos = 0;
$tamanho_liberado = 0;
$tempo_limite = 3600; // Remove arquivos com mais de 1 hora (3600 segundos)

// Padroes de arquivos temporarios
$padroes = [
    'copy_background_*.bat',
    'nota_*.txt',
    'php_copy_*.php'
];

echo "Iniciando limpeza de arquivos temporarios...\n";
echo "Diretorio: {$diretorio}\n";
echo "Tempo limite: {$tempo_limite} segundos (1 hora)\n\n";

foreach ($padroes as $padrao) {
    $arquivos = glob($diretorio . DIRECTORY_SEPARATOR . $padrao);
    
    foreach ($arquivos as $arquivo) {
        if (is_file($arquivo)) {
            $tempo_modificacao = filemtime($arquivo);
            $tempo_atual = time();
            $idade_arquivo = $tempo_atual - $tempo_modificacao;
            
            // Remove arquivos antigos (mais de 1 hora)
            if ($idade_arquivo > $tempo_limite) {
                $tamanho = filesize($arquivo);
                $nome_arquivo = basename($arquivo);
                
                // Remove atributos de somente leitura antes de deletar
                if (strtoupper(substr(PHP_OS, 0, 3)) === 'WIN') {
                    $arquivo_escaped = escapeshellarg($arquivo);
                    @exec("attrib -r -s -h {$arquivo_escaped} >nul 2>&1");
                }
                @chmod($arquivo, 0666);
                
                // Tenta deletar varias vezes
                $tentativas = 0;
                $removido = false;
                while (file_exists($arquivo) && $tentativas < 5) {
                    if (@unlink($arquivo)) {
                        $removido = true;
                        break;
                    }
                    if (file_exists($arquivo)) {
                        usleep(500000); // 0.5 segundos
                    }
                    $tentativas++;
                }
                
                if ($removido || !file_exists($arquivo)) {
                    $arquivos_removidos++;
                    $tamanho_liberado += $tamanho;
                    echo "Removido: {$nome_arquivo} (" . number_format($tamanho / 1024, 2) . " KB, idade: " . round($idade_arquivo / 60) . " minutos";
                    if ($tentativas > 1) {
                        echo ", tentativas: {$tentativas}";
                    }
                    echo ")\n";
                    
                    // Log do evento se a funcao estiver disponivel
                    if (function_exists('registrarEventoImpressao')) {
                        registrarEventoImpressao('ARQUIVO_TEMPORARIO_REMOVIDO', [
                            'arquivo' => $nome_arquivo,
                            'tamanho_bytes' => $tamanho,
                            'idade_segundos' => $idade_arquivo,
                            'tentativas' => $tentativas
                        ]);
                    }
                } else {
                    echo "ERRO ao remover: {$nome_arquivo} (tentativas: {$tentativas})\n";
                }
            }
        }
    }
}

echo "\n";
echo "Limpeza concluida!\n";
echo "Arquivos removidos: {$arquivos_removidos}\n";
echo "Espaco liberado: " . number_format($tamanho_liberado / 1024, 2) . " KB (" . number_format($tamanho_liberado / 1024 / 1024, 2) . " MB)\n";

// Se executado via CLI, retorna codigo de saida
if (php_sapi_name() === 'cli') {
    exit($arquivos_removidos > 0 ? 0 : 1);
}

