<?php
/**
 * Arquivo de Configuração do Sistema
 * 
 * IMPORTANTE: Este arquivo contém configurações sensíveis.
 * Mantenha este arquivo fora do webroot ou proteja-o com .htaccess
 */

// Previne acesso direto ao arquivo via web
// Verifica se está sendo acessado diretamente (não incluído)
// Só bloqueia se for acesso HTTP direto ao arquivo config.php
if (php_sapi_name() !== 'cli') {
    // Verifica se o script atual é o config.php (acesso direto)
    $scriptName = basename($_SERVER['SCRIPT_NAME'] ?? $_SERVER['PHP_SELF'] ?? '');
    if ($scriptName === 'config.php') {
        http_response_code(403);
        die('Acesso negado');
    }
}

/**
 * Carrega configurações de variáveis de ambiente ou arquivo .env
 */
function carregarConfiguracao() {
    $config = [];
    
    // Tenta carregar de variáveis de ambiente primeiro (recomendado para produção)
    $config['db_server'] = getenv('DB_SERVER') ?: '';
    $config['db_database'] = getenv('DB_DATABASE') ?: '';
    $config['db_user'] = getenv('DB_USER') ?: '';
    $config['db_password'] = getenv('DB_PASSWORD') ?: '';
    
    // Se não encontrou nas variáveis de ambiente, tenta carregar do arquivo .env
    if (empty($config['db_server']) || empty($config['db_database']) || 
        empty($config['db_user']) || empty($config['db_password'])) {
        
        $envFile = __DIR__ . DIRECTORY_SEPARATOR . '.env';
        
        if (file_exists($envFile) && is_readable($envFile)) {
            // Usa file_get_contents para ler o arquivo inteiro
            $content = @file_get_contents($envFile);
            
            if ($content === false || $content === '') {
                error_log("Erro ao ler arquivo .env: não foi possível ler o arquivo ou arquivo vazio");
            } else {
                // Remove BOM se presente
                $content = preg_replace('/^\xEF\xBB\xBF/', '', $content);
                
                // Divide em linhas (suporta Windows, Unix e Mac)
                $lines = preg_split('/\r\n|\r|\n/', $content);
                
                foreach ($lines as $lineNum => $line) {
                    // Remove espaços e tabs
                    $line = trim($line);
                    
                    // Ignora linhas vazias e comentários
                    if (empty($line) || strpos($line, '#') === 0) {
                        continue;
                    }
                    
                    // Processa linhas no formato KEY=VALUE
                    if (strpos($line, '=') !== false) {
                        $parts = explode('=', $line, 2);
                        $key = trim($parts[0]);
                        $value = isset($parts[1]) ? trim($parts[1]) : '';
                        
                        // Remove aspas se presentes
                        $value = trim($value, '"\'');

                        switch ($key) {
                            case 'DB_SERVER':
                                $config['db_server'] = $value;
                                break;
                            case 'DB_DATABASE':
                                $config['db_database'] = $value;
                                break;
                            case 'DB_USER':
                                $config['db_user'] = $value;
                                break;
                            case 'DB_PASSWORD':
                                $config['db_password'] = $value;
                                break;
                            case 'AD_SERVER':
                                $config['ad_server'] = $value;
                                break;
                            case 'AD_DOMAIN':
                                $config['ad_domain'] = $value;
                                break;
                            case 'AD_BASE_DN':
                                $config['ad_base_dn'] = $value;
                                break;
                            case 'AD_PORT':
                                $config['ad_port'] = $value;
                                break;
                            // Suporte para formato Laravel também
                            case 'LDAP_HOST':
                                if (empty($config['ad_server'])) {
                                    $config['ad_server'] = $value;
                                }
                                break;
                            case 'LDAP_BASE_DN':
                                if (empty($config['ad_base_dn'])) {
                                    $config['ad_base_dn'] = $value;
                                }
                                break;
                            case 'LDAP_PORT':
                                if (empty($config['ad_port'])) {
                                    $config['ad_port'] = $value;
                                }
                                break;
                        }
                    }
                }
            }
        } else {
            error_log("Arquivo .env não encontrado ou não legível em: " . $envFile);
        }
    }
    
    // Valida se todas as configurações do banco foram carregadas
    // (Configurações do AD são opcionais e validadas em auth.php)
    if (empty($config['db_server']) || empty($config['db_database']) || 
        empty($config['db_user']) || empty($config['db_password'])) {
        
        // Log detalhado para debug (apenas em desenvolvimento)
        $missing = [];
        if (empty($config['db_server'])) $missing[] = 'DB_SERVER';
        if (empty($config['db_database'])) $missing[] = 'DB_DATABASE';
        if (empty($config['db_user'])) $missing[] = 'DB_USER';
        if (empty($config['db_password'])) $missing[] = 'DB_PASSWORD';
        
        error_log("Configurações faltando: " . implode(', ', $missing));
        error_log("Valores carregados - DB_SERVER: '" . ($config['db_server'] ?? 'vazio') . 
                 "', DB_DATABASE: '" . ($config['db_database'] ?? 'vazio') . 
                 "', DB_USER: '" . ($config['db_user'] ?? 'vazio') . 
                 "', DB_PASSWORD: '" . (empty($config['db_password']) ? 'vazio' : '***') . "'");
        
        throw new Exception(
            'Configurações do banco de dados não encontradas. ' .
            'Configure as variáveis de ambiente ou crie o arquivo .env. ' .
            'Consulte o arquivo .env.example para mais informações.'
        );
    }
    
    return $config;
}

// Carrega as configurações
try {
    $dbConfig = carregarConfiguracao();
    
    // Define as constantes para compatibilidade com o código existente
    if (!defined('DB_SERVER')) {
        define('DB_SERVER', $dbConfig['db_server']);
    }
    if (!defined('DB_DATABASE')) {
        define('DB_DATABASE', $dbConfig['db_database']);
    }
    if (!defined('DB_USER')) {
        define('DB_USER', $dbConfig['db_user']);
    }
    if (!defined('DB_PASSWORD')) {
        define('DB_PASSWORD', $dbConfig['db_password']);
    }
} catch (Exception $e) {
    // Em produção, não exponha detalhes do erro
    error_log('Erro ao carregar configurações: ' . $e->getMessage());
    error_log('Stack trace: ' . $e->getTraceAsString());
    
    // Exibe mensagem genérica ao usuário
    if (php_sapi_name() !== 'cli') {
        // Limpa qualquer output anterior
        while (ob_get_level() > 0) {
            ob_end_clean();
        }
        
        http_response_code(500);
        header('Content-Type: text/html; charset=UTF-8');
        die('Erro de configuração do sistema. Entre em contato com o administrador.');
    } else {
        die('Erro: ' . $e->getMessage() . PHP_EOL);
    }
}

