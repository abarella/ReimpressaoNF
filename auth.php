<?php
/**
 * Sistema de Autenticação com Active Directory (LDAP)
 * 
 * IMPORTANTE: Este arquivo contém funções de autenticação sensíveis.
 * Mantenha este arquivo protegido e não exponha informações de erro detalhadas.
 */

// Define encoding UTF-8
mb_internal_encoding('UTF-8');
mb_http_output('UTF-8');

// Previne acesso direto ao arquivo via web
if (php_sapi_name() !== 'cli') {
    $scriptName = basename($_SERVER['SCRIPT_NAME'] ?? $_SERVER['PHP_SELF'] ?? '');
    if ($scriptName === 'auth.php') {
        http_response_code(403);
        die('Acesso negado');
    }
}

// Carrega configurações
require_once __DIR__ . DIRECTORY_SEPARATOR . 'config.php';

/**
 * Inicia sessão segura
 */
function iniciarSessaoSegura() {
    if (session_status() === PHP_SESSION_NONE) {
        // Configurações de segurança da sessão
        ini_set('session.cookie_httponly', '1');
        ini_set('session.cookie_secure', '0'); // Mude para 1 se usar HTTPS
        ini_set('session.use_strict_mode', '1');
        ini_set('session.cookie_samesite', 'Strict');
        
        // Timeout de sessão (30 minutos)
        ini_set('session.gc_maxlifetime', '1800');
        
        try {
            session_start();
        } catch (Exception $e) {
            error_log("Erro ao iniciar sessão: " . $e->getMessage());
            // Tenta iniciar novamente sem configurações especiais se falhar
            @session_start();
        }
        
        // Regenera ID da sessão periodicamente para prevenir session fixation
        if (!isset($_SESSION['created'])) {
            $_SESSION['created'] = time();
        } else if (time() - $_SESSION['created'] > 1800) {
            session_regenerate_id(true);
            $_SESSION['created'] = time();
        }
    }
}

/**
 * Autentica usuário no Active Directory via LDAP
 * 
 * @param string $username Nome de usuário (sem domínio)
 * @param string $password Senha do usuário
 * @return array|false Retorna array com dados do usuário ou false em caso de falha
 */
function autenticarAD($username, $password) {
    // Carrega configurações do AD (suporta formato Laravel e formato antigo)
    $adServer = getenv('LDAP_HOST') ?: getenv('AD_SERVER') ?: '';
    $adBaseDN = getenv('LDAP_BASE_DN') ?: getenv('AD_BASE_DN') ?: '';
    $adPort = getenv('LDAP_PORT') ?: getenv('AD_PORT') ?: '389';
    $adTimeout = getenv('LDAP_TIMEOUT') ?: '5';
    $adDomain = getenv('AD_DOMAIN') ?: '';
    
    // Tenta carregar do arquivo .env se não encontrou nas variáveis de ambiente
    if (empty($adServer) || empty($adBaseDN)) {
        $envFile = __DIR__ . DIRECTORY_SEPARATOR . '.env';
        if (file_exists($envFile)) {
            $lines = file($envFile, FILE_IGNORE_NEW_LINES | FILE_SKIP_EMPTY_LINES);
            foreach ($lines as $line) {
                if (strpos(trim($line), '#') === 0) {
                    continue;
                }
                if (strpos($line, '=') !== false) {
                    list($key, $value) = explode('=', $line, 2);
                    $key = trim($key);
                    $value = trim($value);
                    $value = trim($value, '"\''); // Remove aspas
                    
                    switch ($key) {
                        // Formato Laravel
                        case 'LDAP_HOST':
                            $adServer = $value;
                            break;
                        case 'LDAP_BASE_DN':
                            $adBaseDN = $value;
                            break;
                        case 'LDAP_PORT':
                            $adPort = $value;
                            break;
                        case 'LDAP_TIMEOUT':
                            $adTimeout = $value;
                            break;
                        // Formato antigo (compatibilidade)
                        case 'AD_SERVER':
                            if (empty($adServer)) $adServer = $value;
                            break;
                        case 'AD_DOMAIN':
                            $adDomain = $value;
                            break;
                        case 'AD_BASE_DN':
                            if (empty($adBaseDN)) $adBaseDN = $value;
                            break;
                        case 'AD_PORT':
                            if (empty($adPort) || $adPort === '389') $adPort = $value;
                            break;
                    }
                }
            }
        }
    }
    
    // Extrai domínio do BASE_DN se não foi configurado explicitamente
    if (empty($adDomain) && !empty($adBaseDN)) {
        // Extrai de DC=ip,DC=ipen,DC=br -> ipen.br
        if (preg_match_all('/DC=([^,]+)/i', $adBaseDN, $matches)) {
            $dcParts = $matches[1];
            if (count($dcParts) >= 2) {
                // Pega os últimos dois DCs para formar o domínio
                $adDomain = implode('.', array_slice($dcParts, -2));
            } else {
                $adDomain = $dcParts[0];
            }
        }
    }
    
    // Valida configurações
    if (empty($adServer) || empty($adBaseDN)) {
        error_log('Configurações do Active Directory não encontradas. LDAP_HOST e LDAP_BASE_DN são obrigatórios.');
        return false;
    }
    
    // Sanitiza entrada
    $username = trim($username);
    $password = trim($password);
    
    if (empty($username) || empty($password)) {
        return false;
    }
    
        // Preserva username original para busca
        $usernameOriginal = $username;
        $usernameClean = $username;
        
        // Remove domínio do username se presente (ex: DOMINIO\usuario -> usuario)
        if (strpos($usernameClean, '\\') !== false) {
            $usernameClean = explode('\\', $usernameClean)[1];
        }
        if (strpos($usernameClean, '@') !== false) {
            $usernameClean = explode('@', $usernameClean)[0];
        }
        
        // Formata DN do usuário
        // Tenta diferentes formatos de DN e UPN
        $dnFormats = [];
        
        // Se o username original já tem formato completo, usa ele primeiro
        if (strpos($usernameOriginal, '@') !== false) {
            $dnFormats[] = $usernameOriginal; // UPN completo: usuario@ipen.br
        }
        
        // Adiciona outros formatos
        if (!empty($adDomain)) {
            $dnFormats[] = "{$usernameClean}@{$adDomain}"; // UPN: usuario@ipen.br
        }
        $dnFormats[] = "CN={$usernameClean},CN=Users,{$adBaseDN}"; // DN padrão
        $dnFormats[] = "CN={$usernameClean},{$adBaseDN}"; // DN alternativo
        
        // Para IPEN, também tenta formato específico
        if (strpos($adBaseDN, 'ipen') !== false) {
            $dnFormats[] = "{$usernameClean}@ip.ipen.br"; // UPN específico IPEN
        }
    
    $ldapConn = false;
    $ldapBound = false;
    
    try {
        // Conecta ao servidor LDAP
        $ldapConn = @ldap_connect($adServer, $adPort);
        
        if (!$ldapConn) {
            error_log("Erro ao conectar ao servidor AD: {$adServer}:{$adPort}");
            return false;
        }
        
        // Configura opções LDAP
        ldap_set_option($ldapConn, LDAP_OPT_PROTOCOL_VERSION, 3);
        ldap_set_option($ldapConn, LDAP_OPT_REFERRALS, 0);
        ldap_set_option($ldapConn, LDAP_OPT_NETWORK_TIMEOUT, (int)$adTimeout);
        
        // Configura SSL/TLS se necessário (formato Laravel)
        $useSSL = getenv('LDAP_SSL') === 'true' || getenv('LDAP_SSL') === '1';
        $useTLS = getenv('LDAP_TLS') === 'true' || getenv('LDAP_TLS') === '1';
        
        // Carrega SSL/TLS do .env se não encontrou nas variáveis de ambiente
        if (!$useSSL && !$useTLS) {
            $envFile = __DIR__ . DIRECTORY_SEPARATOR . '.env';
            if (file_exists($envFile)) {
                $lines = file($envFile, FILE_IGNORE_NEW_LINES | FILE_SKIP_EMPTY_LINES);
                foreach ($lines as $line) {
                    if (strpos(trim($line), '#') === 0) continue;
                    if (strpos($line, '=') !== false) {
                        list($key, $value) = explode('=', $line, 2);
                        $key = trim($key);
                        $value = trim(strtolower(trim($value, '"\'')));
                        if ($key === 'LDAP_SSL' && ($value === 'true' || $value === '1')) {
                            $useSSL = true;
                        }
                        if ($key === 'LDAP_TLS' && ($value === 'true' || $value === '1')) {
                            $useTLS = true;
                        }
                    }
                }
            }
        }
        
        if ($useTLS) {
            ldap_set_option($ldapConn, LDAP_OPT_X_TLS_REQUIRE_CERT, LDAP_OPT_X_TLS_NEVER);
            if (!@ldap_start_tls($ldapConn)) {
                error_log("Erro ao iniciar TLS: " . ldap_error($ldapConn));
                @ldap_close($ldapConn);
                return false;
            }
        }
        
        // Tenta autenticar com diferentes formatos de DN
        $userDN = '';
        foreach ($dnFormats as $dn) {
            $ldapBound = @ldap_bind($ldapConn, $dn, $password);
            if ($ldapBound) {
                $userDN = $dn;
                break;
            }
        }
        
        if (!$ldapBound) {
            error_log("Falha na autenticação AD para usuário: {$usernameOriginal} (tentou formatos: " . implode(', ', array_slice($dnFormats, 0, 3)) . "...)");
            @ldap_close($ldapConn);
            return false;
        }
        
        // Busca informações do usuário no AD usando sAMAccountName ou UPN
        // Tenta tanto com username limpo quanto com username original
        $searchFilter = "(|(sAMAccountName={$usernameClean})(userPrincipalName={$usernameOriginal})(userPrincipalName={$usernameClean}@{$adDomain}))";
        if (empty($adDomain)) {
            $searchFilter = "(sAMAccountName={$usernameClean})";
        }
        $searchAttributes = ['cn', 'mail', 'displayName', 'sAMAccountName', 'memberOf', 'userPrincipalName'];
        
        $searchResult = @ldap_search($ldapConn, $adBaseDN, $searchFilter, $searchAttributes);
        
        if (!$searchResult) {
            error_log("Erro ao buscar usuário no AD: {$usernameOriginal} - " . ldap_error($ldapConn));
            @ldap_close($ldapConn);
            return false;
        }
        
        $entries = @ldap_get_entries($ldapConn, $searchResult);
        
        if (!$entries || $entries['count'] == 0) {
            error_log("Usuário não encontrado no AD após autenticação: {$usernameOriginal} (buscou com: {$usernameClean})");
            @ldap_close($ldapConn);
            return false;
        }
        
        $userInfo = $entries[0];
        
        // Extrai username real do AD (pode ser diferente do informado)
        $adUsername = isset($userInfo['samaccountname'][0]) ? 
                     strtolower($userInfo['samaccountname'][0]) : 
                     $usernameClean;
        
        // Extrai informações do usuário
        $userData = [
            'username' => $adUsername,
            'displayName' => isset($userInfo['displayname'][0]) ? $userInfo['displayname'][0] : 
                           (isset($userInfo['cn'][0]) ? $userInfo['cn'][0] : $adUsername),
            'email' => isset($userInfo['mail'][0]) ? $userInfo['mail'][0] : '',
            'cn' => isset($userInfo['cn'][0]) ? $userInfo['cn'][0] : $adUsername,
            'upn' => isset($userInfo['userprincipalname'][0]) ? $userInfo['userprincipalname'][0] : '',
            'groups' => []
        ];
        
        // Extrai grupos do usuário
        if (isset($userInfo['memberof']) && is_array($userInfo['memberof'])) {
            foreach ($userInfo['memberof'] as $group) {
                if (is_string($group)) {
                    // Extrai nome do grupo do DN (ex: CN=Grupo,OU=... -> Grupo)
                    if (preg_match('/CN=([^,]+)/', $group, $matches)) {
                        $userData['groups'][] = $matches[1];
                    }
                }
            }
        }
        
        @ldap_close($ldapConn);
        
        return $userData;
        
    } catch (Exception $e) {
        error_log("Exceção na autenticação AD: " . $e->getMessage());
        if ($ldapConn) {
            @ldap_close($ldapConn);
        }
        return false;
    }
}

/**
 * Verifica se o usuário está autenticado
 * 
 * @return bool
 */
function estaAutenticado() {
    iniciarSessaoSegura();
    return isset($_SESSION['usuario_autenticado']) && 
           $_SESSION['usuario_autenticado'] === true &&
           isset($_SESSION['usuario']) &&
           isset($_SESSION['ultimo_acesso']);
}

/**
 * Requer autenticação - redireciona para login se não autenticado
 */
function requerAutenticacao() {
    if (!estaAutenticado()) {
        iniciarSessaoSegura();
        $_SESSION['redirect_after_login'] = $_SERVER['REQUEST_URI'] ?? '/';
        header('Location: login.php');
        exit;
    }
    
    // Atualiza último acesso
    $_SESSION['ultimo_acesso'] = time();
}

/**
 * Faz logout do usuário
 */
function fazerLogout() {
    iniciarSessaoSegura();
    
    // Limpa todas as variáveis de sessão
    $_SESSION = [];
    
    // Destrói cookie de sessão
    if (isset($_COOKIE[session_name()])) {
        setcookie(session_name(), '', time() - 3600, '/');
    }
    
    // Destrói sessão
    session_destroy();
}

/**
 * Obtém dados do usuário autenticado
 * 
 * @return array|null
 */
function obterUsuario() {
    if (estaAutenticado()) {
        return $_SESSION['usuario'] ?? null;
    }
    return null;
}

/**
 * Verifica se o usuário pertence a um grupo específico
 * 
 * @param string $grupo Nome do grupo
 * @return bool
 */
function usuarioPertenceAoGrupo($grupo) {
    $usuario = obterUsuario();
    if (!$usuario || !isset($usuario['groups'])) {
        return false;
    }
    
    return in_array($grupo, $usuario['groups']);
}

/**
 * Gera token CSRF e armazena na sessão
 * 
 * @return string Token CSRF
 */
function gerarTokenCSRF() {
    try {
        // Garante que a sessão está iniciada
        if (session_status() === PHP_SESSION_NONE) {
            iniciarSessaoSegura();
        }
        
        // Gera novo token se não existir ou se expirou (regenera a cada 1 hora)
        if (!isset($_SESSION['csrf_token']) || 
            !isset($_SESSION['csrf_token_time']) || 
            (time() - $_SESSION['csrf_token_time']) > 3600) {
            $_SESSION['csrf_token'] = bin2hex(random_bytes(32));
            $_SESSION['csrf_token_time'] = time();
        }
        
        return $_SESSION['csrf_token'] ?? '';
    } catch (Throwable $e) {
        // Em caso de erro, retorna string vazia e loga o erro
        error_log("Erro ao gerar token CSRF: " . $e->getMessage());
        error_log("Stack trace: " . $e->getTraceAsString());
        // Retorna token temporário para não quebrar a página
        return bin2hex(random_bytes(16));
    }
}

/**
 * Valida token CSRF
 * 
 * @param string $token Token CSRF a ser validado
 * @return bool True se válido, False caso contrário
 */
function validarTokenCSRF($token) {
    iniciarSessaoSegura();
    
    if (!isset($_SESSION['csrf_token']) || empty($token)) {
        return false;
    }
    
    // Usa hash_equals para prevenir timing attacks
    return hash_equals($_SESSION['csrf_token'], $token);
}

/**
 * Requer validação CSRF em requisições POST
 * Lança exceção se token inválido
 */
function requerCSRF() {
    // Só valida CSRF em requisições POST
    if ($_SERVER['REQUEST_METHOD'] !== 'POST') {
        return;
    }
    
    // Garante que a sessão está iniciada
    iniciarSessaoSegura();
    
    $token = $_POST['csrf_token'] ?? $_SERVER['HTTP_X_CSRF_TOKEN'] ?? '';
    
    if (!validarTokenCSRF($token)) {
        // Log da tentativa de CSRF
        error_log("Tentativa de CSRF bloqueada. IP: " . ($_SERVER['REMOTE_ADDR'] ?? 'desconhecido') . 
                 " | Token recebido: " . substr($token, 0, 10) . "...");
        
        // Verifica se é requisição AJAX (JSON) ou HTML
        $isAjax = !empty($_SERVER['HTTP_X_REQUESTED_WITH']) && 
                  strtolower($_SERVER['HTTP_X_REQUESTED_WITH']) === 'xmlhttprequest';
        
        if ($isAjax || (!empty($_POST['acao']))) {
            http_response_code(403);
            header('Content-Type: application/json; charset=UTF-8');
            die(json_encode([
                'success' => false,
                'error' => 'Token de segurança inválido. Por favor, recarregue a página e tente novamente.'
            ], JSON_UNESCAPED_UNICODE));
        } else {
            http_response_code(403);
            die('Token de segurança inválido. Por favor, recarregue a página e tente novamente.');
        }
    }
}

/**
 * Registra tentativa de login no log de auditoria
 */
function registrarTentativaLogin($username, $sucesso, $ip = null) {
    $ip = $ip ?? ($_SERVER['REMOTE_ADDR'] ?? 'desconhecido');
    $timestamp = date('Y-m-d H:i:s');
    $status = $sucesso ? 'SUCESSO' : 'FALHA';
    
    $logMessage = "[{$timestamp}] Login {$status} - Usuário: {$username} - IP: {$ip}" . PHP_EOL;
    
    // Cria diretório de logs se não existir
    $logDir = __DIR__ . DIRECTORY_SEPARATOR . 'logs';
    if (!is_dir($logDir)) {
        @mkdir($logDir, 0755, true);
    }
    
    $logFile = $logDir . DIRECTORY_SEPARATOR . 'auth.log';
    @file_put_contents($logFile, $logMessage, FILE_APPEND | LOCK_EX);
}

