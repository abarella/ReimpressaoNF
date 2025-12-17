<?php
/**
 * Página de Login - Autenticação Active Directory
 */

// Define encoding UTF-8 ANTES de qualquer coisa
mb_internal_encoding('UTF-8');
mb_http_output('UTF-8');

// Envia header de encoding IMEDIATAMENTE, antes de qualquer include
if (!headers_sent()) {
    header('Content-Type: text/html; charset=UTF-8');
}

// Limpa qualquer output buffer e inicia novo com UTF-8
while (ob_get_level() > 0) {
    ob_end_clean();
}
// Inicia output buffer com handler UTF-8
ob_start(function($buffer) {
    // Garante que o buffer está em UTF-8
    if (!mb_check_encoding($buffer, 'UTF-8')) {
        $buffer = mb_convert_encoding($buffer, 'UTF-8', mb_detect_encoding($buffer));
    }
    return $buffer;
});

// Função helper para garantir encoding UTF-8 correto em strings
function utf8($str) {
    if (!mb_check_encoding($str, 'UTF-8')) {
        return mb_convert_encoding($str, 'UTF-8', 'ISO-8859-1');
    }
    return $str;
}

require_once __DIR__ . DIRECTORY_SEPARATOR . 'auth.php';

// Se já estiver autenticado, redireciona para a página principal
if (estaAutenticado()) {
    $redirect = $_SESSION['redirect_after_login'] ?? 'reimpressaoNF.php';
    unset($_SESSION['redirect_after_login']);
    header('Location: ' . $redirect);
    exit;
}

$erro = '';
$mensagem = '';

// Processa login
if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['acao']) && $_POST['acao'] === 'login') {
    // Valida token CSRF
    if (!validarTokenCSRF($_POST['csrf_token'] ?? '')) {
        $erro = utf8('Token de segurança inválido. Por favor, recarregue a página e tente novamente.');
    } else {
        $username = trim($_POST['username'] ?? '');
        $password = $_POST['password'] ?? '';
        
        if (empty($username) || empty($password)) {
            $erro = utf8('Por favor, preencha todos os campos.');
        } else {
            // Autentica no Active Directory
            $userData = autenticarAD($username, $password);
            
            if ($userData) {
                // Login bem-sucedido
                iniciarSessaoSegura();
                
                $_SESSION['usuario_autenticado'] = true;
                $_SESSION['usuario'] = $userData;
                $_SESSION['ultimo_acesso'] = time();
                $_SESSION['ip'] = $_SERVER['REMOTE_ADDR'] ?? 'desconhecido';
                
                // Registra login bem-sucedido
                registrarTentativaLogin($username, true);
                
                // Redireciona para página solicitada ou página principal
                $redirect = $_SESSION['redirect_after_login'] ?? 'reimpressaoNF.php';
                unset($_SESSION['redirect_after_login']);
                
                header('Location: ' . $redirect);
                exit;
            } else {
                // Login falhou
                $erro = utf8('Usuário ou senha inválidos. Verifique suas credenciais e tente novamente.');
                registrarTentativaLogin($username, false);
            }
        }
    }
}

// Verifica se há mensagem de logout
if (isset($_GET['logout']) && $_GET['logout'] === '1') {
    $mensagem = utf8('Você foi desconectado com sucesso.');
}

// Verifica se foi redirecionado por falta de autenticação
if (isset($_GET['redirect']) && $_GET['redirect'] === '1') {
    $mensagem = utf8('Por favor, faça login para acessar o sistema.');
}
?>
<!DOCTYPE html>
<html lang="pt-BR">
<head>
    <meta http-equiv="Content-Type" content="text/html; charset=UTF-8">
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title><?php echo htmlspecialchars(utf8('Login - Sistema de Reimpressão de Notas Fiscais'), ENT_QUOTES, 'UTF-8'); ?></title>
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
            min-height: 100vh;
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
        
        .login-wrapper {
            display: flex;
            align-items: center;
            justify-content: center;
            min-height: calc(100vh - 60px);
            padding: 20px;
        }
        
        .login-container {
            background: white;
            border-radius: 10px;
            box-shadow: 0 10px 40px rgba(0,0,0,0.2);
            padding: 40px;
            width: 100%;
            max-width: 400px;
        }
        
        .login-header {
            text-align: center;
            margin-bottom: 30px;
        }
        
        .login-header h1 {
            color: #180a7b;
            font-size: 24px;
            margin-bottom: 10px;
        }
        
        .login-header p {
            color: #666;
            font-size: 14px;
        }
        
        .form-group {
            margin-bottom: 20px;
        }
        
        .form-group label {
            display: block;
            margin-bottom: 8px;
            color: #333;
            font-weight: bold;
            font-size: 14px;
        }
        
        .form-group input {
            width: 100%;
            padding: 12px;
            border: 1px solid #ddd;
            border-radius: 5px;
            font-size: 14px;
            transition: border-color 0.3s;
        }
        
        .form-group input:focus {
            outline: none;
            border-color: #180a7b;
        }
        
        .btn-login {
            width: 100%;
            padding: 12px;
            background-color: #180a7b;
            color: white;
            border: none;
            border-radius: 5px;
            font-size: 16px;
            font-weight: bold;
            cursor: pointer;
            transition: background-color 0.3s;
        }
        
        .btn-login:hover {
            background-color: #2a1ba8;
        }
        
        .btn-login:disabled {
            background-color: #ccc;
            cursor: not-allowed;
        }
        
        .alert {
            padding: 12px;
            border-radius: 5px;
            margin-bottom: 20px;
            font-size: 14px;
        }
        
        .alert-error {
            background-color: #f8d7da;
            color: #721c24;
            border: 1px solid #f5c6cb;
        }
        
        .alert-success {
            background-color: #d4edda;
            color: #155724;
            border: 1px solid #c3e6cb;
        }
        
        .info-text {
            text-align: center;
            margin-top: 20px;
            color: #666;
            font-size: 12px;
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
        <!-- Right navbar links - vazio na tela de login -->
        <ul class="navbar-nav ml-auto">
        </ul>
    </nav>
    <!-- /.navbar -->
    
    <div class="login-wrapper">
        <div class="login-container">
            <div class="login-header">
                <h1>Login</h1>
                <p><?php echo htmlspecialchars(utf8('Sistema de Reimpressão de Notas Fiscais'), ENT_QUOTES, 'UTF-8'); ?></p>
            </div>
        
        <?php if ($erro): ?>
            <div class="alert alert-error">
                <?php echo htmlspecialchars($erro, ENT_QUOTES, 'UTF-8'); ?>
            </div>
        <?php endif; ?>
        
        <?php if ($mensagem): ?>
            <div class="alert alert-success">
                <?php echo htmlspecialchars($mensagem, ENT_QUOTES, 'UTF-8'); ?>
            </div>
        <?php endif; ?>
        
        <form method="POST" action="" id="loginForm">
            <input type="hidden" name="acao" value="login">
            <input type="hidden" name="csrf_token" value="<?php echo htmlspecialchars(gerarTokenCSRF(), ENT_QUOTES, 'UTF-8'); ?>">
            
            <div class="form-group">
                <label for="username"><?php echo htmlspecialchars(utf8('Usuário:'), ENT_QUOTES, 'UTF-8'); ?></label>
                <input 
                    type="text" 
                    id="username" 
                    name="username" 
                    required 
                    autofocus
                    autocomplete="username"
                    placeholder="<?php echo htmlspecialchars(utf8('Digite seu usuário de rede'), ENT_QUOTES, 'UTF-8'); ?>"
                >
            </div>
            
            <div class="form-group">
                <label for="password"><?php echo htmlspecialchars(utf8('Senha:'), ENT_QUOTES, 'UTF-8'); ?></label>
                <input 
                    type="password" 
                    id="password" 
                    name="password" 
                    required
                    autocomplete="current-password"
                    placeholder="<?php echo htmlspecialchars(utf8('Digite sua senha'), ENT_QUOTES, 'UTF-8'); ?>"
                >
            </div>
            
            <button type="submit" class="btn-login" id="btnLogin">
                <?php echo htmlspecialchars(utf8('Entrar'), ENT_QUOTES, 'UTF-8'); ?>
            </button>
        </form>
        
        <div class="info-text">
            <?php echo htmlspecialchars(utf8('Use suas credenciais de rede para acessar o sistema.'), ENT_QUOTES, 'UTF-8'); ?>
        </div>
        </div>
    </div>
    
    <script>
        const form = document.getElementById('loginForm');
        const btnLogin = document.getElementById('btnLogin');
        
        form.addEventListener('submit', function(e) {
            btnLogin.disabled = true;
            btnLogin.textContent = '<?php echo htmlspecialchars(utf8('Autenticando...'), ENT_QUOTES, 'UTF-8'); ?>';
        });
    </script>
</body>
</html>
