<?php
session_start();
require_once 'db.php';

// Auto-login from remember me cookie
if (!isset($_SESSION['logged_in']) && isset($_COOKIE['rememberme'])) {
    list($selector, $validator) = explode(':', $_COOKIE['rememberme']);
    $stmt = $pdo->prepare('SELECT user_id, hashed_validator, expires FROM user_tokens WHERE selector = ? LIMIT 1');
    $stmt->execute([$selector]);
    $token = $stmt->fetch();
    if ($token && hash_equals($token['hashed_validator'], hash('sha256', $validator)) && strtotime($token['expires']) > time()) {
        $stmt = $pdo->prepare('SELECT * FROM users WHERE id = ? LIMIT 1');
        $stmt->execute([$token['user_id']]);
        $user = $stmt->fetch();
        if ($user) {
            $_SESSION['logged_in'] = true;
            $_SESSION['user'] = $user['name'];
            $_SESSION['user_email'] = $user['email'];
            $_SESSION['user_id'] = $user['id'];
            // Rotate token
            $new_selector = bin2hex(random_bytes(6));
            $new_validator = bin2hex(random_bytes(32));
            $hashed_validator = hash('sha256', $new_validator);
            $expires = date('Y-m-d H:i:s', time() + 60 * 60 * 24 * 5);
            $pdo->prepare('DELETE FROM user_tokens WHERE selector = ?')->execute([$selector]);
            $pdo->prepare('INSERT INTO user_tokens (user_id, selector, hashed_validator, expires) VALUES (?, ?, ?, ?)')->execute([$user['id'], $new_selector, $hashed_validator, $expires]);
            // Set cookie with hashed timestamp as name
            $cookie_name = hash('sha256', time());
            setcookie($cookie_name, "$new_selector:$new_validator", time() + 60 * 60 * 24 * 5, '/', '', isset($_SERVER['HTTPS']), true);
            header('Location: index.php');
            exit;
        }
    } else {
        setcookie('rememberme', '', time() - 3600, '/');
    }
}

// Handle login form submission
$errors = [];
if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    require_once 'db.php';
    $email = filter_var(trim($_POST['email']), FILTER_VALIDATE_EMAIL);
    $password = $_POST['password'] ?? '';
    $remember = isset($_POST['remember_me']);
    if (!$email) {
        $errors[] = 'Please enter a valid email address.';
    }
    if (empty($password)) {
        $errors[] = 'Please enter your password.';
    }
    if (empty($errors)) {
        $stmt = $pdo->prepare('SELECT * FROM users WHERE email = ? LIMIT 1');
        $stmt->execute([$email]);
        $user = $stmt->fetch();
        if ($user && password_verify($password, $user['password'])) {
            $_SESSION['logged_in'] = true;
            $_SESSION['user'] = $user['name'];
            $_SESSION['user_email'] = $user['email'];
            $_SESSION['user_id'] = $user['id'];
            // Remember Me logic
            if ($remember) {
                $selector = bin2hex(random_bytes(6));
                $validator = bin2hex(random_bytes(32));
                $hashed_validator = hash('sha256', $validator);
                $expires = date('Y-m-d H:i:s', time() + 60 * 60 * 24 * 5);
                $pdo->prepare('INSERT INTO user_tokens (user_id, selector, hashed_validator, expires) VALUES (?, ?, ?, ?)')->execute([$user['id'], $selector, $hashed_validator, $expires]);
                // Set cookie with hashed timestamp as name
                $cookie_name = hash('sha256', time());
                setcookie($cookie_name, "$selector:$validator", time() + 60 * 60 * 24 * 5, '/', '', isset($_SERVER['HTTPS']), true);
            }
            header('Location: index.php');
            exit;
        } else {
            $errors[] = 'Invalid email or password.';
        }
    }
}
// On logout, clear remember me token and cookie
if (isset($_GET['logout'])) {
    if (isset($_COOKIE['rememberme'])) {
        list($selector) = explode(':', $_COOKIE['rememberme']);
        $pdo->prepare('DELETE FROM user_tokens WHERE selector = ?')->execute([$selector]);
        setcookie('rememberme', '', time() - 3600, '/');
    }
    session_destroy();
    header('Location: login.php');
    exit;
}
?>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Vaultio | Login</title>
    <script src="https://cdn.tailwindcss.com/3.4.16"></script>
    <script>tailwind.config={theme:{extend:{colors:{primary:'#1E3A8A',secondary:'#0D9488'},borderRadius:{'none':'0px','sm':'4px',DEFAULT:'8px','md':'12px','lg':'16px','xl':'20px','2xl':'24px','3xl':'32px','full':'9999px','button':'8px'}}}}</script>
    <link rel="preconnect" href="https://fonts.googleapis.com">
    <link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
    <link href="https://fonts.googleapis.com/css2?family=Pacifico&display=swap" rel="stylesheet">
    <link href="https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600;700&display=swap" rel="stylesheet">
    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/remixicon/4.6.0/remixicon.min.css">
    <style>
        :where([class^="ri-"])::before { content: "\f3c2"; }
        body {
            font-family: 'Inter', sans-serif;
            background-color: #1A1A1A;
            color: #E5E5E5;
            min-height: 100vh;
        }
        .auth-container {
            display: flex;
            justify-content: center;
            align-items: center;
            min-height: 100vh;
            background-color: #1A1A1A;
        }
        .auth-card {
            background-color: #242424;
            border-radius: 12px;
            box-shadow: 0 8px 30px rgba(0, 0, 0, 0.3);
            width: 100%;
            max-width: 400px;
            padding: 2.5rem;
        }
        .input-group {
            position: relative;
            margin-bottom: 1.5rem;
        }
        .form-input {
            width: 100%;
            padding: 0.75rem 1rem;
            padding-left: 2.5rem;
            background-color: #333;
            border: 1px solid #444;
            border-radius: 8px;
            color: #E5E5E5;
            transition: all 0.2s;
        }
        .form-input:focus {
            border-color: #0D9488;
            outline: none;
            box-shadow: 0 0 0 2px rgba(13, 148, 136, 0.2);
        }
        .input-icon {
            position: absolute;
            left: 0.75rem;
            top: 50%;
            transform: translateY(-50%);
            color: #999;
        }
        .password-toggle {
            position: absolute;
            right: 0.75rem;
            top: 50%;
            transform: translateY(-50%);
            color: #999;
            cursor: pointer;
        }
        .btn {
            display: inline-flex;
            align-items: center;
            justify-content: center;
            padding: 0.75rem 1.5rem;
            border-radius: 8px;
            font-weight: 500;
            transition: all 0.2s;
            cursor: pointer;
            white-space: nowrap;
        }
        .btn-primary {
            background-color: #1E3A8A;
            color: white;
        }
        .btn-primary:hover {
            background-color: #1e4199;
        }
        .btn-secondary {
            background-color: #0D9488;
            color: white;
        }
        .btn-secondary:hover {
            background-color: #0ca69a;
        }
        .btn-outline {
            border: 1px solid #444;
            background-color: transparent;
            color: #E5E5E5;
        }
        .btn-outline:hover {
            background-color: #333;
        }
        .social-login {
            display: flex;
            gap: 1rem;
            margin-top: 1.5rem;
        }
        .social-btn {
            flex: 1;
            display: flex;
            align-items: center;
            justify-content: center;
            padding: 0.75rem;
            border-radius: 8px;
            background-color: #333;
            color: #E5E5E5;
            transition: all 0.2s;
        }
        .social-btn:hover {
            background-color: #444;
        }
        .divider {
            display: flex;
            align-items: center;
            margin: 1.5rem 0;
            color: #777;
        }
        .divider::before, .divider::after {
            content: "";
            flex: 1;
            height: 1px;
            background-color: #444;
        }
        .divider span {
            padding: 0 1rem;
        }
        .custom-checkbox {
            position: relative;
            width: 18px;
            height: 18px;
            border-radius: 4px;
            border: 1px solid #555;
            margin-right: 0.75rem;
            cursor: pointer;
            overflow: hidden;
        }
        .custom-checkbox.checked {
            background-color: #0D9488;
            border-color: #0D9488;
        }
        .custom-checkbox.checked::after {
            content: "";
            position: absolute;
            top: 2px;
            left: 6px;
            width: 5px;
            height: 10px;
            border: solid white;
            border-width: 0 2px 2px 0;
            transform: rotate(45deg);
        }
    </style>
</head>
<body>
    <div class="auth-container">
        <div class="auth-card">
            <div class="flex justify-center mb-8">
                <img src="vaultioLogo.png" alt="Vaultio Logo" class="h-20 w-auto" />
            </div>
            <div class="flex justify-center mb-6">
                <h2 class="text-2xl font-semibold text-white">Sign in to your account</h2>
            </div>
            <?php if (!empty($errors)): ?>
                <div class="error-message bg-red-600 text-white p-3 rounded mb-4 text-center">
                    <?php foreach ($errors as $error): ?>
                        <div><?= htmlspecialchars($error) ?></div>
                    <?php endforeach; ?>
                </div>
            <?php endif; ?>
            <form method="POST" action="login.php" autocomplete="off">
                <div class="input-group">
                    <div class="w-5 h-5 flex items-center justify-center input-icon">
                        <i class="ri-mail-line"></i>
                    </div>
                    <input type="email" name="email" class="form-input" placeholder="Email address" required>
                </div>
                <div class="input-group">
                    <div class="w-5 h-5 flex items-center justify-center input-icon">
                        <i class="ri-lock-line"></i>
                    </div>
                    <input type="password" id="password" name="password" class="form-input" placeholder="Password" required>
                    <div class="w-5 h-5 flex items-center justify-center password-toggle" onclick="togglePassword()">
                        <i id="password-icon" class="ri-eye-off-line"></i>
                    </div>
                </div>
                <div class="flex items-center justify-between mb-6">
                    <div class="flex items-center">
                        <input type="checkbox" id="remember_me" name="remember_me" class="form-checkbox mr-2 bg-transparent border-gray-500 text-secondary focus:ring-secondary" />
                        <label for="remember_me" class="text-sm text-gray-400 cursor-pointer select-none">Remember me</label>
                    </div>
                    <a href="#" class="text-sm text-secondary hover:underline" onclick="showFeatureModal();return false;">Forgot password?</a>
                </div>
                <button type="submit" class="btn btn-primary w-full !rounded-button mb-4">Sign in</button>
                <div class="text-center text-sm text-gray-400 mb-4">
                    Don't have an account?
                    <a href="signup.php" class="text-secondary hover:underline">Sign up</a>
                </div>
                <div class="divider">
                    <span>Or continue with</span>
                </div>
                <div class="social-login">
                    <button type="button" class="social-btn !rounded-button" onclick="showFeatureModal()">
                        <div class="w-5 h-5 flex items-center justify-center mr-2">
                            <i class="ri-google-fill"></i>
                        </div>
                        Google
                    </button>
                    <button type="button" class="social-btn !rounded-button" onclick="showFeatureModal()">
                        <div class="w-5 h-5 flex items-center justify-center mr-2">
                            <i class="ri-github-fill"></i>
                        </div>
                        GitHub
                    </button>
                </div>
            </form>
        </div>
    </div>

    <!-- Feature Coming Soon Modal -->
    <div id="feature-modal" class="fixed inset-0 flex items-center justify-center bg-black bg-opacity-60 z-50 hidden">
        <div class="bg-[#242424] rounded-lg p-8 shadow-lg text-center max-w-xs w-full">
            <h3 class="text-xl font-semibold text-white mb-4">Coming Soon</h3>
            <p class="text-gray-300 mb-6">Sorry, this feature is not available yet.<br>Coming soon!</p>
            <button onclick="closeFeatureModal()" class="btn btn-primary w-full">OK</button>
        </div>
    </div>

    <script>
        // Toggle password visibility
        function togglePassword() {
            const passwordInput = document.getElementById('password');
            const passwordIcon = document.getElementById('password-icon');
            
            if (passwordInput.type === 'password') {
                passwordInput.type = 'text';
                passwordIcon.className = 'ri-eye-line';
            } else {
                passwordInput.type = 'password';
                passwordIcon.className = 'ri-eye-off-line';
            }
        }
        
        // Toggle checkbox
        function toggleCheckbox(id) {
            const checkbox = document.getElementById(id);
            checkbox.classList.toggle('checked');
        }

        // Feature Coming Soon Modal
        function showFeatureModal() {
            document.getElementById('feature-modal').classList.remove('hidden');
        }
        function closeFeatureModal() {
            document.getElementById('feature-modal').classList.add('hidden');
        }
    </script>
</body>
</html> 