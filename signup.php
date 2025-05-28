<?php
session_start();
require_once 'db.php';

// If user is already logged in, redirect to index.php
if (isset($_SESSION['logged_in']) && $_SESSION['logged_in'] === true) {
    header('Location: index.php');
    exit;
}

$errors = [];

// Handle sign up form submission
if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $email = filter_var(trim($_POST['email']), FILTER_VALIDATE_EMAIL);
    $password = $_POST['password'] ?? '';
    $confirm_password = $_POST['confirm_password'] ?? '';
    $name = isset($_POST['name']) ? trim($_POST['name']) : '';

    // Validate input
    if (!$email) {
        $errors[] = 'Please enter a valid email address.';
    }
    // Password requirements
    $passwordErrors = [];
    if (strlen($password) < 8) {
        $passwordErrors[] = 'at least 8 characters';
    }
    if (!preg_match('/[a-z]/', $password)) {
        $passwordErrors[] = 'a lowercase letter';
    }
    if (!preg_match('/[A-Z]/', $password)) {
        $passwordErrors[] = 'an uppercase letter';
    }
    if (!preg_match('/[0-9]/', $password)) {
        $passwordErrors[] = 'a number';
    }
    if (!preg_match('/[^a-zA-Z0-9]/', $password)) {
        $passwordErrors[] = 'a symbol';
    }
    if (!empty($passwordErrors)) {
        $errors[] = 'The password must contain: <ul style="text-align:left; margin:0.5em 0 0 1.5em;">' .
            implode('', array_map(fn($e) => "<li>".htmlspecialchars($e).".</li>", $passwordErrors)) . '</ul>';
    }
    if ($password !== $confirm_password) {
        $errors[] = 'Passwords do not match.';
    }
    if (empty($name)) {
        $errors[] = 'Please enter your name.';
    }

    // Check if email already exists
    if (empty($errors)) {
        $stmt = $pdo->prepare('SELECT id FROM users WHERE email = ? LIMIT 1');
        $stmt->execute([$email]);
        if ($stmt->fetch()) {
            $errors[] = 'This email is already registered.';
        }
    }

    // If no errors, insert user
    if (empty($errors)) {
        $hashed_password = password_hash($password, PASSWORD_DEFAULT);
        $stmt = $pdo->prepare('INSERT INTO users (email, password, name) VALUES (?, ?, ?)');
        $stmt->execute([$email, $hashed_password, $name]);
        $_SESSION['logged_in'] = true;
        $_SESSION['user'] = $name;
        $_SESSION['user_email'] = $email;
        header('Location: index.php');
        exit;
    }
}
?>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Vaultio | Sign Up</title>
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
        .btn-outline {
            border: 1px solid #444;
            background-color: transparent;
            color: #E5E5E5;
        }
        .btn-outline:hover {
            background-color: #333;
        }
        .error-message {
            background: #ef4444;
            color: #fff;
            padding: 0.75rem 1rem;
            border-radius: 6px;
            margin-bottom: 1rem;
            text-align: center;
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
                <h2 class="text-2xl font-semibold text-white">Create your account</h2>
            </div>
            <?php if (!empty($errors)): ?>
                <div class="error-message">
                    <?php foreach ($errors as $error): ?>
                        <div><?= $error ?></div>
                    <?php endforeach; ?>
                </div>
            <?php endif; ?>
            <form method="POST" action="signup.php" autocomplete="off">
                <div class="input-group">
                    <div class="w-5 h-5 flex items-center justify-center input-icon">
                        <i class="ri-user-line"></i>
                    </div>
                    <input type="text" name="name" class="form-input" placeholder="Full name" required value="<?= isset($_POST['name']) ? htmlspecialchars($_POST['name']) : '' ?>">
                </div>
                <div class="input-group">
                    <div class="w-5 h-5 flex items-center justify-center input-icon">
                        <i class="ri-mail-line"></i>
                    </div>
                    <input type="email" name="email" class="form-input" placeholder="Email address" required value="<?= isset($_POST['email']) ? htmlspecialchars($_POST['email']) : '' ?>">
                </div>
                <div class="input-group">
                    <div class="w-5 h-5 flex items-center justify-center input-icon">
                        <i class="ri-lock-line"></i>
                    </div>
                    <input type="password" id="password" name="password" class="form-input pr-10" placeholder="Password" required>
                    <span class="w-5 h-5 flex items-center justify-center password-toggle absolute right-3 top-1/2 transform -translate-y-1/2 cursor-pointer" onclick="togglePassword('password', 'password-icon')">
                        <i id="password-icon" class="ri-eye-off-line"></i>
                    </span>
                </div>
                <div class="input-group">
                    <div class="w-5 h-5 flex items-center justify-center input-icon">
                        <i class="ri-lock-2-line"></i>
                    </div>
                    <input type="password" id="confirm_password" name="confirm_password" class="form-input pr-10" placeholder="Confirm password" required>
                    <span class="w-5 h-5 flex items-center justify-center password-toggle absolute right-3 top-1/2 transform -translate-y-1/2 cursor-pointer" onclick="togglePassword('confirm_password', 'confirm-password-icon')">
                        <i id="confirm-password-icon" class="ri-eye-off-line"></i>
                    </span>
                </div>
                <button type="submit" class="btn btn-primary w-full !rounded-button mb-4">Sign up</button>
                <div class="text-center text-sm text-gray-400 mb-4">
                    Already have an account?
                    <a href="login.php" class="text-secondary hover:underline">Sign in</a>
                </div>
            </form>
        </div>
    </div>
</body>
</html>
<script>
function togglePassword(inputId, iconId) {
    const input = document.getElementById(inputId);
    const icon = document.getElementById(iconId);
    if (input.type === 'password') {
        input.type = 'text';
        icon.className = 'ri-eye-line';
    } else {
        input.type = 'password';
        icon.className = 'ri-eye-off-line';
    }
}
</script> 