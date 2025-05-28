<?php
session_start();

// Check if user is already logged in
if (isset($_SESSION['logged_in']) && $_SESSION['logged_in'] === true) {
    header('Location: index.php');
    exit;
}

// Handle login form submission
if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    // Add your authentication logic here
    // For demo purposes, we'll just set the session
    $_SESSION['logged_in'] = true;
    $_SESSION['user'] = 'John Doe'; // Replace with actual user data
    header('Location: index.php');
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
            <form method="POST" action="login.php">
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
                    <div class="checkbox-container">
                        <div id="remember-checkbox" class="custom-checkbox" onclick="toggleCheckbox('remember-checkbox')"></div>
                        <label for="remember-checkbox" class="text-sm text-gray-400">Remember me</label>
                    </div>
                    <a href="#" class="text-sm text-secondary hover:underline">Forgot password?</a>
                </div>
                <button type="submit" class="btn btn-primary w-full !rounded-button mb-4">Sign in</button>
                <div class="divider">
                    <span>Or continue with</span>
                </div>
                <div class="social-login">
                    <button type="button" class="social-btn !rounded-button">
                        <div class="w-5 h-5 flex items-center justify-center mr-2">
                            <i class="ri-google-fill"></i>
                        </div>
                        Google
                    </button>
                    <button type="button" class="social-btn !rounded-button">
                        <div class="w-5 h-5 flex items-center justify-center mr-2">
                            <i class="ri-github-fill"></i>
                        </div>
                        GitHub
                    </button>
                </div>
            </form>
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
    </script>
</body>
</html> 