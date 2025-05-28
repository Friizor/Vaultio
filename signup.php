<?php
session_start();

// If user is already logged in, redirect to index.php
if (isset($_SESSION['logged_in']) && $_SESSION['logged_in'] === true) {
    header('Location: index.php');
    exit;
}

// Handle sign up form submission
if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    // Here you would add validation and save the user to your database
    // For demo, just set session and redirect
    $_SESSION['logged_in'] = true;
    $_SESSION['user'] = 'New User'; // Replace with actual user data
    header('Location: index.php');
    exit;
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
            <form method="POST" action="signup.php">
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
                    <input type="password" name="password" class="form-input" placeholder="Password" required>
                </div>
                <div class="input-group">
                    <div class="w-5 h-5 flex items-center justify-center input-icon">
                        <i class="ri-lock-2-line"></i>
                    </div>
                    <input type="password" name="confirm_password" class="form-input" placeholder="Confirm password" required>
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