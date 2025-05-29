<?php
session_start();
require_once 'db.php';

// If user is not logged in, try to auto-login from remember me cookie
// This block runs *before* the inactivity check
if (!isset($_SESSION['logged_in']) || $_SESSION['logged_in'] !== true) {
    // Find the remember me cookie by checking all cookies
    $remember_cookie = null;
    foreach ($_COOKIE as $name => $value) {
        if (strlen($name) === 64) { // SHA-256 hash is 64 characters
            $remember_cookie = $value;
            $cookie_name = $name;
            break;
        }
    }

    if ($remember_cookie) {
        list($selector, $validator) = explode(':', $remember_cookie);
        $stmt = $pdo->prepare('SELECT user_id, hashed_validator, expires FROM user_tokens WHERE selector = ? LIMIT 1');
        $stmt->execute([$selector]);
        $token = $stmt->fetch();
        if ($token && hash_equals($token['hashed_validator'], hash('sha256', $validator)) && strtotime($token['expires']) > time()) {
            // Token is valid, log user in
            $stmt = $pdo->prepare('SELECT * FROM users WHERE id = ? LIMIT 1');
            $stmt->execute([$token['user_id']]);
            $user = $stmt->fetch();
            if ($user) {
                $_SESSION['logged_in'] = true;
                $_SESSION['user'] = $user['name'];
                $_SESSION['user_email'] = $user['email'];
                $_SESSION['user_id'] = $user['id'];
                // Rotate token (optional but recommended)
                $new_selector = bin2hex(random_bytes(6));
                $new_validator = bin2hex(random_bytes(32));
                $hashed_validator = hash('sha256', $new_validator);
                $expires = date('Y-m-d H:i:s', time() + 60 * 60 * 24 * 5); // 5 days
                $pdo->prepare('DELETE FROM user_tokens WHERE selector = ?')->execute([$selector]);
                $pdo->prepare('INSERT INTO user_tokens (user_id, selector, hashed_validator, expires) VALUES (?, ?, ?, ?)')->execute([$user['id'], $new_selector, $hashed_validator, $expires]);
                // Set new cookie with new hashed timestamp
                $new_cookie_name = hash('sha256', time());
                setcookie($new_cookie_name, "$new_selector:$new_validator", time() + 60 * 60 * 24 * 5, '/', '', isset($_SERVER['HTTPS']), true);
                // Clear old cookie
                setcookie($cookie_name, '', time() - 3600, '/');
            }
        } else {
            // Invalid token, clear cookie
            setcookie($cookie_name, '', time() - 3600, '/');
        }
    }
    // If still not logged in after trying remember me, redirect
    if (!isset($_SESSION['logged_in']) || $_SESSION['logged_in'] !== true) {
         header('Location: login.php');
         exit;
    }
}

// Auto logout after 5 minutes of inactivity *only if no rememberme cookie*
$timeout_duration = 20; // 5 minutes in seconds
if (
    isset($_SESSION['LAST_ACTIVITY']) && // Check if session activity timestamp exists
    (time() - $_SESSION['LAST_ACTIVITY']) > $timeout_duration && // Check if inactive for longer than timeout
    !array_filter($_COOKIE, function($name) { return strlen($name) === 64; }) // Check if no remember me cookie exists
) {
    // Inactive and no rememberme cookie, log out
    session_unset();
    session_destroy();
    header('Location: login.php?timeout=1');
    exit;
}

// Update last activity timestamp (This always runs for active sessions)
$_SESSION['LAST_ACTIVITY'] = time();

// Handle manual logout
if (isset($_GET['logout'])) {
    // Clear session and remember me token/cookie
    foreach ($_COOKIE as $name => $value) {
        if (strlen($name) === 64) { // SHA-256 hash is 64 characters
            list($selector) = explode(':', $value);
            $pdo->prepare('DELETE FROM user_tokens WHERE selector = ?')->execute([$selector]);
            setcookie($name, '', time() - 3600, '/');
        }
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
    <title>Vaultio | Password and Notes Management</title>
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
        .app-container {
            display: flex;
            flex-direction: column;
            min-height: 100vh;
        }
        .navbar {
            display: flex;
            align-items: center;
            justify-content: space-between;
            padding: 0.75rem 1.5rem;
            background-color: #242424;
            box-shadow: 0 2px 10px rgba(0, 0, 0, 0.2);
        }
        .sidebar {
            width: 240px;
            background-color: #242424;
            border-right: 1px solid #333;
            padding: 1rem;
        }
        .content {
            flex: 1;
            padding: 1.5rem;
            overflow-y: auto;
        }
        .tab-active {
            color: #0D9488;
            border-bottom: 2px solid #0D9488;
        }
        .card {
            background-color: #242424;
            border-radius: 8px;
            box-shadow: 0 4px 12px rgba(0, 0, 0, 0.1);
            padding: 1.5rem;
            margin-bottom: 1rem;
        }
        .tag {
            display: inline-flex;
            align-items: center;
            padding: 0.25rem 0.75rem;
            border-radius: 9999px;
            font-size: 0.75rem;
            background-color: rgba(13, 148, 136, 0.2);
            color: #0D9488;
            margin-right: 0.5rem;
            margin-bottom: 0.5rem;
        }
        .password-item {
            display: flex;
            align-items: center;
            padding: 1rem;
            border-bottom: 1px solid #333;
        }
        .password-item:hover {
            background-color: #2a2a2a;
        }
        .password-strength {
            width: 60px;
            height: 4px;
            background-color: #333;
            border-radius: 2px;
            overflow: hidden;
        }
        .strength-indicator {
            height: 100%;
            border-radius: 2px;
        }
        .strength-weak {
            width: 30%;
            background-color: #ef4444;
        }
        .strength-medium {
            width: 60%;
            background-color: #f59e0b;
        }
        .strength-strong {
            width: 100%;
            background-color: #10b981;
        }
        .modal {
            position: fixed;
            top: 0;
            left: 0;
            right: 0;
            bottom: 0;
            background-color: rgba(0, 0, 0, 0.7);
            display: flex;
            align-items: center;
            justify-content: center;
            z-index: 50;
        }
        .modal-content {
            background-color: #242424;
            border-radius: 12px;
            box-shadow: 0 10px 25px rgba(0, 0, 0, 0.5);
            width: 100%;
            max-width: 500px;
            max-height: 90vh;
            overflow-y: auto;
        }
        .modal-header {
            padding: 1.25rem 1.5rem;
            border-bottom: 1px solid #333;
            display: flex;
            align-items: center;
            justify-content: space-between;
        }
        .modal-body {
            padding: 1.5rem;
        }
        .modal-footer {
            padding: 1rem 1.5rem;
            border-top: 1px solid #333;
            display: flex;
            justify-content: flex-end;
            gap: 0.75rem;
        }
        .note-editor {
            background-color: #333;
            border-radius: 8px;
            border: 1px solid #444;
            min-height: 200px;
            padding: 1rem;
            margin-bottom: 1rem;
        }
        .toolbar {
            display: flex;
            gap: 0.5rem;
            margin-bottom: 0.75rem;
            padding-bottom: 0.75rem;
            border-bottom: 1px solid #444;
        }
        .toolbar-btn {
            display: flex;
            align-items: center;
            justify-content: center;
            width: 32px;
            height: 32px;
            border-radius: 4px;
            color: #ccc;
            background-color: transparent;
            transition: all 0.2s;
        }
        .toolbar-btn:hover {
            background-color: #444;
            color: white;
        }
        .password-generator {
            background-color: #333;
            border-radius: 8px;
            padding: 1rem;
            margin-bottom: 1rem;
        }
        .range-slider {
            width: 100%;
            height: 4px;
            background-color: #444;
            border-radius: 2px;
            outline: none;
            appearance: none;
            -webkit-appearance: none;
        }
        .range-slider::-webkit-slider-thumb {
            -webkit-appearance: none;
            width: 16px;
            height: 16px;
            border-radius: 50%;
            background-color: #0D9488;
            cursor: pointer;
        }
        .checkbox-container {
            display: flex;
            align-items: center;
            margin-bottom: 0.5rem;
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
        .logout-warning {
            position: fixed;
            bottom: 20px;
            right: 20px;
            background-color: #242424;
            border-radius: 8px;
            box-shadow: 0 4px 20px rgba(0, 0, 0, 0.3);
            padding: 1rem;
            width: 300px;
            z-index: 40;
        }
        .countdown {
            width: 100%;
            height: 4px;
            background-color: #333;
            border-radius: 2px;
            margin-bottom: 1rem;
            overflow: hidden;
        }
        .countdown-progress {
            height: 100%;
            background-color: #0D9488;
            border-radius: 2px;
            width: 70%;
        }
        .search-container {
            position: relative;
            width: 100%;
            max-width: 400px;
        }
        .search-input {
            width: 100%;
            padding: 0.5rem 1rem;
            padding-left: 2.5rem;
            background-color: #333;
            border: 1px solid #444;
            border-radius: 8px;
            color: #E5E5E5;
        }
        .search-icon {
            position: absolute;
            left: 0.75rem;
            top: 50%;
            transform: translateY(-50%);
            color: #999;
        }
        .fab {
            position: fixed;
            bottom: 2rem;
            right: 2rem;
            width: 56px;
            height: 56px;
            border-radius: 28px;
            background-color: #0D9488;
            color: white;
            display: flex;
            align-items: center;
            justify-content: center;
            box-shadow: 0 4px 12px rgba(13, 148, 136, 0.4);
            cursor: pointer;
            transition: all 0.2s;
        }
        .fab:hover {
            background-color: #0ca69a;
            transform: translateY(-2px);
        }
        .switch {
            position: relative;
            display: inline-block;
            width: 44px;
            height: 22px;
        }
        .switch input {
            opacity: 0;
            width: 0;
            height: 0;
        }
        .slider {
            position: absolute;
            cursor: pointer;
            top: 0;
            left: 0;
            right: 0;
            bottom: 0;
            background-color: #444;
            transition: .4s;
            border-radius: 22px;
        }
        .slider:before {
            position: absolute;
            content: "";
            height: 18px;
            width: 18px;
            left: 2px;
            bottom: 2px;
            background-color: white;
            transition: .4s;
            border-radius: 50%;
        }
        input:checked + .slider {
            background-color: #0D9488;
        }
        input:checked + .slider:before {
            transform: translateX(22px);
        }
        @media (max-width: 768px) {
            .sidebar {
                display: none;
            }
            .password-item {
                flex-direction: column;
                align-items: flex-start;
            }
            .password-actions {
                margin-top: 0.75rem;
                width: 100%;
                display: flex;
                justify-content: flex-end;
            }
            .modal-content {
                max-width: 95%;
            }
        }
    </style>
</head>
<body>
    <!-- Main Dashboard -->
    <div class="app-container">
        <!-- Navbar -->
        <div class="navbar">
            <div class="flex items-center">
                <h1 class="text-xl font-['Pacifico'] text-white mr-8">Vaultio</h1>
                <div class="hidden md:flex space-x-4">
                    <a href="#" class="text-white hover:text-secondary">Dashboard</a>
                    <a href="#" class="text-gray-400 hover:text-secondary">Recent</a>
                    <a href="#" class="text-gray-400 hover:text-secondary">Favorites</a>
                </div>
            </div>
            <div class="search-container hidden md:block">
                <div class="w-5 h-5 flex items-center justify-center search-icon">
                    <i class="ri-search-line"></i>
                </div>
                <input type="text" class="search-input" placeholder="Search vault...">
            </div>
            <div class="flex items-center space-x-4">
                <button type="button" class="w-8 h-8 flex items-center justify-center rounded-full bg-gray-700 hover:bg-gray-600">
                    <i class="ri-notification-3-line"></i>
                </button>
                <button type="button" class="w-8 h-8 flex items-center justify-center rounded-full bg-gray-700 hover:bg-gray-600">
                    <i class="ri-settings-3-line"></i>
                </button>
                <div class="w-8 h-8 flex items-center justify-center rounded-full bg-primary text-white cursor-pointer" onclick="showLogoutModal()">
                    <span class="text-sm font-medium"><?php echo substr($_SESSION['user'], 0, 2); ?></span>
                </div>
            </div>
        </div>

        <!-- Rest of your existing dashboard content -->
        <!-- ... (keep all the existing dashboard content) ... -->

    </div>

    <!-- Logout Modal -->
    <div id="logout-modal" class="fixed inset-0 flex items-center justify-center bg-black bg-opacity-60 z-50 hidden">
        <div class="bg-[#242424] rounded-lg p-8 shadow-lg text-center max-w-xs w-full">
            <h3 class="text-lg font-medium text-white mb-2">Logout</h3>
            <p class="text-gray-400 text-sm mb-4">Are you sure you want to logout?</p>
            <div class="flex space-x-2">
                <button type="button" class="btn btn-outline flex-1 !rounded-button" onclick="closeLogoutModal()">Cancel</button>
                <button type="button" class="btn btn-primary flex-1 !rounded-button" onclick="logout()">Logout</button>
            </div>
        </div>
    </div>

    <!-- Auto Logout Warning -->
    <!-- Keeping this for reference/potential future use, but will use the combined logic now -->
    <div id="logout-warning" class="logout-warning hidden">
        <div class="countdown">
            <div class="countdown-progress"></div>
        </div>
        <h4 class="text-lg font-medium text-white mb-2">Session Timeout</h4>
        <p class="text-gray-400 text-sm mb-4">Your session will expire in 2 minutes due to inactivity.</p>
        <div class="flex space-x-2">
            <button type="button" class="btn btn-outline flex-1 !rounded-button" onclick="logout()">Logout</button>
            <button type="button" class="btn btn-primary flex-1 !rounded-button" onclick="staySignedIn()">Stay Signed In</button>
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
        
        // Toggle master key visibility
        function toggleMasterKey() {
            const masterKeyInput = document.getElementById('master-key');
            const masterKeyIcon = document.getElementById('master-key-icon');
            
            if (masterKeyInput.type === 'password') {
                masterKeyInput.type = 'text';
                masterKeyIcon.className = 'ri-eye-line';
            } else {
                masterKeyInput.type = 'password';
                masterKeyIcon.className = 'ri-eye-off-line';
            }
        }
        
        // Toggle new password visibility
        function toggleNewPassword() {
            const newPasswordInput = document.getElementById('new-password');
            const newPasswordIcon = document.getElementById('new-password-icon');
            
            if (newPasswordInput.type === 'password') {
                newPasswordInput.type = 'text';
                newPasswordIcon.className = 'ri-eye-line';
            } else {
                newPasswordInput.type = 'password';
                newPasswordIcon.className = 'ri-eye-off-line';
            }
        }
        
        // Toggle checkbox
        function toggleCheckbox(id) {
            const checkbox = document.getElementById(id);
            checkbox.classList.toggle('checked');
        }
        
        // Show master key modal
        function showMasterKeyModal() {
            document.getElementById('master-key-modal').classList.remove('hidden');
        }
        
        // Close master key modal
        function closeMasterKeyModal() {
            document.getElementById('master-key-modal').classList.add('hidden');
        }
        
        // Unlock vault and show dashboard
        function unlockVault() {
            document.getElementById('login-screen').classList.add('hidden');
            document.getElementById('master-key-modal').classList.add('hidden');
            document.getElementById('dashboard').classList.remove('hidden');
        }
        
        // Switch between tabs
        function switchTab(tab) {
            // Update tab buttons
            document.getElementById('notes-tab').classList.remove('tab-active');
            document.getElementById('passwords-tab').classList.remove('tab-active');
            document.getElementById(tab + '-tab').classList.add('tab-active');
            
            // Update content
            document.getElementById('notes-content').classList.add('hidden');
            document.getElementById('passwords-content').classList.add('hidden');
            document.getElementById(tab + '-content').classList.remove('hidden');
        }
        
        // Show note editor
        function showNoteEditor() {
            document.getElementById('note-editor-modal').classList.remove('hidden');
        }
        
        // Close note editor
        function closeNoteEditor() {
            document.getElementById('note-editor-modal').classList.add('hidden');
        }
        
        // Show password modal
        function showPasswordModal() {
            document.getElementById('password-modal').classList.remove('hidden');
        }
        
        // Close password modal
        function closePasswordModal() {
            document.getElementById('password-modal').classList.add('hidden');
        }
        
        // Show logout warning
        function showLogoutWarning() {
            document.getElementById('logout-warning').classList.remove('hidden');
        }
        
        // Stay signed in
        function staySignedIn() {
            document.getElementById('logout-warning').classList.add('hidden');
        }
        
        // Logout
        function logout() {
            window.location.href = 'index.php?logout=1';
        }
        
        // Show logout modal
        function showLogoutModal() {
            document.getElementById('logout-modal').classList.remove('hidden');
        }
        
        // Close logout modal
        function closeLogoutModal() {
            document.getElementById('logout-modal').classList.add('hidden');
        }
        
        // Auto logout on inactivity (frontend) - Only if no rememberme cookie
        let logoutTimeout;
        function resetLogoutTimer() {
            // Clear any existing timer
            clearTimeout(logoutTimeout);

            // Check if any cookie with 64-character name exists (our remember me cookie)
            const hasRememberMeCookie = document.cookie.split(';').some((item) => {
                const [name] = item.trim().split('=');
                return name.length === 64;
            });

            // If no rememberme cookie, set the inactivity timer
            if (!hasRememberMeCookie) {
                logoutTimeout = setTimeout(() => {
                    window.location.href = 'index.php?logout=1';
                }, 300000); // 5 minutes (300000 ms)
            }
        }

        // Reset the timer on user activity
        ['click', 'mousemove', 'keydown', 'scroll', 'touchstart'].forEach(evt => {
            document.addEventListener(evt, resetLogoutTimer, true);
        });

        // Initial timer start (only if no rememberme cookie exists on load)
        document.addEventListener('DOMContentLoaded', function() {
             const hasRememberMeCookie = document.cookie.split(';').some((item) => {
                const [name] = item.trim().split('=');
                return name.length === 64;
             });
             if (!hasRememberMeCookie) {
                 resetLogoutTimer();
             }
             
             // Set the active tab initially
             switchTab('passwords');
        });
    </script>
</body>
</html> 