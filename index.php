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


$timeout_duration = 500; 

$hasRememberMeCookie = false;
foreach ($_COOKIE as $name => $value) {
    if (strlen($name) === 64) {
        $hasRememberMeCookie = true;
        break;
    }
}

if (
    isset($_SESSION['LAST_ACTIVITY']) && // Check if session activity timestamp exists
    (time() - $_SESSION['LAST_ACTIVITY']) > $timeout_duration && // Check if inactive for longer than timeout
    !$hasRememberMeCookie // Check if no remember me cookie exists using the flag
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
    <title>Vaultio | Dashboard</title>
    <script src="https://cdn.tailwindcss.com/3.4.16"></script>
    <script>
        tailwind.config = {
            theme: {
                extend: {
                    colors: {
                        primary: '#1E3A8A',
                        secondary: '#0D9488'
                    },
                    borderRadius: {
                        'none': '0px',
                        'sm': '4px',
                        DEFAULT: '8px',
                        'md': '12px',
                        'lg': '16px',
                        'xl': '20px',
                        '2xl': '24px',
                        '3xl': '32px',
                        'full': '9999px',
                        'button': '8px'
                    }
                }
            }
        }
    </script>
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
            z-index: 20; /* Ensure navbar is above content */
            position: relative;
        }
        .dashboard-layout {
            display: flex;
            flex-grow: 1;
        }

        .sidebar {
            width: 240px;
            background-color: #242424;
            border-right: 1px solid #333;
            padding: 1rem;
            flex-shrink: 0;
            transform: translateX(0);
            transition: transform 0.3s ease-in-out;
            z-index: 10;
        }

        .sidebar.hidden-mobile {
             transform: translateX(-100%);
        }

        @media (max-width: 768px) {
            .sidebar {
                position: fixed;
                top: 64px; /* Below navbar */
                bottom: 0;
                left: 0;
                height: calc(100vh - 64px);
                overflow-y: auto;
            }
             .sidebar.hidden-mobile {
                 transform: translateX(-100%);
             }
            .main-content {
                 width: 100%;
            }
        }

        .sidebar a {
            display: flex; /* Use flex for icon and text alignment */
            align-items: center;
            padding: 0.75rem 1rem;
            margin-bottom: 0.5rem;
            border-radius: 6px;
            color: #E5E5E5;
            text-decoration: none;
            transition: background-color 0.2s;
        }

        .sidebar a:hover {
            background-color: #333;
        }

        .sidebar a.active {
            background-color: #1E3A8A;
            color: white;
        }

        .sidebar a i {
            margin-right: 0.75rem; /* Spacing between icon and text */
            font-size: 1.1rem;
        }

        .main-content {
            flex-grow: 1;
            padding: 1.5rem;
            overflow-y: auto;
        }

        .card {
            background-color: #242424;
            border-radius: 8px;
            box-shadow: 0 4px 12px rgba(0, 0, 0, 0.1);
            padding: 1.5rem;
            margin-bottom: 1.5rem;
        }

        /* Added styles for a more refined look */
        .text-secondary {
            color: #0D9488;
        }
        .font-semibold {
             font-weight: 600;
        }

        .tab-active {
            color: #0D9488;
            border-bottom: 2px solid #0D9488;
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
    <div class="app-container">
        <!-- Navbar -->
        <div class="navbar">
            <div class="flex items-center">
                <!-- Mobile menu button -->
                <button id="mobile-menu-button" class="text-gray-400 hover:text-white focus:outline-none mr-4 md:hidden">
                    <i class="ri-menu-line text-xl"></i>
                </button>
                 <img src="vaultioLogo.png" alt="Vaultio Logo" class="h-8 w-auto mr-2" /> <!-- Adjusted margin -->
                <span class="text-xl font-semibold text-white">Vaultio</span>
            </div>
            <div class="flex items-center space-x-4">
                 <!-- Search container - Optional, can be added later -->
                 <!-- <div class="search-container hidden md:block">
                      <div class="w-5 h-5 flex items-center justify-center search-icon">
                          <i class="ri-search-line"></i>
                      </div>
                      <input type="text" class="search-input" placeholder="Search vault...">
                  </div> -->
                <button type="button" class="w-8 h-8 flex items-center justify-center rounded-full bg-gray-700 hover:bg-gray-600 text-gray-400 hover:text-white">
                    <i class="ri-notification-3-line"></i>
                </button>
                <button type="button" class="w-8 h-8 flex items-center justify-center rounded-full bg-gray-700 hover:bg-gray-600 text-gray-400 hover:text-white">
                    <i class="ri-settings-3-line"></i>
                </button>
                <div class="w-9 h-9 flex items-center justify-center rounded-full bg-primary text-white cursor-pointer text-lg font-medium" onclick="showLogoutModal()"> <!-- Slightly larger and centered text -->
                    <?php echo htmlspecialchars(strtoupper(substr($_SESSION['user'] ?? '', 0, 2))); ?> <!-- Ensure user is set and show uppercase initials -->
                </div>
            </div>
        </div>

        <!-- Dashboard Layout -->
        <div class="dashboard-layout">
            <!-- Sidebar -->
            <div id="sidebar" class="sidebar md:block"> <!-- Initially hidden on mobile, shown on medium screens -->
                <?php
                $current_page = basename($_SERVER['PHP_SELF']);
                ?>
                <a href="index.php" class="<?php echo $current_page === 'index.php' ? 'active' : ''; ?>"><i class="ri-dashboard-line"></i> Dashboard</a>
                <a href="passwords.php" class="<?php echo $current_page === 'passwords.php' ? 'active' : ''; ?>"><i class="ri-lock-2-line"></i> Passwords</a>
                <a href="notes.php" class="<?php echo $current_page === 'notes.php' ? 'active' : ''; ?>"><i class="ri-sticky-note-line"></i> Notes</a>
                <a href="archive.php" class="<?php echo $current_page === 'archive.php' ? 'active' : ''; ?>"><i class="ri-archive-line"></i> Archive</a>
                <a href="trash.php" class="<?php echo $current_page === 'trash.php' ? 'active' : ''; ?>"><i class="ri-delete-bin-line"></i> Trash</a>
            </div>

             <!-- Sidebar backdrop for mobile -->
             <div id="sidebar-backdrop" class="fixed inset-0 bg-black bg-opacity-50 z-5 md:hidden hidden" onclick="toggleSidebar()"></div>

            <!-- Main Content -->
            <div class="main-content">
                <h1 class="text-2xl font-semibold text-white mb-6">Dashboard Overview</h1>

                <!-- Placeholder Cards -->
                <div class="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
                    <div class="card">
                        <h2 class="text-lg font-medium mb-2 text-gray-300">Total Passwords</h2>
                        <p class="text-3xl font-bold text-secondary">150</p>
                    </div>
                    <div class="card">
                        <h2 class="text-lg font-medium mb-2 text-gray-300">Total Notes</h2>
                        <p class="text-3xl font-bold text-secondary">35</p>
                    </div>
                    <div class="card">
                        <h2 class="text-lg font-medium mb-2 text-gray-300">Recent Activity</h2>
                        <ul>
                            <li class="text-sm text-gray-400 mb-1">Logged in: Just now</li>
                            <li class="text-sm text-gray-400">Added new password: Google</li>
                        </ul>
                    </div>
                </div>

                <!-- Another Placeholder Section -->
                <div class="card">
                    <h2 class="text-xl font-semibold text-white mb-4">Quick Actions</h2>
                    <div class="flex flex-col sm:flex-row space-y-4 sm:space-y-0 sm:space-x-4">
                        <button class="btn btn-primary !rounded-button"><i class="ri-add-line mr-2"></i> Add Password</button>
                        <button class="btn btn-outline !rounded-button"><i class="ri-add-line mr-2"></i> Add Note</button>
                    </div>
                </div>

                <!-- Placeholder Table (similar to your existing table structure) -->
                <div class="card">
                    <h2 class="text-xl font-semibold text-white mb-4">Recently Added Items</h2>
                    <div class="overflow-x-auto">
                        <table class="w-full">
                            <thead>
                                <tr class="bg-gray-800 text-left">
                                    <th class="py-3 px-4 font-medium text-gray-400">Type</th>
                                    <th class="py-3 px-4 font-medium text-gray-400">Name</th>
                                    <th class="py-3 px-4 font-medium text-gray-400">Created</th>
                                    <th class="py-3 px-4 font-medium text-gray-400">Actions</th>
                                </tr>
                            </thead>
                            <tbody>
                                <tr class="border-b border-gray-700 hover:bg-gray-700">
                                    <td class="py-3 px-4 text-gray-300"><i class="ri-lock-2-line mr-2 text-secondary"></i> Password</td>
                                    <td class="py-3 px-4 text-white">Google</td>
                                    <td class="py-3 px-4 text-gray-400">May 29, 2025</td>
                                    <td class="py-3 px-4">
                                        <div class="flex space-x-2">
                                            <button type="button" class="text-gray-400 hover:text-white" title="View">
                                                <i class="ri-eye-line"></i>
                                            </button>
                                            <button type="button" class="text-gray-400 hover:text-white" title="Edit">
                                                <i class="ri-edit-line"></i>
                                            </button>
                                            <button type="button" class="text-gray-400 hover:text-white" title="Delete">
                                                <i class="ri-delete-bin-line"></i>
                                            </button>
                                        </div>
                                    </td>
                                </tr>
                                <tr class="border-b border-gray-700 hover:bg-gray-700">
                                    <td class="py-3 px-4 text-gray-300"><i class="ri-sticky-note-line mr-2 text-secondary"></i> Note</td>
                                    <td class="py-3 px-4 text-white">Important Ideas</td>
                                    <td class="py-3 px-4 text-gray-400">May 28, 2025</td>
                                    <td class="py-3 px-4">
                                        <div class="flex space-x-2">
                                             <button type="button" class="text-gray-400 hover:text-white" title="View">
                                                <i class="ri-eye-line"></i>
                                            </button>
                                            <button type="button" class="text-gray-400 hover:text-white" title="Edit">
                                                <i class="ri-edit-line"></i>
                                            </button>
                                            <button type="button" class="text-gray-400 hover:text-white" title="Delete">
                                                <i class="ri-delete-bin-line"></i>
                                            </button>
                                        </div>
                                    </td>
                                </tr>
                                <!-- Add more rows as needed -->
                            </tbody>
                        </table>
                    </div>
                </div>

            </div>
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

    </div>

    <script>
        // Toggle sidebar visibility on mobile
        function toggleSidebar() {
            const sidebar = document.getElementById('sidebar');
            const backdrop = document.getElementById('sidebar-backdrop');
            sidebar.classList.toggle('hidden-mobile');
            backdrop.classList.toggle('hidden');
        }

        // Event listener for the mobile menu button
        document.getElementById('mobile-menu-button').addEventListener('click', toggleSidebar);

        // Close sidebar when clicking outside on mobile
        document.getElementById('sidebar-backdrop').addEventListener('click', toggleSidebar);

        // Close sidebar when a link is clicked on mobile
        document.querySelectorAll('#sidebar a').forEach(link => {
            link.addEventListener('click', () => {
                // Only toggle on mobile screens (width < 768px)
                if (window.innerWidth < 768) {
                    const sidebar = document.getElementById('sidebar');
                    if (!sidebar.classList.contains('hidden-mobile')) {
                        toggleSidebar();
                    }
                }
            });
        });


        // Toggle password visibility (if you have password fields in the dashboard)
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
        
        // Toggle checkbox (if you have checkboxes)
        function toggleCheckbox(id) {
            const checkbox = document.getElementById(id);
            checkbox.classList.toggle('checked');
        }
        
        // Logout Modal functions
        function showLogoutModal() {
            document.getElementById('logout-modal').classList.remove('hidden');
        }
        function closeLogoutModal() {
            document.getElementById('logout-modal').classList.add('hidden');
        }
        function logout() {
            window.location.href = 'login.php?logout=1';
        }

    </script>
</body>
</html>