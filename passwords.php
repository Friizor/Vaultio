<?php
session_start();
require_once 'db.php';

// Authentication check
if (!isset($_SESSION['logged_in']) || $_SESSION['logged_in'] !== true) {
    header('Location: login.php');
    exit;
}

// If user is not logged in, try to auto-login from remember me cookie
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
            }
        }
    }
    // If still not logged in after trying remember me, redirect
    if (!isset($_SESSION['logged_in']) || $_SESSION['logged_in'] !== true) {
        header('Location: login.php');
        exit;
    }
}

// Handle manual logout
if (isset($_GET['logout'])) {
    foreach ($_COOKIE as $name => $value) {
        if (strlen($name) === 64) {
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
    <title>Vaultio | Passwords</title>
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
            z-index: 20;
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
                top: 64px;
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
            display: flex;
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
            margin-right: 0.75rem;
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
        .text-secondary {
            color: #0D9488;
        }
        .font-semibold {
            font-weight: 600;
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
    </style>
</head>
<body>
    <div class="app-container">
        <!-- Navbar -->
        <div class="navbar">
            <div class="flex items-center">
                <button id="mobile-menu-button" class="text-gray-400 hover:text-white focus:outline-none mr-4 md:hidden">
                    <i class="ri-menu-line text-xl"></i>
                </button>
                <img src="vaultioLogo.png" alt="Vaultio Logo" class="h-8 w-auto mr-2" />
                <span class="text-xl font-semibold text-white">Vaultio</span>
            </div>
            <div class="flex items-center space-x-4">
                <button type="button" class="w-8 h-8 flex items-center justify-center rounded-full bg-gray-700 hover:bg-gray-600 text-gray-400 hover:text-white">
                    <i class="ri-notification-3-line"></i>
                </button>
                <button type="button" class="w-8 h-8 flex items-center justify-center rounded-full bg-gray-700 hover:bg-gray-600 text-gray-400 hover:text-white">
                    <i class="ri-settings-3-line"></i>
                </button>
                <div class="w-9 h-9 flex items-center justify-center rounded-full bg-primary text-white cursor-pointer text-lg font-medium" onclick="showLogoutModal()">
                    <?php echo htmlspecialchars(strtoupper(substr($_SESSION['user'] ?? '', 0, 2))); ?>
                </div>
            </div>
        </div>

        <!-- Dashboard Layout -->
        <div class="dashboard-layout">
            <!-- Sidebar -->
            <div id="sidebar" class="sidebar md:block">
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
                <h1 class="text-2xl font-semibold text-white mb-6">Passwords</h1>

                <!-- Search and Filter -->
                <div class="mb-6">
                    <div class="flex flex-col md:flex-row gap-4">
                        <div class="flex-1">
                            <div class="relative">
                                <input type="text" placeholder="Search passwords..." class="w-full px-4 py-2 bg-gray-700 border border-gray-600 rounded-lg text-white focus:outline-none focus:border-secondary">
                                <i class="ri-search-line absolute right-3 top-1/2 transform -translate-y-1/2 text-gray-400"></i>
                            </div>
                        </div>
                        <div class="flex gap-2">
                            <button class="px-4 py-2 bg-gray-700 hover:bg-gray-600 rounded-lg text-white flex items-center">
                                <i class="ri-filter-3-line mr-2"></i> Filter
                            </button>
                            <button class="px-4 py-2 bg-gray-700 hover:bg-gray-600 rounded-lg text-white flex items-center">
                                <i class="ri-sort-asc mr-2"></i> Sort
                            </button>
                        </div>
                    </div>
                </div>

                <!-- Passwords List -->
                <div class="bg-[#242424] rounded-lg overflow-hidden shadow-md mb-6">
                    <div class="overflow-x-auto">
                        <table class="w-full">
                            <thead>
                                <tr class="bg-gray-800 text-left">
                                    <th class="py-2 px-4 border-b border-gray-700">Website</th>
                                    <th class="py-2 px-4 border-b border-gray-700">Username/Email</th>
                                    <th class="py-2 px-4 border-b border-gray-700">Password</th>
                                    <th class="py-2 px-4 border-b border-gray-700">Password Length</th>
                                    <th class="py-2 px-4 border-b border-gray-700">Last Updated</th>
                                    <th class="py-2 px-4 border-b border-gray-700">Actions</th>
                                </tr>
                            </thead>
                            <tbody>
                                <!-- Sample password entries -->
                                <tr class="border-b border-gray-700 hover:bg-gray-700">
                                    <td class="py-2 px-4 border-b border-gray-700">
                                        <div class="flex items-center">
                                            <!-- <?php $website_name = "Google"; ?> -->
                                            <div class="w-8 h-8 flex items-center justify-center rounded-full bg-blue-600 mr-3 text-white text-xs">G</div>
                                            <span class="font-medium text-white">Google</span>
                                        </div>
                                    </td>
                                    <td class="py-2 px-4 border-b border-gray-700 text-sm">user@gmail.com</td>
                                    <td class="py-2 px-4 border-b border-gray-700">
                                        <div class="flex items-center">
                                            <span class="text-gray-300">••••••••</span>
                                            <button type="button" class="ml-2 text-gray-400 hover:text-white">
                                                <div class="w-5 h-5 flex items-center justify-center">
                                                    <i class="ri-eye-line"></i>
                                                </div>
                                            </button>
                                        </div>
                                    </td>
                                    <td class="py-2 px-4 border-b border-gray-700">
                                        <div class="w-24 h-2 bg-gray-700 rounded-full overflow-hidden">
                                            <div class="h-full bg-red-500" style="width: 40%"></div>
                                        </div>
                                    </td>
                                    <td class="py-2 px-4 border-b border-gray-700 text-sm text-gray-400">May 29, 2024</td>
                                    <td class="py-2 px-4 border-b border-gray-700">
                                        <div class="flex space-x-2">
                                             <button type="button" class="text-gray-400 hover:text-white" title="Copy password">
                                                <i class="ri-clipboard-line"></i>
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
                                <!-- Add more sample entries here -->
                                <tr class="border-b border-gray-700 hover:bg-gray-700">
                                    <td class="py-2 px-4 border-b border-gray-700">
                                        <div class="flex items-center">
                                            <!-- <?php $website_name = "Facebook"; ?> -->
                                            <div class="w-8 h-8 flex items-center justify-center rounded-full bg-blue-500 mr-3 text-white text-xs">F</div>
                                            <span class="font-medium text-white">Facebook</span>
                                        </div>
                                    </td>
                                    <td class="py-2 px-4 border-b border-gray-700 text-sm">alex.morgan</td>
                                    <td class="py-2 px-4 border-b border-gray-700">
                                        <div class="flex items-center">
                                            <span class="text-gray-300">••••••••••</span>
                                            <button type="button" class="ml-2 text-gray-400 hover:text-white">
                                                <div class="w-5 h-5 flex items-center justify-center">
                                                    <i class="ri-eye-line"></i>
                                                </div>
                                            </button>
                                        </div>
                                    </td>
                                    <td class="py-2 px-4 border-b border-gray-700">
                                        <div class="w-24 h-2 bg-gray-700 rounded-full overflow-hidden">
                                            <div class="h-full bg-orange-500" style="width: 60%"></div>
                                        </div>
                                    </td>
                                    <td class="py-2 px-4 border-b border-gray-700 text-sm text-gray-400">May 28, 2024</td>
                                    <td class="py-2 px-4 border-b border-gray-700">
                                        <div class="flex space-x-2">
                                             <button type="button" class="text-gray-400 hover:text-white" title="Copy password">
                                                <i class="ri-clipboard-line"></i>
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
                                    <td class="py-2 px-4 border-b border-gray-700">
                                        <div class="flex items-center">
                                            <!-- <?php $website_name = "Netflix"; ?> -->
                                            <div class="w-8 h-8 flex items-center justify-center rounded-full bg-red-600 mr-3 text-white text-xs">N</div>
                                            <span class="font-medium text-white">Netflix</span>
                                        </div>
                                    </td>
                                    <td class="py-2 px-4 border-b border-gray-700 text-sm">user@email.com</td>
                                    <td class="py-2 px-4 border-b border-gray-700">
                                        <div class="flex items-center">
                                            <span class="text-gray-300">••••••••••••</span>
                                            <button type="button" class="ml-2 text-gray-400 hover:text-white">
                                                <div class="w-5 h-5 flex items-center justify-center">
                                                    <i class="ri-eye-line"></i>
                                                </div>
                                            </button>
                                        </div>
                                    </td>
                                    <td class="py-2 px-4 border-b border-gray-700">
                                        <div class="w-24 h-2 bg-gray-700 rounded-full overflow-hidden">
                                            <div class="h-full bg-green-500" style="width: 80%"></div>
                                        </div>
                                    </td>
                                    <td class="py-2 px-4 border-b border-gray-700 text-sm text-gray-400">May 25, 2024</td>
                                    <td class="py-2 px-4 border-b border-gray-700">
                                        <div class="flex space-x-2">
                                             <button type="button" class="text-gray-400 hover:text-white" title="Copy password">
                                                <i class="ri-clipboard-line"></i>
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
                            </tbody>
                        </table>
                    </div>
                </div>
            </div>
        </div>

        <!-- Add Password FAB -->
        <button class="fab" onclick="showAddPasswordModal()">
            <i class="ri-add-line text-2xl"></i>
        </button>

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

        <!-- Add Password Modal -->
        <div id="add-password-modal" class="fixed inset-0 flex items-center justify-center bg-black bg-opacity-60 z-50 hidden" onclick="handleModalClick(event)">
            <div class="bg-[#242424] rounded-lg p-8 shadow-lg max-w-md w-full" onclick="event.stopPropagation()">
                <div class="flex justify-between items-center mb-6">
                    <h3 class="text-lg font-medium text-white">Add New Password</h3>
                    <button type="button" class="text-gray-400 hover:text-white" onclick="closeAddPasswordModal()">
                        <i class="ri-close-line text-xl"></i>
                    </button>
                </div>
                <form id="add-password-form" class="space-y-4">
                    <!-- Website Field -->
                    <div>
                        <label for="website" class="block text-sm font-medium text-gray-300 mb-1">Website/App</label>
                        <input type="text" id="website" name="website" class="w-full px-4 py-2 bg-gray-700 border border-gray-600 rounded-lg text-white focus:outline-none focus:border-secondary" placeholder="e.g., Google, Facebook">
                    </div>

                    <!-- Username/Email Field -->
                    <div>
                        <label for="username" class="block text-sm font-medium text-gray-300 mb-1">Username/Email</label>
                        <input type="text" id="username" name="username" class="w-full px-4 py-2 bg-gray-700 border border-gray-600 rounded-lg text-white focus:outline-none focus:border-secondary" placeholder="Enter username or email">
                    </div>

                    <!-- Password Field -->
                    <div>
                        <label for="password" class="block text-sm font-medium text-gray-300 mb-1">Password</label>
                        <div class="relative">
                            <input type="password" id="password" name="password" class="w-full px-4 py-2 bg-gray-700 border border-gray-600 rounded-lg text-white focus:outline-none focus:border-secondary pr-10" placeholder="Enter password">
                            <button type="button" class="absolute right-3 top-1/2 transform -translate-y-1/2 text-gray-400 hover:text-white" onclick="togglePasswordVisibility()">
                                <i class="ri-eye-line"></i>
                            </button>
                        </div>
                    </div>

                    <!-- Password Strength Indicator -->
                    <div>
                        <label class="block text-sm font-medium text-gray-300 mb-1">Password Strength</label>
                        <div class="w-full h-2 bg-gray-700 rounded-full overflow-hidden">
                            <div id="password-strength-bar" class="h-full transition-all duration-300" style="width: 0%"></div>
                        </div>
                        <p id="password-strength-text" class="mt-1 text-sm text-gray-400">Enter a password to check strength</p>
                    </div>

                    <!-- Generate Password Button -->
                    <div>
                        <button type="button" class="w-full px-4 py-2 bg-gray-700 hover:bg-gray-600 rounded-lg text-white flex items-center justify-center" onclick="generatePassword()">
                            <i class="ri-refresh-line mr-2"></i> Generate Strong Password
                        </button>
                    </div>

                    <!-- Submit Button -->
                    <div class="flex space-x-2 pt-4">
                        <button type="button" class="flex-1 px-4 py-2 bg-gray-700 hover:bg-gray-600 rounded-lg text-white" onclick="closeAddPasswordModal()">Cancel</button>
                        <button type="submit" class="flex-1 px-4 py-2 bg-secondary hover:bg-teal-600 rounded-lg text-white">Save Password</button>
                    </div>
                </form>
            </div>
        </div>
    </div>

    <script>
        let activityTimeout;
        const timeoutDuration = 15 * 60 * 1000; // 15 minutes in milliseconds

        function resetActivityTimeout() {
            console.log('Activity detected, resetting timeout.');
            clearTimeout(activityTimeout);

            // Check for remember me cookie before setting timeout
            // Look for a cookie name that is 64 characters long (SHA-256 hash)
            const rememberMeCookieExists = Object.keys(document.cookie.split('; ').reduce((acc, cookie) => {
                const [name, value] = cookie.split('=');
                acc[name] = value;
                return acc;
            }, {})).some(name => name.length === 64);

            if (!rememberMeCookieExists) {
                activityTimeout = setTimeout(logout, timeoutDuration);
            }
        }

        // Set up event listeners for user activity
        window.onload = resetActivityTimeout;
        document.onmousemove = resetActivityTimeout;
        document.onkeypress = resetActivityTimeout;
        document.onmousedown = resetActivityTimeout;
        document.ontouchstart = resetActivityTimeout;
        document.onclick = resetActivityTimeout;
        document.onscroll = resetActivityTimeout;
        document.onfocus = resetActivityTimeout;

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

        // Add Password Modal functions
        function showAddPasswordModal() {
            document.getElementById('add-password-modal').classList.remove('hidden');
        }

        function closeAddPasswordModal() {
            document.getElementById('add-password-modal').classList.add('hidden');
            document.getElementById('add-password-form').reset();
            document.getElementById('password-strength-bar').style.width = '0%';
            document.getElementById('password-strength-text').textContent = 'Enter a password to check strength';
            document.getElementById('password-strength-bar').className = 'h-full transition-all duration-300';
        }

        function handleModalClick(event) {
            // Close modal if clicking the backdrop (outside the form container)
            if (event.target.id === 'add-password-modal') {
                closeAddPasswordModal();
            }
        }

        function togglePasswordVisibility() {
            const passwordInput = document.getElementById('password');
            const icon = document.querySelector('#password + button i');
            if (passwordInput.type === 'password') {
                passwordInput.type = 'text';
                icon.className = 'ri-eye-off-line';
            } else {
                passwordInput.type = 'password';
                icon.className = 'ri-eye-line';
            }
        }

        function checkPasswordStrength(password) {
            let strength = 0;
            const feedback = [];

            // Length check
            if (password.length >= 8) {
                strength += 25;
            } else {
                feedback.push('At least 8 characters');
            }

            // Lowercase check
            if (/[a-z]/.test(password)) {
                strength += 25;
            } else {
                feedback.push('Lowercase letter');
            }

            // Uppercase check
            if (/[A-Z]/.test(password)) {
                strength += 25;
            } else {
                feedback.push('Uppercase letter');
            }

            // Number check
            if (/[0-9]/.test(password)) {
                strength += 12.5;
            } else {
                feedback.push('Number');
            }

            // Special character check
            if (/[^A-Za-z0-9]/.test(password)) {
                strength += 12.5;
            } else {
                feedback.push('Special character');
            }

            // Update strength bar
            const strengthBar = document.getElementById('password-strength-bar');
            const strengthText = document.getElementById('password-strength-text');

            strengthBar.style.width = strength + '%';
            
            if (strength <= 25) {
                strengthBar.className = 'h-full bg-red-500 transition-all duration-300';
                strengthText.textContent = 'Weak - ' + feedback.join(', ');
            } else if (strength <= 50) {
                strengthBar.className = 'h-full bg-orange-500 transition-all duration-300';
                strengthText.textContent = 'Medium - ' + feedback.join(', ');
            } else if (strength <= 75) {
                strengthBar.className = 'h-full bg-yellow-500 transition-all duration-300';
                strengthText.textContent = 'Good - ' + feedback.join(', ');
            } else {
                strengthBar.className = 'h-full bg-green-500 transition-all duration-300';
                strengthText.textContent = 'Strong password!';
            }
        }

        function generatePassword() {
            const length = 16;
            const charset = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#$%^&*()_+~`|}{[]:;?><,./-=";
            let password = "";
            
            // Ensure at least one of each required character type
            password += charset.match(/[a-z]/)[0]; // lowercase
            password += charset.match(/[A-Z]/)[0]; // uppercase
            password += charset.match(/[0-9]/)[0]; // number
            password += charset.match(/[^A-Za-z0-9]/)[0]; // special

            // Fill the rest randomly
            for (let i = 4; i < length; i++) {
                const randomIndex = Math.floor(Math.random() * charset.length);
                password += charset[randomIndex];
            }

            // Shuffle the password
            password = password.split('').sort(() => Math.random() - 0.5).join('');

            // Set the password and check its strength
            const passwordInput = document.getElementById('password');
            passwordInput.value = password;
            checkPasswordStrength(password);
        }

        // Add event listener for password strength checking
        document.getElementById('password').addEventListener('input', function(e) {
            checkPasswordStrength(e.target.value);
        });

        // Add event listener for form submission
        document.getElementById('add-password-form').addEventListener('submit', function(e) {
            e.preventDefault();
            // TODO: Add password saving logic
            closeAddPasswordModal();
        });

        // Reset timeout on modal interactions
        document.getElementById('add-password-modal').addEventListener('mousemove', resetActivityTimeout);
        document.getElementById('add-password-modal').addEventListener('keypress', resetActivityTimeout);
    </script>
</body>
</html> 