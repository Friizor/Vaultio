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
    <title>Vaultio | Cards</title>
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
            background-color: #333; /* Dark background */
            color: #0D9488; /* Secondary color */
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
        /* Styles for search, filter, sort copied from passwords.php, adapted for cards */
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
        #filter-dropdown, #sort-dropdown {
            position: absolute;
            background-color: #242424;
            border-radius: 8px;
            box-shadow: 0 4px 12px rgba(0, 0, 0, 0.1);
            border: 1px solid #333;
            z-index: 50;
            padding: 0.5rem;
        }
        #filter-dropdown h3, #sort-dropdown h3 {
            color: #999;
            font-size: 0.875rem;
            margin-bottom: 0.5rem;
            padding: 0 0.5rem;
        }
        .filter-type, .sort-option {
             width: 100%;
             text-align: left;
             padding: 0.5rem 0.75rem;
             border-radius: 4px;
             color: #E5E5E5;
             transition: background-color 0.2s;
        }
         .filter-type:hover, .sort-option:hover {
             background-color: #333;
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
                <a href="cards.php" class="<?php echo $current_page === 'cards.php' ? 'active' : ''; ?>"><i class="ri-bank-card-line"></i> Cards</a>
                <a href="notes.php" class="<?php echo $current_page === 'notes.php' ? 'active' : ''; ?>"><i class="ri-sticky-note-line"></i> Notes</a>
                <a href="archive.php" class="<?php echo $current_page === 'archive.php' ? 'active' : ''; ?>"><i class="ri-archive-line"></i> Archive</a>
                <a href="trash.php" class="<?php echo $current_page === 'trash.php' ? 'active' : ''; ?>"><i class="ri-delete-bin-line"></i> Trash</a>
            </div>

            <!-- Sidebar backdrop for mobile -->
            <div id="sidebar-backdrop" class="fixed inset-0 bg-black bg-opacity-50 z-5 md:hidden hidden" onclick="toggleSidebar()"></div>

            <!-- Main Content -->
            <div class="main-content">
                <h1 class="text-2xl font-semibold text-white mb-6">Cards</h1>

                <!-- Search and Filter -->
                <div class="mb-6">
                    <div class="flex flex-col md:flex-row gap-4">
                        <div class="flex-1">
                            <div class="relative">
                                <input type="text" id="search-input" placeholder="Search cards..." class="w-full px-4 py-2 bg-gray-700 border border-gray-600 rounded-lg text-white focus:outline-none focus:border-secondary">
                                <i class="ri-search-line absolute right-3 top-1/2 transform -translate-y-1/2 text-gray-400"></i>
                            </div>
                        </div>
                        <div class="flex gap-2">
                             <div class="relative">
                                <button id="filter-button" class="px-4 py-2 bg-gray-700 hover:bg-gray-600 rounded-lg text-white flex items-center">
                                    <i class="ri-filter-3-line mr-2"></i> Filter
                                </button>
                                <div id="filter-dropdown" class="absolute left-0 mt-2 w-48 bg-[#242424] rounded-lg shadow-lg border border-gray-700 hidden z-50">
                                    <div class="p-2">
                                        <h3 class="text-sm font-medium text-gray-300 mb-2">Filter by Type</h3>
                                        <div class="space-y-1">
                                            <button class="w-full text-left px-3 py-2 text-sm text-gray-300 hover:bg-gray-700 rounded-md filter-type" data-type="all">
                                                All Types
                                            </button>
                                            <button class="w-full text-left px-3 py-2 text-sm text-gray-300 hover:bg-gray-700 rounded-md filter-type" data-type="Credit Card">
                                                Credit Card
                                            </button>
                                            <button class="w-full text-left px-3 py-2 text-sm text-gray-300 hover:bg-gray-700 rounded-md filter-type" data-type="Debit Card">
                                                Debit Card
                                            </button>
                                            <!-- Add more types if needed -->
                                        </div>
                                    </div>
                                </div>
                            </div>
                            <div class="relative">
                                <button id="sort-button" class="px-4 py-2 bg-gray-700 hover:bg-gray-600 rounded-lg text-white flex items-center">
                                    <i class="ri-sort-asc mr-2"></i> Sort
                                </button>
                                <div id="sort-dropdown" class="absolute right-0 mt-2 w-48 bg-[#242424] rounded-lg shadow-lg border border-gray-700 hidden z-50">
                                    <div class="p-2">
                                        <h3 class="text-sm font-medium text-gray-300 mb-2">Sort by</h3>
                                        <div class="space-y-1">
                                            <button class="w-full text-left px-3 py-2 text-sm text-gray-300 hover:bg-gray-700 rounded-md sort-option" data-sort="name" data-order="asc">
                                                <i class="ri-sort-alpha-asc mr-2"></i> Name (A-Z)
                                            </button>
                                            <button class="w-full text-left px-3 py-2 text-sm text-gray-300 hover:bg-gray-700 rounded-md sort-option" data-sort="name" data-order="desc">
                                                <i class="ri-sort-alpha-desc mr-2"></i> Name (Z-A)
                                            </button>
                                            <button class="w-full text-left px-3 py-2 text-sm text-gray-300 hover:bg-gray-700 rounded-md sort-option" data-sort="date" data-order="desc">
                                                <i class="ri-sort-desc mr-2"></i> Recently Added
                                            </button>
                                            <button class="w-full text-left px-3 py-2 text-sm text-gray-300 hover:bg-gray-700 rounded-md sort-option" data-sort="date" data-order="asc">
                                                <i class="ri-sort-asc mr-2"></i> Oldest First
                                            </button>
                                        </div>
                                    </div>
                                </div>
                            </div>
                        </div>
                    </div>
                </div>

                <!-- Add Cards content here -->

            </div>
        </div>

        <!-- Add Card FAB -->
        <button class="fab" onclick="showAddCardModal()">
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

        // Add Card Modal functions (to be implemented)
        function showAddCardModal() {
            // TODO: Implement add card modal
            alert('Add Card functionality coming soon!');
        }

        // Reset timeout on modal interactions
        document.getElementById('logout-modal').addEventListener('mousemove', resetActivityTimeout);
        document.getElementById('logout-modal').addEventListener('keypress', resetActivityTimeout);

        // Add filter functionality for cards
        document.getElementById('filter-button').addEventListener('click', function(e) {
            e.stopPropagation();
            const dropdown = document.getElementById('filter-dropdown');
            if (dropdown) {
                dropdown.classList.toggle('hidden');
            }
        });

        // Close filter dropdown when clicking outside
        document.addEventListener('click', function(e) {
            const dropdown = document.getElementById('filter-dropdown');
            const filterButton = document.getElementById('filter-button');
            if (dropdown && filterButton && !dropdown.contains(e.target) && !filterButton.contains(e.target)) {
                dropdown.classList.add('hidden');
            }
        });

        // Handle type filtering (placeholder for cards)
        document.querySelectorAll('.filter-type').forEach(button => {
            button.addEventListener('click', function() {
                const selectedType = this.dataset.type;
                console.log('Filter cards by type:', selectedType);
                // TODO: Implement actual filtering logic for cards based on selectedType
                const dropdown = document.getElementById('filter-dropdown');
                if (dropdown) {
                    dropdown.classList.add('hidden');
                }
            });
        });

        // Add sort functionality for cards
        document.getElementById('sort-button').addEventListener('click', function(e) {
            e.stopPropagation();
            const dropdown = document.getElementById('sort-dropdown');
            if (dropdown) {
                 dropdown.classList.toggle('hidden');
            }
        });

        // Close sort dropdown when clicking outside
        document.addEventListener('click', function(e) {
            const dropdown = document.getElementById('sort-dropdown');
            const sortButton = document.getElementById('sort-button');
            if (dropdown && sortButton && !dropdown.contains(e.target) && !sortButton.contains(e.target)) {
                dropdown.classList.add('hidden');
            }
        });

        // Handle sorting (placeholder for cards)
        document.querySelectorAll('.sort-option').forEach(button => {
            button.addEventListener('click', function() {
                const sortBy = this.dataset.sort;
                const order = this.dataset.order;
                console.log('Sort cards by:', sortBy, order);
                // TODO: Implement actual sorting logic for cards
                 const dropdown = document.getElementById('sort-dropdown');
                 if (dropdown) {
                    dropdown.classList.add('hidden');
                 }
            });
        });

        // Add search functionality for cards
        document.getElementById('search-input').addEventListener('input', function(e) {
            const searchTerm = e.target.value.toLowerCase();
            console.log('Search cards for:', searchTerm);
            // TODO: Implement actual search logic for cards
        });

        // Reset timeout on search input
        document.getElementById('search-input').addEventListener('input', resetActivityTimeout);
    </script>
</body>
</html> 