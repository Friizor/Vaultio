<?php
session_start();
require_once 'db.php';

// Debug information
error_log("Session data: " . print_r($_SESSION, true));
error_log("POST data: " . print_r($_POST, true));
error_log("Request method: " . $_SERVER['REQUEST_METHOD']);

// Handle AJAX request to fetch single password data
if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['action']) && $_POST['action'] === 'fetch_password') {
    header('Content-Type: application/json');
    // Allow requests from the same origin
    header('Access-Control-Allow-Origin: ' . $_SERVER['HTTP_ORIGIN']);
    header('Access-Control-Allow-Methods: POST');
    header('Access-Control-Allow-Headers: Content-Type');

    // Check if user is logged in
    if (!isset($_SESSION['logged_in']) || $_SESSION['logged_in'] !== true) {
        echo json_encode(['success' => false, 'message' => 'Unauthorized']);
        exit;
    }

    if (!isset($_POST['password_id'])) {
        echo json_encode(['success' => false, 'message' => 'Password ID not provided']);
        exit;
    }

    $passwordId = $_POST['password_id'];

    try {
        $stmt = $pdo->prepare("SELECT * FROM passwords WHERE id = ? AND user_id = ? LIMIT 1");
        $stmt->execute([$passwordId, $_SESSION['user_id']]);
        $password = $stmt->fetch(PDO::FETCH_ASSOC);

        if ($password) {
            // Decrypt username and password before sending
            $key = $_SESSION['user_id'] . 'your-secret-salt';
            $password['username'] = decrypt($password['username'], $key);
            $password['password'] = decrypt($password['password'], $key);

            echo json_encode(['success' => true, 'password' => $password]);
        } else {
            echo json_encode(['success' => false, 'message' => 'Password not found']);
        }

    } catch (PDOException $e) {
        echo json_encode(['success' => false, 'message' => 'Database error: ' . $e->getMessage()]);
    } catch (Exception $e) {
        echo json_encode(['success' => false, 'message' => 'Decryption error: ' . $e->getMessage()]);
    }
    exit; // Stop further execution after handling the AJAX request
}

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

// Simple encryption function
function encrypt($data, $key) {
    $key = substr(hash('sha256', $key, true), 0, 32);
    $iv = openssl_random_pseudo_bytes(16);
    $encrypted = openssl_encrypt($data, 'AES-256-CBC', $key, 0, $iv);
    return base64_encode($iv . $encrypted);
}

// Simple decryption function
function decrypt($data, $key) {
    $key = substr(hash('sha256', $key, true), 0, 32);
    $data = base64_decode($data);
    $iv = substr($data, 0, 16);
    $encrypted = substr($data, 16);
    return openssl_decrypt($encrypted, 'AES-256-CBC', $key, 0, $iv);
}

// Handle password submission
if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['action']) && $_POST['action'] === 'add_password') {
    try {
        // Validate input
        if (empty($_POST['website']) || empty($_POST['username']) || empty($_POST['password']) || empty($_POST['category'])) {
            throw new Exception('All fields are required');
        }

        // Sanitize website name
        $website = trim($_POST['website']);

        // Sanitize category
        $category = trim($_POST['category']);

        // Get password strength
        $password = $_POST['password'];
        $strength = 'weak';
        $score = 0;

        // Length check
        if (strlen($password) >= 8) $score += 25;
        // Lowercase check
        if (preg_match('/[a-z]/', $password)) $score += 25;
        // Uppercase check
        if (preg_match('/[A-Z]/', $password)) $score += 25;
        // Number check
        if (preg_match('/[0-9]/', $password)) $score += 12.5;
        // Special character check
        if (preg_match('/[^A-Za-z0-9]/', $password)) $score += 12.5;

        if ($score <= 25) $strength = 'weak';
        else if ($score <= 50) $strength = 'medium';
        else $strength = 'strong';

        // Encrypt username and password
        $key = $_SESSION['user_id'] . 'your-secret-salt';
        $encrypted_username = encrypt($_POST['username'], $key);
        $encrypted_password = encrypt($password, $key);

        // Insert into database
        $stmt = $pdo->prepare("INSERT INTO passwords (user_id, website, username, password, password_length, strength, category) VALUES (?, ?, ?, ?, ?, ?, ?)");
        $result = $stmt->execute([
            $_SESSION['user_id'],
            $website,
            $encrypted_username,
            $encrypted_password,
            strlen($password),
            $strength,
            $category
        ]);

        if (!$result) {
            throw new Exception('Failed to save password');
        }

        header('Location: passwords.php?success=1');
        exit;

    } catch (Exception $e) {
        $error = $e->getMessage();
    }
}

// Handle password update (edit_password)
if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['action']) && $_POST['action'] === 'edit_password') {
    header('Content-Type: application/json');
    // Allow requests from the same origin
    header('Access-Control-Allow-Origin: ' . $_SERVER['HTTP_ORIGIN']);
    header('Access-Control-Allow-Methods: POST');
    header('Access-Control-Allow-Headers: Content-Type');

    // Debug log received POST data
    error_log("Edit password POST data: " . print_r($_POST, true));

    // Check if user is logged in
    if (!isset($_SESSION['logged_in']) || $_SESSION['logged_in'] !== true) {
        error_log("Unauthorized attempt to edit password");
        echo json_encode(['success' => false, 'message' => 'Unauthorized']);
        exit;
    }

    try {
        // Validate input
        if (empty($_POST['password_id']) || empty($_POST['website']) || empty($_POST['username']) || empty($_POST['password']) || empty($_POST['category'])) {
            throw new Exception('All fields are required');
        }

        $passwordId = $_POST['password_id'];
        $website = trim($_POST['website']);
        $username = $_POST['username'];
        $password = $_POST['password'];
        $category = trim($_POST['category']);

        // Get password strength
        $strength = 'weak';
        $score = 0;

        // Length check
        if (strlen($password) >= 8) $score += 25;
        // Lowercase check
        if (preg_match('/[a-z]/', $password)) $score += 25;
        // Uppercase check
        if (preg_match('/[A-Z]/', $password)) $score += 25;
        // Number check
        if (preg_match('/[0-9]/', $password)) $score += 12.5;
        // Special character check
        if (preg_match('/[^A-Za-z0-9]/', $password)) $score += 12.5;

        if ($score <= 25) $strength = 'weak';
        else if ($score <= 50) $strength = 'medium';
        else $strength = 'strong';

        // Encrypt username and password
        $key = $_SESSION['user_id'] . 'your-secret-salt';
        $encrypted_username = encrypt($username, $key);
        $encrypted_password = encrypt($password, $key);

        // Update database
        $stmt = $pdo->prepare("UPDATE passwords SET website = ?, username = ?, password = ?, password_length = ?, strength = ?, category = ?, last_updated = NOW() WHERE id = ? AND user_id = ?");
        $result = $stmt->execute([
            $website,
            $encrypted_username,
            $encrypted_password,
            strlen($password),
            $strength,
            $category,
            $passwordId,
            $_SESSION['user_id']
        ]);

        if ($result) {
            error_log("Password ID " . $passwordId . " updated successfully");
            echo json_encode(['success' => true, 'message' => 'Password updated successfully!']);
        } else {
            error_log("Database execute failed for password ID " . $passwordId);
            // Log detailed error if available (PDO errors might not always throw exceptions for execute)
            $errorInfo = $stmt->errorInfo();
            error_log("PDO Error Info: " . print_r($errorInfo, true));
            throw new Exception('Failed to update password');
        }

    } catch (PDOException $e) {
        error_log("Database error in edit_password: " . $e->getMessage());
        echo json_encode(['success' => false, 'message' => 'Database error: ' . $e->getMessage()]);
    } catch (Exception $e) {
        error_log("Error in edit_password: " . $e->getMessage());
        echo json_encode(['success' => false, 'message' => $e->getMessage()]);
    }
    exit; // Stop further execution after handling the AJAX request
}

// Handle password deletion
if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['action']) && $_POST['action'] === 'delete_password') {
    try {
        if (empty($_POST['password_id'])) {
            throw new Exception('Password ID is required');
        }

        $stmt = $pdo->prepare("DELETE FROM passwords WHERE id = ? AND user_id = ?");
        $result = $stmt->execute([$_POST['password_id'], $_SESSION['user_id']]);

        if (!$result) {
            throw new Exception('Failed to delete password');
        }

        header('Location: passwords.php?deleted=1');
        exit;

    } catch (Exception $e) {
        $error = $e->getMessage();
    }
}

// Add success/error message display
if (isset($_GET['success'])) {
    $success = "Password saved successfully!";
} elseif (isset($_GET['deleted'])) {
    $success = "Password deleted successfully!";
    $notification_type = "error";
}

// Fetch user's passwords
try {
    $stmt = $pdo->prepare("SELECT * FROM passwords WHERE user_id = ? ORDER BY last_updated DESC");
    $stmt->execute([$_SESSION['user_id']]);
    $passwords = $stmt->fetchAll(PDO::FETCH_ASSOC);
    
    // Decrypt usernames
    $key = $_SESSION['user_id'] . 'your-secret-salt';
    foreach ($passwords as &$password) {
        try {
            $password['username'] = decrypt($password['username'], $key);
        } catch (Exception $e) {
            $password['username'] = "Error decrypting username";
        }
    }
} catch (PDOException $e) {
    $error = "Error fetching passwords: " . $e->getMessage();
    $passwords = [];
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
        /* Add notification styles */
        .notification {
            position: fixed;
            top: 50%;
            left: 50%;
            transform: translate(-50%, -50%);
            background-color: #242424;
            border: 1px solid #0D9488;
            border-radius: 8px;
            padding: 1.5rem;
            box-shadow: 0 4px 12px rgba(0, 0, 0, 0.2);
            z-index: 1000;
            display: flex;
            flex-direction: column;
            align-items: center;
            gap: 1rem;
            min-width: 300px;
            animation: fadeIn 0.3s ease-out;
        }
        @keyframes fadeIn {
            from { opacity: 0; transform: translate(-50%, -60%); }
            to { opacity: 1; transform: translate(-50%, -50%); }
        }
        @keyframes fadeOut {
            from { opacity: 1; transform: translate(-50%, -50%); }
            to { opacity: 0; transform: translate(-50%, -60%); }
        }
        .notification.fade-out {
            animation: fadeOut 0.3s ease-out forwards;
        }
        .notification-backdrop {
            position: fixed;
            top: 0;
            left: 0;
            right: 0;
            bottom: 0;
            background-color: rgba(0, 0, 0, 0.5);
            z-index: 999;
        }
        .password-mask {
            font-family: monospace;
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

                <?php if (isset($error)): ?>
                <div class="mb-4 p-4 bg-red-500 bg-opacity-20 border border-red-500 rounded-lg text-red-500">
                    <?php echo htmlspecialchars($error); ?>
                </div>
                <?php endif; ?>

                <?php if (isset($success)): ?>
                <div id="success-notification" class="fixed bottom-4 left-4 <?php echo isset($notification_type) && $notification_type === 'error' ? 'bg-red-100 border-red-400 text-red-700' : 'bg-green-100 border-green-400 text-green-700'; ?> border px-4 py-3 rounded-lg shadow-lg z-50">
                    <div class="flex items-center">
                        <i class="ri-<?php echo isset($notification_type) && $notification_type === 'error' ? 'delete-bin-line' : 'checkbox-circle-line'; ?> text-xl mr-2"></i>
                        <p><?php echo htmlspecialchars($success); ?></p>
                    </div>
                </div>
                <script>
                    // Auto close notification after 2 seconds
                    setTimeout(() => {
                        const notification = document.getElementById('success-notification');
                        if (notification) {
                            notification.remove();
                        }
                    }, 2000);
                </script>
                <?php endif; ?>

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

                <!-- Password List Table (Regenerated) -->
                <div class="bg-[#242424] rounded-lg overflow-hidden shadow-md mb-6">
                    <div class="overflow-x-auto">
                        <table class="w-full">
                            <thead>
                                <tr class="bg-gray-800 text-left">
                                    <th class="py-2 px-4 border-b border-gray-700">Website</th>
                                    <th class="py-2 px-4 border-b border-gray-700">Username/Email</th>
                                    <th class="py-2 px-4 border-b border-gray-700">Password</th>
                                    <th class="py-2 px-4 border-b border-gray-700">Password Length</th>
                                    <th class="py-2 px-4 border-b border-gray-700">Category</th>
                                    <th class="py-2 px-4 border-b border-gray-700">Last Updated</th>
                                    <th class="py-2 px-4 border-b border-gray-700">Actions</th>
                                </tr>
                            </thead>
                            <tbody>
                                <?php
                                // Fetch user's passwords (New Fetch)
                                try {
                                    $stmt_new = $pdo->prepare("SELECT * FROM passwords WHERE user_id = ? ORDER BY last_updated DESC");
                                    $stmt_new->execute([$_SESSION['user_id']]);
                                    $passwords_new = $stmt_new->fetchAll(PDO::FETCH_ASSOC);

                                    if (empty($passwords_new)): ?>
                                    <tr>
                                        <td colspan="7" class="py-4 text-center text-gray-400">No passwords saved yet</td>
                                    </tr>
                                    <?php else: ?>
                                    <?php foreach ($passwords_new as $password): ?>
                                    <tr class="border-b border-gray-700 hover:bg-gray-700">
                                        <td class="py-2 px-4 border-b border-gray-700">
                                            <div class="flex items-center">
                                                <?php
                                                // Get the website name for the current password entry and escape it for display
                                                $websiteName = htmlspecialchars($password['website']);
                                                $firstLetter = strtoupper(substr($websiteName, 0, 1));
                                                $colors = [
                                                    'bg-blue-600', 'bg-red-600', 'bg-green-600',
                                                    'bg-yellow-600', 'bg-purple-600', 'bg-pink-600',
                                                    'bg-indigo-600', 'bg-teal-600', 'bg-orange-600'
                                                ];
                                                // Use the first character to determine the color index
                                                $colorIndex = ord(strtolower($firstLetter)) % count($colors);
                                                $colorClass = $colors[$colorIndex];
                                                ?>
                                                <div class="w-8 h-8 flex items-center justify-center rounded-full <?php echo $colorClass; ?> mr-3 text-white text-xs">
                                                    <?php echo $firstLetter; // Display the first letter ?>
                                                </div>
                                                <span class="font-medium text-white"><?php echo $websiteName; // Display the escaped website name ?></span>
                                            </div>
                                        </td>
                                        <td class="py-2 px-4 border-b border-gray-700 text-sm">
                                            <?php
                                            // Decrypt username for display
                                            $decrypted_username = "Error decrypting username";
                                            try {
                                                $decrypted_username = decrypt($password['username'], $key);
                                            } catch (Exception $e) {
                                                // Handle decryption error if necessary
                                            }
                                            echo htmlspecialchars($decrypted_username);
                                            ?>
                                        </td>
                                        <td class="py-2 px-4 border-b border-gray-700">
                                            <div class="flex items-center">
                                                <span class="text-gray-300 password-mask" data-password="<?php echo htmlspecialchars($password['password']); ?>">••••••••</span>
                                                <button type="button" class="ml-2 text-gray-400 hover:text-white toggle-password"
                                                        data-password="<?php echo htmlspecialchars($password['password']); ?>">
                                                    <div class="w-5 h-5 flex items-center justify-center">
                                                        <i class="ri-eye-line"></i>
                                                    </div>
                                                </button>
                                            </div>
                                        </td>
                                        <td class="py-2 px-4 border-b border-gray-700">
                                            <div class="w-24 h-2 bg-gray-700 rounded-full overflow-hidden">
                                                <div class="h-full <?php
                                                    echo $password['strength'] === 'weak' ? 'bg-red-500' :
                                                        ($password['strength'] === 'medium' ? 'bg-orange-500' : 'bg-green-500');
                                                ?>" style="width: <?php
                                                    echo $password['strength'] === 'weak' ? '40%' :
                                                        ($password['strength'] === 'medium' ? '60%' : '80%');
                                                ?>"></div>
                                            </div>
                                        </td>
                                        <td class="py-2 px-4 border-b border-gray-700 text-sm"><?php echo htmlspecialchars($password['category']); ?></td>
                                        <td class="py-2 px-4 border-b border-gray-700 text-sm text-gray-400">
                                            <?php echo date('M d, Y', strtotime($password['last_updated'])); ?>
                                        </td>
                                        <td class="py-2 px-4 border-b border-gray-700">
                                            <div class="flex space-x-2">
                                                <button type="button" class="text-gray-400 hover:text-white copy-password"
                                                        data-password="<?php echo htmlspecialchars($password['password']); ?>"
                                                        title="Copy password">
                                                    <i class="ri-clipboard-line"></i>
                                                </button>
                                                <button type="button" class="text-gray-400 hover:text-white edit-password-button" title="Edit" data-id="<?php echo $password['id']; ?>">
                                                    <i class="ri-edit-line"></i>
                                                </button>
                                                <button type="button" class="text-gray-400 hover:text-white" title="Delete" onclick="showDeleteModal(<?php echo $password['id']; ?>)">
                                                    <i class="ri-delete-bin-line"></i>
                                                </button>
                                            </div>
                                        </td>
                                    </tr>
                                    <?php endforeach; ?>
                                <?php endif; ?>
                                <?php
                                } catch (PDOException $e) {
                                    echo "<tr><td colspan=\"7\" class=\"py-4 text-center text-red-500\">Error fetching passwords: " . htmlspecialchars($e->getMessage()) . "</td></tr>";
                                }
                                ?>
                            </tbody>
                        </table>
                    </div>
                </div>

                <!-- Delete Confirmation Modal -->
                <div id="delete-confirmation-modal" class="fixed inset-0 flex items-center justify-center bg-black bg-opacity-60 z-50 hidden">
                    <div class="bg-[#242424] rounded-lg p-8 shadow-lg text-center max-w-xs w-full">
                        <div class="flex justify-between items-center mb-4">
                            <h3 class="text-lg font-medium text-white">Delete Password</h3>
                            <button type="button" class="text-gray-400 hover:text-white" onclick="closeDeleteModal()">
                                <i class="ri-close-line text-xl"></i>
                            </button>
                        </div>
                        <p class="text-gray-400 text-sm mb-4">Are you sure you want to delete this password? This action cannot be undone.</p>
                        <div class="flex space-x-2">
                            <button type="button" class="flex-1 px-4 py-2 bg-gray-700 hover:bg-gray-600 rounded-lg text-white" onclick="closeDeleteModal()">Cancel</button>
                            <button type="button" class="flex-1 px-4 py-2 bg-red-600 hover:bg-red-700 rounded-lg text-white" onclick="confirmDelete()">Delete</button>
                        </div>
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

        <!-- Edit Password Modal -->
        <div id="edit-password-modal" class="fixed inset-0 flex items-center justify-center bg-black bg-opacity-60 z-50 hidden" onclick="handleModalClick(event)">
            <div class="bg-[#242424] rounded-lg p-8 shadow-lg max-w-md w-full" onclick="event.stopPropagation()">
                <div class="flex justify-between items-center mb-6">
                    <h3 class="text-lg font-medium text-white">Edit Password</h3>
                    <button type="button" class="text-gray-400 hover:text-white" onclick="closeEditPasswordModal()">
                        <i class="ri-close-line text-xl"></i>
                    </button>
                </div>
                <form id="edit-password-form" method="POST" action="passwords.php" class="space-y-4">
                    <input type="hidden" name="action" value="edit_password">
                    <input type="hidden" name="password_id" id="edit-password-id">

                    <!-- Website Field -->
                    <div>
                        <label for="edit-website" class="block text-sm font-medium text-gray-300 mb-1">Website/App</label>
                        <input type="text" id="edit-website" name="website" autocomplete="off" required class="w-full px-4 py-2 bg-gray-700 border border-gray-600 rounded-lg text-white focus:outline-none focus:border-secondary" placeholder="e.g., Google, Facebook">
                    </div>

                    <!-- Username/Email Field -->
                    <div>
                        <label for="edit-username" class="block text-sm font-medium text-gray-300 mb-1">Username/Email</label>
                        <input type="text" id="edit-username" name="username" autocomplete="username" required class="w-full px-4 py-2 bg-gray-700 border border-gray-600 rounded-lg text-white focus:outline-none focus:border-secondary" placeholder="Enter username or email">
                    </div>

                    <!-- Password Field -->
                    <div>
                        <label for="edit-password" class="block text-sm font-medium text-gray-300 mb-1">Password</label>
                        <div class="relative">
                            <input type="password" id="edit-password" name="password" autocomplete="new-password" required class="w-full px-4 py-2 bg-gray-700 border border-gray-600 rounded-lg text-white focus:outline-none focus:border-secondary pr-10" placeholder="Enter password">
                            <button type="button" class="absolute right-3 top-1/2 transform -translate-y-1/2 text-gray-400 hover:text-white toggle-password" onclick="togglePasswordVisibility('edit-password', this)">
                                <i class="ri-eye-line"></i>
                            </button>
                        </div>
                    </div>

                     <!-- Category Field -->
                        <div>
                            <label for="edit-category" class="block text-sm font-medium text-gray-300 mb-1">Category</label>
                            <select id="edit-category" name="category" required class="w-full px-4 py-2 bg-gray-700 border border-gray-600 rounded-lg text-white focus:outline-none focus:border-secondary">
                                <option value="">Select a Category</option>
                                <option value="Websites">Websites</option>
                                <option value="Financial">Financial</option>
                                <option value="Applications">Applications</option>
                                <option value="Wi-Fi">Wi-Fi</option>
                                 <option value="Social Media">Social Media</option>
                            </select>
                        </div>

                    <!-- Password Strength Indicator - Optional for Edit -->
                    <div id="edit-password-strength-section">
                        <label class="block text-sm font-medium text-gray-300 mb-1">Password Strength</label>
                        <div class="w-full h-2 bg-gray-700 rounded-full overflow-hidden">
                            <div id="edit-password-strength-bar" class="h-full transition-all duration-300" style="width: 0%"></div>
                        </div>
                        <p id="edit-password-strength-text" class="mt-1 text-sm text-gray-400">Enter a password to check strength</p>
                    </div>

                    <!-- Generate Password Button - Optional for Edit -->
                    <div>
                        <button type="button" class="w-full px-4 py-2 bg-gray-700 hover:bg-gray-600 rounded-lg text-white flex items-center justify-center" onclick="generatePassword('edit-password', 'edit-password-strength-bar', 'edit-password-strength-text')">
                            <i class="ri-refresh-line mr-2"></i> Generate Strong Password
                        </button>
                    </div>

                    <!-- Submit Button -->
                    <div class="flex space-x-2 pt-4">
                        <button type="button" class="flex-1 px-4 py-2 bg-gray-700 hover:bg-gray-600 rounded-lg text-white" onclick="closeEditPasswordModal()">Cancel</button>
                        <button type="submit" class="flex-1 px-4 py-2 bg-secondary hover:bg-teal-600 rounded-lg text-white">Save Changes</button>
                    </div>
                </form>
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
                <form id="add-password-form" method="POST" action="passwords.php" class="space-y-4">
                    <input type="hidden" name="action" value="add_password">
                    <!-- Website Field -->
                    <div>
                        <label for="website" class="block text-sm font-medium text-gray-300 mb-1">Website/App</label>
                        <input type="text" id="website" name="website" autocomplete="off" required class="w-full px-4 py-2 bg-gray-700 border border-gray-600 rounded-lg text-white focus:outline-none focus:border-secondary" placeholder="e.g., Google, Facebook">
                    </div>

                    <!-- Username/Email Field -->
                    <div>
                        <label for="username" class="block text-sm font-medium text-gray-300 mb-1">Username/Email</label>
                        <input type="text" id="username" name="username" autocomplete="username" required class="w-full px-4 py-2 bg-gray-700 border border-gray-600 rounded-lg text-white focus:outline-none focus:border-secondary" placeholder="Enter username or email">
                    </div>

                    <!-- Password Field -->
                    <div>
                        <label for="password" class="block text-sm font-medium text-gray-300 mb-1">Password</label>
                        <div class="relative">
                            <input type="password" id="password" name="password" autocomplete="new-password" required class="w-full px-4 py-2 bg-gray-700 border border-gray-600 rounded-lg text-white focus:outline-none focus:border-secondary pr-10" placeholder="Enter password">
                            <button type="button" class="absolute right-3 top-1/2 transform -translate-y-1/2 text-gray-400 hover:text-white toggle-password" onclick="togglePasswordVisibility('password', this)">
                                <i class="ri-eye-line"></i>
                            </button>
                        </div>
                    </div>

                    <!-- Category Field -->
                    <div>
                        <label for="category" class="block text-sm font-medium text-gray-300 mb-1">Category</label>
                        <select id="category" name="category" required class="w-full px-4 py-2 bg-gray-700 border border-gray-600 rounded-lg text-white focus:outline-none focus:border-secondary">
                            <option value="">Select a Category</option>
                            <option value="Websites">Websites</option>
                            <option value="Financial">Financial</option>
                            <option value="Applications">Applications</option>
                            <option value="Wi-Fi">Wi-Fi</option>
                            <option value="Social Media">Social Media</option>
                        </select>
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
                        <button type="button" class="w-full px-4 py-2 bg-gray-700 hover:bg-gray-600 rounded-lg text-white flex items-center justify-center" onclick="generatePassword('password', 'password-strength-bar', 'password-strength-text')">
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
            // Close add modal if clicking the backdrop (outside the form container)
            if (event.target.id === 'add-password-modal') {
                closeAddPasswordModal();
            }
             // Close edit modal if clicking the backdrop (outside the form container)
            if (event.target.id === 'edit-password-modal') {
                closeEditPasswordModal();
            }
        }

        function togglePasswordVisibility(inputId, buttonElement) {
            const passwordInput = document.getElementById(inputId);
            const icon = buttonElement.querySelector('i');
            if (passwordInput.type === 'password') {
                passwordInput.type = 'text';
                icon.className = 'ri-eye-off-line';
            } else {
                passwordInput.type = 'password';
                icon.className = 'ri-eye-line';
            }
        }

        function checkPasswordStrength(passwordInputId, strengthBarId, strengthTextId) {
            const passwordInput = document.getElementById(passwordInputId);
            const strengthBar = document.getElementById(strengthBarId);
            const strengthText = document.getElementById(strengthTextId);
            const password = passwordInput.value;

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

        function generatePassword(passwordInputId, strengthBarId, strengthTextId) {
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
            const passwordInput = document.getElementById(passwordInputId);
            passwordInput.value = password;
            checkPasswordStrength(passwordInputId, strengthBarId, strengthTextId);
        }

        // Edit Password Modal functions
        function showEditPasswordModal(passwordId, website, username, password, category) {
            // Set the password ID in the hidden input
            document.getElementById('edit-password-id').value = passwordId;
            
            // Set other form fields, trimming whitespace from username
            document.getElementById('edit-website').value = website;
            document.getElementById('edit-username').value = username.trim(); // Trim whitespace
            document.getElementById('edit-password').value = password;
            document.getElementById('edit-category').value = category;
            
            // Check password strength
            checkPasswordStrength('edit-password', 'edit-password-strength-bar', 'edit-password-strength-text');
            
            // Show the modal
            document.getElementById('edit-password-modal').classList.remove('hidden');
        }

        function closeEditPasswordModal() {
            document.getElementById('edit-password-modal').classList.add('hidden');
            document.getElementById('edit-password-form').reset();
            // Reset password strength indicator
            document.getElementById('edit-password-strength-bar').style.width = '0%';
            document.getElementById('edit-password-strength-text').textContent = 'Enter a password to check strength';
            document.getElementById('edit-password-strength-bar').className = 'h-full transition-all duration-300';
        }

        function handleModalClick(event) {
            // Close add modal if clicking the backdrop (outside the form container)
            if (event.target.id === 'add-password-modal') {
                closeAddPasswordModal();
            }
            // Close edit modal if clicking the backdrop (outside the form container)
            if (event.target.id === 'edit-password-modal') {
                closeEditPasswordModal();
            }
        }

        // Add event listener for password strength checking on add modal
        document.getElementById('password').addEventListener('input', function(e) {
            checkPasswordStrength('password', 'password-strength-bar', 'password-strength-text');
        });

        // Add event listener for password strength checking on edit modal
        document.getElementById('edit-password').addEventListener('input', function(e) {
            checkPasswordStrength('edit-password', 'edit-password-strength-bar', 'edit-password-strength-text');
        });

        // Add event listener for form submission on edit modal (Handle via AJAX)
        document.getElementById('edit-password-form').addEventListener('submit', function(e) {
            e.preventDefault(); // Prevent default form submission

            const form = e.target;
            const formData = new FormData(form);

            // Debug log formData content
            console.log('FormData content:');
            for (let pair of formData.entries()) {
                console.log(pair[0]+ ': ' + pair[1]);
            }

            // Log the URL being fetched
            console.log('Fetching to:', form.action, 'with method:', form.method);

            fetch('passwords.php', {
                method: 'POST',
                body: formData
            })
            .then(response => {
                if (!response.ok) {
                    throw new Error('Network response was not ok');
                }
                return response.text();
            })
            .then(text => {
                try {
                    const data = JSON.parse(text);
                    if (data.success) {
                        alert('Password updated successfully!');
                        closeEditPasswordModal();
                        window.location.reload();
                    } else {
                        alert('Error: ' + (data.message || 'Failed to update password'));
                    }
                } catch (e) {
                    console.error('Error parsing response:', text);
                    alert('Error updating password. Please try again.');
                }
            })
            .catch(error => {
                console.error('Error:', error);
                alert('An error occurred while saving changes. Please try again.');
            });
        });

        // Add event listener for form submission on add modal
        document.getElementById('add-password-form').addEventListener('submit', function(e) {
            // Password strength check is already handled by input event
            // This submit handler can be used for additional validation or AJAX submission if needed later
        });

        // Reset timeout on modal interactions
        document.getElementById('add-password-modal').addEventListener('mousemove', resetActivityTimeout);
        document.getElementById('add-password-modal').addEventListener('keypress', resetActivityTimeout);
        document.getElementById('edit-password-modal').addEventListener('mousemove', resetActivityTimeout);
        document.getElementById('edit-password-modal').addEventListener('keypress', resetActivityTimeout);

        // Add password visibility toggle functionality
        document.querySelectorAll('.toggle-password').forEach(button => {
            button.addEventListener('click', async function() {
                const passwordMask = this.parentElement.querySelector('.password-mask');
                const icon = this.querySelector('i');
                const encryptedPassword = this.dataset.password;
                
                if (passwordMask.textContent === '••••••••') {
                    try {
                        // Show loading state
                        icon.className = 'ri-loader-4-line animate-spin';
                        
                        // Decrypt password
                        const response = await fetch('decrypt_password.php', {
                            method: 'POST',
                            headers: {
                                'Content-Type': 'application/json',
                            },
                            body: JSON.stringify({ password: encryptedPassword })
                        });

                        if (!response.ok) {
                            throw new Error('Network response was not ok');
                        }

                        const data = await response.json();
                        
                        if (data.success) {
                            passwordMask.textContent = data.password;
                            icon.className = 'ri-eye-off-line';
                        } else {
                            throw new Error(data.message || 'Failed to decrypt password');
                        }
                    } catch (error) {
                        console.error('Error:', error);
                        icon.className = 'ri-eye-line';
                        alert('Error decrypting password: ' + error.message);
                    }
                } else {
                    // Hide password
                    passwordMask.textContent = '••••••••';
                    icon.className = 'ri-eye-line';
                }
            });
        });

        // Add copy password functionality
        document.querySelectorAll('.copy-password').forEach(button => {
            button.addEventListener('click', function() {
                const encryptedPassword = this.dataset.password;
                
                fetch('decrypt_password.php', {
                    method: 'POST',
                    headers: {
                        'Content-Type': 'application/json',
                    },
                    body: JSON.stringify({ password: encryptedPassword })
                })
                .then(response => response.json())
                .then(data => {
                    if (data.success) {
                        navigator.clipboard.writeText(data.password).then(() => {
                            // Show copied feedback
                            const originalTitle = this.getAttribute('title');
                            this.setAttribute('title', 'Copied!');
                            setTimeout(() => {
                                this.setAttribute('title', originalTitle);
                            }, 2000);

                            // Change icon to indicate success
                            const icon = this.querySelector('i');
                            const originalIconClass = icon.className;
                            icon.className = 'ri-check-line text-green-500'; // Change to a success icon and color

                            // Revert icon after a delay
                            setTimeout(() => {
                                icon.className = originalIconClass;
                            }, 2000); // Match this duration with the title change delay
                        }).catch(err => {
                            console.error('Failed to copy password: ', err);
                            // Optionally show an error feedback
                        });
                    }
                }).catch(err => {
                    console.error('Error decrypting password for copy:', err);
                    alert('Error decrypting password for copy.');
                });
            });
        });

        // Delete Modal functions
        let passwordToDelete = null;

        function showDeleteModal(passwordId) {
            passwordToDelete = passwordId;
            document.getElementById('delete-confirmation-modal').classList.remove('hidden');
        }

        function closeDeleteModal() {
            document.getElementById('delete-confirmation-modal').classList.add('hidden');
            passwordToDelete = null;
        }

        function confirmDelete() {
            if (passwordToDelete) {
                const form = document.createElement('form');
                form.method = 'POST';
                form.innerHTML = `
                    <input type="hidden" name="action" value="delete_password">
                    <input type="hidden" name="password_id" value="${passwordToDelete}">
                `;
                document.body.appendChild(form);
                form.submit();
            }
        }

        // Close delete modal when clicking outside
        document.getElementById('delete-confirmation-modal').addEventListener('click', function(e) {
            if (e.target === this) {
                closeDeleteModal();
            }
        });

        // Add notification function
        function showNotification(message, type = 'success') {
            const notification = document.createElement('div');
            notification.className = `fixed bottom-4 right-4 px-4 py-2 rounded-lg shadow-lg z-50 ${
                type === 'success' ? 'bg-green-500' : 'bg-red-500'
            } text-white`;
            notification.textContent = message;
            document.body.appendChild(notification);
            
            // Remove notification after 3 seconds
            setTimeout(() => {
                notification.remove();
            }, 3000);
        }

        // Add event listeners for edit buttons
        document.querySelectorAll('.edit-password-button').forEach(button => {
            button.addEventListener('click', function() {
                const passwordId = this.dataset.id;
                const row = this.closest('tr');
                
                if (!row) {
                    console.error('Could not find table row for edit button.');
                    return;
                }

                // Get data from the row
                const website = row.querySelector('td:first-child span').textContent;
                const username = row.querySelector('td:nth-child(2)').textContent;
                const passwordMask = row.querySelector('.password-mask');
                const password = passwordMask ? passwordMask.dataset.password : '';
                const category = row.querySelector('td:nth-child(5)').textContent;

                if (!password) {
                    console.error('Could not find password data.');
                    alert('Error: Could not retrieve password data.');
                    return;
                }

                // Show the edit modal with the data
                showEditPasswordModal(passwordId, website, username, password, category);
            });
        });
    </script>
</body>
</html> 