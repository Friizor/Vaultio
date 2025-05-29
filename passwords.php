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

// Add success/error message display
if (isset($_GET['success'])) {
    if (isset($_GET['action']) && $_GET['action'] === 'edit') {
        $success = "Password edited successfully!";
        $notification_type = "info";
    } else {
        $success = "Password saved successfully!";
        $notification_type = "success";
    }
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
            echo json_encode(['success' => true, 'message' => 'Password modified']);
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
                <!-- New Cards section -->
                <a href="cards.php" class="<?php echo $current_page === 'cards.php' ? 'active' : ''; ?>"><i class="ri-bank-card-line"></i> Cards</a>
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
                <div id="success-notification" class="fixed bottom-4 left-4 <?php 
                    if (isset($notification_type)) {
                        switch($notification_type) {
                            case 'error':
                                echo 'bg-red-100 border-red-400 text-red-700';
                                break;
                            case 'info':
                                echo 'bg-blue-100 border-blue-400 text-blue-700';
                                break;
                            default:
                                echo 'bg-green-100 border-green-400 text-green-700';
                        }
                    } else {
                        echo 'bg-green-100 border-green-400 text-green-700';
                    }
                ?> border px-4 py-3 rounded-lg shadow-lg z-50">
                    <div class="flex items-center">
                        <i class="ri-<?php echo isset($notification_type) && $notification_type === 'error' ? 'delete-bin-line' : ($notification_type === 'info' ? 'edit-line' : 'checkbox-circle-line'); ?> text-xl mr-2"></i>
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
                                <input type="text" id="search-input" placeholder="Search passwords..." class="w-full px-4 py-2 bg-gray-700 border border-gray-600 rounded-lg text-white focus:outline-none focus:border-secondary">
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
                                        <h3 class="text-sm font-medium text-gray-300 mb-2">Filter by Category</h3>
                                        <div class="space-y-1">
                                            <button class="w-full text-left px-3 py-2 text-sm text-gray-300 hover:bg-gray-700 rounded-md filter-category" data-category="all">
                                                All Categories
                                            </button>
                                            <button class="w-full text-left px-3 py-2 text-sm text-gray-300 hover:bg-gray-700 rounded-md filter-category" data-category="Websites">
                                                Websites
                                            </button>
                                            <button class="w-full text-left px-3 py-2 text-sm text-gray-300 hover:bg-gray-700 rounded-md filter-category" data-category="Financial">
                                                Financial
                                            </button>
                                            <button class="w-full text-left px-3 py-2 text-sm text-gray-300 hover:bg-gray-700 rounded-md filter-category" data-category="Applications">
                                                Applications
                                            </button>
                                            <button class="w-full text-left px-3 py-2 text-sm text-gray-300 hover:bg-gray-700 rounded-md filter-category" data-category="Wi-Fi">
                                                Wi-Fi
                                            </button>
                                            <button class="w-full text-left px-3 py-2 text-sm text-gray-300 hover:bg-gray-700 rounded-md filter-category" data-category="Social Media">
                                                Social Media
                                            </button>
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
                                            <button class="w-full text-left px-3 py-2 text-sm text-gray-300 hover:bg-gray-700 rounded-md sort-option" data-sort="website" data-order="asc">
                                                <i class="ri-sort-asc mr-2"></i> Website (A-Z)
                                            </button>
                                            <button class="w-full text-left px-3 py-2 text-sm text-gray-300 hover:bg-gray-700 rounded-md sort-option" data-sort="website" data-order="desc">
                                                <i class="ri-sort-desc mr-2"></i> Website (Z-A)
                                            </button>
                                            <button class="w-full text-left px-3 py-2 text-sm text-gray-300 hover:bg-gray-700 rounded-md sort-option" data-sort="date" data-order="desc">
                                                <i class="ri-sort-desc mr-2"></i> Recently Updated
                                            </button>
                                            <button class="w-full text-left px-3 py-2 text-sm text-gray-300 hover:bg-gray-700 rounded-md sort-option" data-sort="date" data-order="asc">
                                                <i class="ri-sort-asc mr-2"></i> Oldest First
                                            </button>
                                            <button class="w-full text-left px-3 py-2 text-sm text-gray-300 hover:bg-gray-700 rounded-md sort-option" data-sort="strength" data-order="desc">
                                                <i class="ri-sort-desc mr-2"></i> Strongest First
                                            </button>
                                            <button class="w-full text-left px-3 py-2 text-sm text-gray-300 hover:bg-gray-700 rounded-md sort-option" data-sort="strength" data-order="asc">
                                                <i class="ri-sort-asc mr-2"></i> Weakest First
                                            </button>
                                        </div>
                                    </div>
                                </div>
                            </div>
                        </div>
                    </div>
                </div>

                <!-- Password List Table (Regenerated) -->
                <div class="bg-[#242424] rounded-lg overflow-hidden shadow-md mb-6">
                    <style>
                        .table-container {
                            max-height: calc(100vh - 300px);
                            overflow-y: auto;
                            scrollbar-width: thin;
                            scrollbar-color: #0D9488 #242424;
                        }
                        .table-container::-webkit-scrollbar {
                            width: 8px;
                        }
                        .table-container::-webkit-scrollbar-track {
                            background: #242424;
                            border-radius: 4px;
                        }
                        .table-container::-webkit-scrollbar-thumb {
                            background: #0D9488;
                            border-radius: 4px;
                        }
                        .table-container::-webkit-scrollbar-thumb:hover {
                            background: #0ca69a;
                        }
                        .fixed-header {
                            position: sticky;
                            top: 0;
                            z-index: 10;
                            background-color: #1f2937; /* bg-gray-800 */
                        }
                        .fixed-header th {
                            position: sticky;
                            top: 0;
                            background-color: #1f2937; /* bg-gray-800 */
                            z-index: 10;
                        }
                    </style>
                    <div class="table-container">
                        <table class="w-full">
                            <thead class="fixed-header">
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
                                <?php
                                // Fetch user's passwords (New Fetch)
                                try {
                                    $stmt_new = $pdo->prepare("SELECT * FROM passwords WHERE user_id = ? ORDER BY last_updated DESC");
                                    $stmt_new->execute([$_SESSION['user_id']]);
                                    $passwords_new = $stmt_new->fetchAll(PDO::FETCH_ASSOC);

                                    if (empty($passwords_new)): ?>
                                    <tr>
                                        <td colspan="6" class="py-4 text-center text-gray-400">No passwords saved yet</td>
                                    </tr>
                                    <?php else: ?>
                                    <?php foreach ($passwords_new as $password): ?>
                                    <tr class="border-b border-gray-700 hover:bg-gray-700" data-category="<?php echo htmlspecialchars($password['category']); ?>">
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
                                    echo "<tr><td colspan=\"6\" class=\"py-4 text-center text-red-500\">Error fetching passwords: " . htmlspecialchars($e->getMessage()) . "</td></tr>";
                                }
                                ?>
                            </tbody>
                        </table>
                    </div>
                </div>

                <!-- Add Export PDF Button -->
                <div class="flex justify-start mb-4">
                    <button id="export-pdf" class="px-4 py-2 bg-secondary hover:bg-teal-600 rounded-lg text-white flex items-center">
                        <i class="ri-file-pdf-line mr-2"></i> Export to PDF
                    </button>
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

    <!-- Add jsPDF library -->
    <script src="https://cdnjs.cloudflare.com/ajax/libs/jspdf/2.5.1/jspdf.umd.min.js"></script>
    <script src="https://cdnjs.cloudflare.com/ajax/libs/jspdf-autotable/3.5.31/jspdf.plugin.autotable.min.js"></script>

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
            
            // Set the category value
            const categorySelect = document.getElementById('edit-category');
            categorySelect.value = category;
            
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
            
            // Reset all edit icons to their normal state
            document.querySelectorAll('.edit-password-button i').forEach(icon => {
                icon.className = 'ri-edit-line';
            });
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

        // Add notification function
        function showNotification(message, type = 'success') {
            const notification = document.createElement('div');
            let bgColor, borderColor, textColor, icon;
            
            switch(type) {
                case 'success':
                    bgColor = 'bg-green-100';
                    borderColor = 'border-green-400';
                    textColor = 'text-green-700';
                    icon = 'ri-checkbox-circle-line';
                    break;
                case 'error':
                    bgColor = 'bg-red-100';
                    borderColor = 'border-red-400';
                    textColor = 'text-red-700';
                    icon = 'ri-delete-bin-line';
                    break;
                case 'info':
                    bgColor = 'bg-blue-100';
                    borderColor = 'border-blue-400';
                    textColor = 'text-blue-700';
                    icon = 'ri-edit-line';
                    break;
                default:
                    bgColor = 'bg-green-100';
                    borderColor = 'border-green-400';
                    textColor = 'text-green-700';
                    icon = 'ri-checkbox-circle-line';
            }
            
            notification.className = `fixed bottom-4 left-4 ${bgColor} ${borderColor} ${textColor} border px-4 py-3 rounded-lg shadow-lg z-50`;
            notification.innerHTML = `
                <div class="flex items-center">
                    <i class="ri-${icon} text-xl mr-2"></i>
                    <p>${message}</p>
                </div>
            `;
            
            document.body.appendChild(notification);
            
            // Remove notification after 2 seconds
            setTimeout(() => {
                notification.remove();
            }, 2000);
        }

        // Add event listeners for edit buttons
        document.querySelectorAll('.edit-password-button').forEach(button => {
            button.addEventListener('click', async function() {
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
                const encryptedPassword = passwordMask ? passwordMask.dataset.password : '';
                const category = row.getAttribute('data-category'); // Get category from data attribute

                if (!encryptedPassword) {
                    console.error('Could not find password data.');
                    showNotification('Error: Could not retrieve password data.', 'error');
                    return;
                }

                try {
                    // Show loading state
                    const icon = this.querySelector('i');
                    const originalIcon = icon.className;
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
                        // Show the edit modal with the decrypted data
                        showEditPasswordModal(passwordId, website, username, data.password, category);
                    } else {
                        throw new Error(data.message || 'Failed to decrypt password');
                    }
                } catch (error) {
                    console.error('Error:', error);
                    showNotification('Error decrypting password: ' + error.message, 'error');
                } finally {
                    // Reset icon
                    const icon = this.querySelector('i');
                    icon.className = originalIcon;
                }
            });
        });

        // Add event listener for form submission on edit modal (Handle via AJAX)
        document.getElementById('edit-password-form').addEventListener('submit', function(e) {
            e.preventDefault(); // Prevent default form submission

            const form = e.target;
            const formData = new FormData(form);

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
                        closeEditPasswordModal();
                        window.location.href = 'passwords.php?success=1&action=edit';
                    } else {
                        showNotification(data.message || 'Failed to update password', 'error');
                    }
                } catch (e) {
                    console.error('Error parsing response:', text);
                    showNotification('Error updating password. Please try again.', 'error');
                }
            })
            .catch(error => {
                console.error('Error:', error);
                showNotification('An error occurred while saving changes. Please try again.', 'error');
            });
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

        // Add filter functionality
        document.getElementById('filter-button').addEventListener('click', function(e) {
            e.stopPropagation();
            const dropdown = document.getElementById('filter-dropdown');
            dropdown.classList.toggle('hidden');
        });

        // Close dropdown when clicking outside
        document.addEventListener('click', function(e) {
            const dropdown = document.getElementById('filter-dropdown');
            const filterButton = document.getElementById('filter-button');
            if (!dropdown.contains(e.target) && !filterButton.contains(e.target)) {
                dropdown.classList.add('hidden');
            }
        });

        // Handle category filtering
        document.querySelectorAll('.filter-category').forEach(button => {
            button.addEventListener('click', function() {
                const selectedCategory = this.dataset.category;
                const rows = document.querySelectorAll('tbody tr');
                let visibleRows = 0;
                
                // Update active state of filter buttons
                document.querySelectorAll('.filter-category').forEach(btn => {
                    btn.classList.remove('bg-gray-700');
                });
                this.classList.add('bg-gray-700');
                
                // Filter rows
                rows.forEach(row => {
                    if (selectedCategory === 'all' || row.dataset.category === selectedCategory) {
                        row.style.display = '';
                        visibleRows++;
                    } else {
                        row.style.display = 'none';
                    }
                });

                // Show message if no passwords in category
                const noPasswordsRow = document.querySelector('tbody tr.no-passwords-message');
                if (noPasswordsRow) {
                    noPasswordsRow.remove();
                }

                if (visibleRows === 0 && selectedCategory !== 'all') {
                    const tbody = document.querySelector('tbody');
                    const messageRow = document.createElement('tr');
                    messageRow.className = 'no-passwords-message';
                    messageRow.innerHTML = `
                        <td colspan="6" class="py-4 text-center text-gray-400">
                            No passwords saved in ${selectedCategory} category yet
                        </td>
                    `;
                    tbody.appendChild(messageRow);
                }
                
                // Close dropdown
                document.getElementById('filter-dropdown').classList.add('hidden');
            });
        });

        // Add sort functionality
        document.getElementById('sort-button').addEventListener('click', function(e) {
            e.stopPropagation();
            const dropdown = document.getElementById('sort-dropdown');
            dropdown.classList.toggle('hidden');
        });

        // Close sort dropdown when clicking outside
        document.addEventListener('click', function(e) {
            const dropdown = document.getElementById('sort-dropdown');
            const sortButton = document.getElementById('sort-button');
            if (!dropdown.contains(e.target) && !sortButton.contains(e.target)) {
                dropdown.classList.add('hidden');
            }
        });

        // Handle sorting
        document.querySelectorAll('.sort-option').forEach(button => {
            button.addEventListener('click', function() {
                const sortBy = this.dataset.sort;
                const order = this.dataset.order;
                const tbody = document.querySelector('tbody');
                const rows = Array.from(tbody.querySelectorAll('tr:not(.no-passwords-message)'));

                // Update active state of sort buttons
                document.querySelectorAll('.sort-option').forEach(btn => {
                    btn.classList.remove('bg-gray-700');
                });
                this.classList.add('bg-gray-700');

                // Sort rows
                rows.sort((a, b) => {
                    let aValue, bValue;

                    switch(sortBy) {
                        case 'website':
                            aValue = a.querySelector('td:first-child span').textContent.toLowerCase();
                            bValue = b.querySelector('td:first-child span').textContent.toLowerCase();
                            break;
                        case 'date':
                            aValue = new Date(a.querySelector('td:nth-child(5)').textContent);
                            bValue = new Date(b.querySelector('td:nth-child(5)').textContent);
                            break;
                        case 'strength':
                            const strengthOrder = { 'strong': 3, 'medium': 2, 'weak': 1 };
                            aValue = strengthOrder[a.querySelector('.h-full').classList.contains('bg-green-500') ? 'strong' : 
                                    a.querySelector('.h-full').classList.contains('bg-orange-500') ? 'medium' : 'weak'];
                            bValue = strengthOrder[b.querySelector('.h-full').classList.contains('bg-green-500') ? 'strong' : 
                                    b.querySelector('.h-full').classList.contains('bg-orange-500') ? 'medium' : 'weak'];
                            break;
                    }

                    if (order === 'asc') {
                        return aValue > bValue ? 1 : -1;
                    } else {
                        return aValue < bValue ? 1 : -1;
                    }
                });

                // Reorder rows in the table
                rows.forEach(row => tbody.appendChild(row));

                // Close dropdown
                document.getElementById('sort-dropdown').classList.add('hidden');
            });
        });

        // Add search functionality
        document.getElementById('search-input').addEventListener('input', function(e) {
            const searchTerm = e.target.value.toLowerCase();
            const rows = document.querySelectorAll('tbody tr:not(.no-passwords-message)');
            let visibleRows = 0;

            rows.forEach(row => {
                const website = row.querySelector('td:first-child span').textContent.toLowerCase();
                const username = row.querySelector('td:nth-child(2)').textContent.toLowerCase();
                
                if (website.includes(searchTerm) || username.includes(searchTerm)) {
                    row.style.display = '';
                    visibleRows++;
                } else {
                    row.style.display = 'none';
                }
            });

            // Show message if no results found
            const noPasswordsRow = document.querySelector('tbody tr.no-passwords-message');
            if (noPasswordsRow) {
                noPasswordsRow.remove();
            }

            if (visibleRows === 0 && searchTerm !== '') {
                const tbody = document.querySelector('tbody');
                const messageRow = document.createElement('tr');
                messageRow.className = 'no-passwords-message';
                messageRow.innerHTML = `
                    <td colspan="6" class="py-4 text-center text-gray-400">
                        No passwords found matching "${searchTerm}"
                    </td>
                `;
                tbody.appendChild(messageRow);
            }
        });

        // Reset timeout on search input
        document.getElementById('search-input').addEventListener('input', resetActivityTimeout);

        // Add PDF Export functionality
        document.getElementById('export-pdf').addEventListener('click', async function() {
            // Show loading state
            const button = this;
            const originalContent = button.innerHTML;
            button.innerHTML = '<i class="ri-loader-4-line animate-spin mr-2"></i> Generating PDF...';
            button.disabled = true;

            try {
                // Get all visible rows (excluding the "no passwords" message)
                const rows = Array.from(document.querySelectorAll('tbody tr:not(.no-passwords-message)')).filter(row => row.style.display !== 'none');
                
                if (rows.length === 0) {
                    showNotification('No passwords to export', 'error');
                    return;
                }

                // Prepare table data with decrypted passwords
                const tableData = [];
                for (const row of rows) {
                    const website = row.querySelector('td:first-child span').textContent;
                    const username = row.querySelector('td:nth-child(2)').textContent;
                    const encryptedPassword = row.querySelector('.password-mask').dataset.password;

                    // Decrypt password
                    try {
                        const response = await fetch('decrypt_password.php', {
                            method: 'POST',
                            headers: {
                                'Content-Type': 'application/json',
                            },
                            body: JSON.stringify({ password: encryptedPassword })
                        });

                        if (!response.ok) {
                            throw new Error('Failed to decrypt password');
                        }

                        const data = await response.json();
                        if (!data.success) {
                            throw new Error(data.message || 'Failed to decrypt password');
                        }

                        tableData.push({
                            website,
                            username,
                            password: data.password
                        });
                    } catch (error) {
                        console.error('Error decrypting password:', error);
                        showNotification('Error decrypting some passwords', 'error');
                        continue;
                    }
                }

                // Sort data alphabetically by website name
                tableData.sort((a, b) => a.website.localeCompare(b.website));

                // Create new PDF document
                const { jsPDF } = window.jspdf;
                const doc = new jsPDF();

                // Add title with cool styling
                doc.setFontSize(24);
                doc.setTextColor(30, 58, 138); // Primary color
                doc.text('Vaultio', 105, 20, { align: 'center' });
                
                doc.setFontSize(16);
                doc.setTextColor(13, 148, 136); // Secondary color
                doc.text('Password List', 105, 30, { align: 'center' });

                // Add decorative line
                doc.setDrawColor(30, 58, 138);
                doc.setLineWidth(0.5);
                doc.line(20, 35, 190, 35);

                // Add date with styling
                doc.setFontSize(10);
                doc.setTextColor(100, 100, 100);
                doc.text(`Generated on: ${new Date().toLocaleDateString()}`, 105, 45, { align: 'center' });

                // Add table with enhanced styling
                doc.autoTable({
                    head: [['Website', 'Username', 'Password']],
                    body: tableData.map(item => [item.website, item.username, item.password]),
                    startY: 50,
                    theme: 'grid',
                    styles: {
                        fontSize: 10,
                        cellPadding: 5,
                        textColor: [50, 50, 50],
                        fontStyle: 'normal',
                        halign: 'center', // Center all content by default
                        valign: 'middle', // Vertical center
                    },
                    headStyles: {
                        fillColor: [30, 58, 138], // Primary color
                        textColor: 255,
                        fontStyle: 'bold',
                        halign: 'center',
                        valign: 'middle',
                    },
                    alternateRowStyles: {
                        fillColor: [245, 245, 245],
                    },
                    columnStyles: {
                        0: { 
                            cellWidth: 50,
                            fontStyle: 'bold',
                            textColor: [30, 58, 138], // Primary color for website names
                            halign: 'center', // Ensure website column is centered
                        },
                        1: { 
                            cellWidth: 60,
                            textColor: [13, 148, 136], // Secondary color for usernames
                            halign: 'center', // Ensure username column is centered
                        },
                        2: { 
                            cellWidth: 50,
                            fontStyle: 'bold',
                            textColor: [50, 50, 50], // Dark gray for passwords
                            halign: 'center', // Ensure password column is centered
                        },
                    },
                    margin: { top: 10, left: 25, right: 25 }, // Center the table horizontally
                    tableWidth: 'auto',
                    showFoot: 'lastPage',
                    footStyles: {
                        fillColor: [30, 58, 138],
                        textColor: 255,
                        fontStyle: 'bold',
                        halign: 'center',
                    },
                    foot: [['', '', '']], // Empty footer row for spacing
                });

                // Add footer with page numbers and decorative elements
                const pageCount = doc.internal.getNumberOfPages();
                for (let i = 1; i <= pageCount; i++) {
                    doc.setPage(i);
                    
                    // Add decorative line at bottom
                    doc.setDrawColor(30, 58, 138);
                    doc.setLineWidth(0.5);
                    doc.line(20, doc.internal.pageSize.height - 20, 190, doc.internal.pageSize.height - 20);
                    
                    // Add page number with styling
                    doc.setFontSize(10);
                    doc.setTextColor(100, 100, 100);
                    doc.text(
                        `Page ${i} of ${pageCount}`,
                        doc.internal.pageSize.width / 2,
                        doc.internal.pageSize.height - 10,
                        { align: 'center' }
                    );
                }

                // Save the PDF
                doc.save('vaultio-passwords.pdf');
                showNotification('PDF exported successfully!', 'success');
            } catch (error) {
                console.error('Error generating PDF:', error);
                showNotification('Error generating PDF', 'error');
            } finally {
                // Reset button state
                button.innerHTML = originalContent;
                button.disabled = false;
            }
        });

        // Reset timeout on PDF export button
        document.getElementById('export-pdf').addEventListener('click', resetActivityTimeout);
    </script>
</body>
</html> 