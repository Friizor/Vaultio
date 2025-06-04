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

// Handle card insertion
if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['action']) && $_POST['action'] === 'add_card') {
    try {
        // Validate input
        if (empty($_POST['card_type']) || empty($_POST['card_number']) || 
            empty($_POST['card_holder']) || empty($_POST['expiry_date']) || 
            empty($_POST['cvv'])) {
            throw new Exception('Required fields are missing');
        }

        // Sanitize and prepare data
        $card_type = trim($_POST['card_type']);
        $bank_name = !empty($_POST['bank_name']) ? trim($_POST['bank_name']) : null;
        $card_number = trim($_POST['card_number']);
        $card_holder = trim($_POST['card_holder']);
        $expiry_date = trim($_POST['expiry_date']);
        $cvv = trim($_POST['cvv']);

        // Insert into database
        $stmt = $pdo->prepare("INSERT INTO cards (user_id, card_type, bank_name, card_number, card_holder, expiry_date, cvv) VALUES (?, ?, ?, ?, ?, ?, ?)");
        $result = $stmt->execute([
            $_SESSION['user_id'],
            $card_type,
            $bank_name,
            $card_number,
            $card_holder,
            $expiry_date,
            $cvv
        ]);

        if (!$result) {
            throw new Exception('Failed to save card');
        }

        header('Location: cards.php?success=1');
        exit;

    } catch (Exception $e) {
        $error = $e->getMessage();
    }
}

// Handle card deletion
if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['action']) && $_POST['action'] === 'delete_card') {
    try {
        if (empty($_POST['card_id'])) {
            throw new Exception('Card ID is required');
        }

        $stmt = $pdo->prepare("DELETE FROM cards WHERE id = ? AND user_id = ?");
        $result = $stmt->execute([$_POST['card_id'], $_SESSION['user_id']]);

        if (!$result) {
            throw new Exception('Failed to delete card');
        }

        header('Location: cards.php?deleted=1');
        exit;

    } catch (Exception $e) {
        $error = $e->getMessage();
    }
}

// Handle card update
if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['action']) && $_POST['action'] === 'edit_card') {
    try {
        // Validate input
        if (empty($_POST['card_id']) || empty($_POST['card_type']) || empty($_POST['card_number']) || 
            empty($_POST['card_holder']) || empty($_POST['expiry_date']) || 
            empty($_POST['cvv'])) {
            throw new Exception('Required fields are missing');
        }

        // Sanitize and prepare data
        $card_id = trim($_POST['card_id']);
        $card_type = trim($_POST['card_type']);
        $bank_name = !empty($_POST['bank_name']) ? trim($_POST['bank_name']) : null;
        $card_number = trim($_POST['card_number']);
        $card_holder = trim($_POST['card_holder']);
        $expiry_date = trim($_POST['expiry_date']);
        $cvv = trim($_POST['cvv']);

        // Update in database
        $stmt = $pdo->prepare("UPDATE cards SET card_type = ?, bank_name = ?, card_number = ?, card_holder = ?, expiry_date = ?, cvv = ? WHERE id = ? AND user_id = ?");
        $result = $stmt->execute([
            $card_type,
            $bank_name,
            $card_number,
            $card_holder,
            $expiry_date,
            $cvv,
            $card_id,
            $_SESSION['user_id']
        ]);

        if (!$result) {
            throw new Exception('Failed to update card');
        }

        header('Location: cards.php?success=1');
        exit;

    } catch (Exception $e) {
        $error = $e->getMessage();
    }
}

// Add success/error message display
if (isset($_GET['success'])) {
    $success = "Card saved successfully!";
    $notification_type = "success";
} elseif (isset($_GET['deleted'])) {
    $success = "Card deleted successfully!";
    $notification_type = "error";
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
                                                All Cards
                                            </button>
                                            <button class="w-full text-left px-3 py-2 text-sm text-gray-300 hover:bg-gray-700 rounded-md filter-type" data-type="visa">
                                                Visa
                                            </button>
                                            <button class="w-full text-left px-3 py-2 text-sm text-gray-300 hover:bg-gray-700 rounded-md filter-type" data-type="mastercard">
                                                Master Card
                                            </button>
                                            <button class="w-full text-left px-3 py-2 text-sm text-gray-300 hover:bg-gray-700 rounded-md filter-type" data-type="amex">
                                                American Express
                                            </button>
                                            <button class="w-full text-left px-3 py-2 text-sm text-gray-300 hover:bg-gray-700 rounded-md filter-type" data-type="edahabia">
                                                Edahabia (ALG)
                                            </button>
                                            <button class="w-full text-left px-3 py-2 text-sm text-gray-300 hover:bg-gray-700 rounded-md filter-type" data-type="other">
                                                Others
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
                <div class="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-6">
                    <?php
                    // Fetch user's cards
                    $stmt = $pdo->prepare("SELECT * FROM cards WHERE user_id = ? ORDER BY created_at DESC");
                    $stmt->execute([$_SESSION['user_id']]);
                    $cards = $stmt->fetchAll();

                    if (empty($cards)): ?>
                        <div class="col-span-full text-center text-gray-400 py-8">
                            No cards saved yet
                        </div>
                    <?php else:
                        foreach ($cards as $card): ?>
                            <div class="card-container relative group">
                                <div class="card bg-gradient-to-br from-emerald-600 to-teal-700 rounded-xl p-6 text-white transform transition-all duration-300 hover:scale-105 h-[280px]">
                                    <!-- Card Header -->
                                    <div class="flex justify-between items-start mb-6">
                                        <div>
                                            <h3 class="text-lg font-semibold mb-1"><?php echo strtoupper(htmlspecialchars($card['card_type'])); ?></h3>
                                            <p class="text-sm text-emerald-200">Credit Card</p>
                                            <div class="h-[20px]">
                                                <?php if (!empty($card['bank_name'])): ?>
                                                    <p class="text-sm text-emerald-200"><?php echo htmlspecialchars($card['bank_name']); ?></p>
                                                <?php endif; ?>
                                            </div>
                                        </div>
                                        <div class="w-12 h-12 bg-white bg-opacity-20 rounded-full flex items-center justify-center">
                                            <i class="ri-bank-card-line text-2xl"></i>
                                        </div>
                                    </div>

                                    <!-- Card Number -->
                                    <div class="mb-6">
                                        <p class="text-sm text-emerald-200 mb-1">Card Number</p>
                                        <p class="text-xl font-mono tracking-wider">**** **** **** <?php echo substr($card['card_number'], -4); ?></p>
                                    </div>

                                    <!-- Card Details -->
                                    <div class="flex justify-between items-end">
                                        <div>
                                            <p class="text-sm text-emerald-200 mb-1">Card Holder</p>
                                            <p class="font-medium"><?php echo htmlspecialchars($card['card_holder']); ?></p>
                                        </div>
                                        <div>
                                            <p class="text-sm text-emerald-200 mb-1">Expires</p>
                                            <p class="font-medium"><?php echo htmlspecialchars($card['expiry_date']); ?></p>
                                        </div>
                                    </div>

                                    <!-- Card Actions (Hidden by default, shown on hover) -->
                                    <div class="absolute inset-0 bg-black bg-opacity-50 rounded-xl flex items-center justify-center space-x-4 opacity-0 group-hover:opacity-100 transition-opacity duration-300">
                                        <button class="p-2 bg-white bg-opacity-20 rounded-full hover:bg-opacity-30 transition-colors" title="View Details" onclick="viewCard(<?php echo $card['id']; ?>)">
                                            <i class="ri-eye-line text-xl"></i>
                                        </button>
                                        <button class="p-2 bg-white bg-opacity-20 rounded-full hover:bg-opacity-30 transition-colors" title="Edit Card" onclick="editCard(<?php echo $card['id']; ?>)">
                                            <i class="ri-edit-line text-xl"></i>
                                        </button>
                                        <button class="p-2 bg-white bg-opacity-20 rounded-full hover:bg-opacity-30 transition-colors" title="Delete Card" onclick="deleteCard(<?php echo $card['id']; ?>)">
                                            <i class="ri-delete-bin-line text-xl"></i>
                                        </button>
                                    </div>
                                </div>
                            </div>
                        <?php endforeach;
                    endif; ?>

                    <!-- Add New Card Button -->
                    <div class="card-container">
                        <div class="card bg-gray-800 border-2 border-dashed border-gray-600 rounded-xl p-6 flex flex-col items-center justify-center min-h-[200px] cursor-pointer hover:border-secondary hover:bg-gray-700 transition-all duration-300" onclick="showAddCardModal()">
                            <div class="w-12 h-12 bg-gray-700 rounded-full flex items-center justify-center mb-4">
                                <i class="ri-add-line text-2xl text-gray-400"></i>
                            </div>
                            <p class="text-gray-400">Add New Card</p>
                        </div>
                    </div>
                </div>

                <!-- Add Card Modal -->
                <div id="add-card-modal" class="fixed inset-0 flex items-center justify-center bg-black bg-opacity-60 z-50 hidden">
                    <div class="bg-[#242424] rounded-lg p-8 shadow-lg max-w-md w-full">
                        <div class="flex justify-between items-center mb-6">
                            <h3 class="text-lg font-medium text-white">Add New Card</h3>
                            <button type="button" class="text-gray-400 hover:text-white" onclick="closeAddCardModal()">
                                <i class="ri-close-line text-xl"></i>
                            </button>
                        </div>
                        <?php if (isset($error)): ?>
                            <div class="bg-red-500 bg-opacity-20 border border-red-500 text-red-500 px-4 py-3 rounded relative mb-4" role="alert">
                                <span class="block sm:inline"><?php echo htmlspecialchars($error); ?></span>
                            </div>
                        <?php endif; ?>
                        <form id="add-card-form" method="POST" action="cards.php" class="space-y-4">
                            <input type="hidden" name="action" value="add_card">
                            
                            <!-- Card Type -->
                            <div>
                                <label class="block text-sm font-medium text-gray-300 mb-1">Card Type</label>
                                <select name="card_type" id="card-type" class="w-full px-4 py-2 bg-gray-700 border border-gray-600 rounded-lg text-white focus:outline-none focus:border-secondary" required>
                                    <option value="">Select Card Type</option>
                                    <option value="visa">Visa</option>
                                    <option value="mastercard">Master Card</option>
                                    <option value="amex">American Express</option>
                                    <option value="edahabia">Edahabia (ALG)</option>
                                    <option value="other">Others</option>
                                </select>
                            </div>

                            <!-- Bank Name (Optional) -->
                            <div>
                                <label class="block text-sm font-medium text-gray-300 mb-1">
                                    Bank Name
                                    <span class="text-gray-500 text-xs">(Optional)</span>
                                </label>
                                <input type="text" name="bank_name" id="bank-name" class="w-full px-4 py-2 bg-gray-700 border border-gray-600 rounded-lg text-white focus:outline-none focus:border-secondary" placeholder="Enter bank name">
                            </div>

                            <!-- Card Number -->
                            <div>
                                <label class="block text-sm font-medium text-gray-300 mb-1">Card Number</label>
                                <input type="text" name="card_number" id="card-number" class="w-full px-4 py-2 bg-gray-700 border border-gray-600 rounded-lg text-white focus:outline-none focus:border-secondary" placeholder="XXXX XXXX XXXX XXXX" maxlength="19" required>
                            </div>

                            <!-- Card Holder Name -->
                            <div>
                                <label class="block text-sm font-medium text-gray-300 mb-1">Card Holder Name</label>
                                <input type="text" name="card_holder" class="w-full px-4 py-2 bg-gray-700 border border-gray-600 rounded-lg text-white focus:outline-none focus:border-secondary" placeholder="John Doe" required>
                            </div>

                            <!-- Expiry Date and CVV -->
                            <div class="grid grid-cols-2 gap-4">
                                <div>
                                    <label class="block text-sm font-medium text-gray-300 mb-1">Expiry Date</label>
                                    <input type="text" name="expiry_date" class="w-full px-4 py-2 bg-gray-700 border border-gray-600 rounded-lg text-white focus:outline-none focus:border-secondary" placeholder="MM/YY" maxlength="5" required>
                                </div>
                                <div>
                                    <label class="block text-sm font-medium text-gray-300 mb-1">CVV</label>
                                    <input type="text" name="cvv" class="w-full px-4 py-2 bg-gray-700 border border-gray-600 rounded-lg text-white focus:outline-none focus:border-secondary" placeholder="123" maxlength="4" required>
                                </div>
                            </div>

                            <!-- Submit Button -->
                            <div class="flex space-x-2 pt-4">
                                <button type="button" class="flex-1 px-4 py-2 bg-gray-700 hover:bg-gray-600 rounded-lg text-white" onclick="closeAddCardModal()">Cancel</button>
                                <button type="submit" class="flex-1 px-4 py-2 bg-secondary hover:bg-teal-600 rounded-lg text-white">Save Card</button>
                            </div>
                        </form>
                    </div>
                </div>

                <!-- View Card Modal -->
                <div id="view-card-modal" class="fixed inset-0 flex items-center justify-center bg-black bg-opacity-60 z-50 hidden">
                    <div class="bg-[#242424] rounded-lg p-8 shadow-lg max-w-md w-full">
                        <div class="flex justify-between items-center mb-6">
                            <h3 class="text-lg font-medium text-white">Card Details</h3>
                            <button type="button" class="text-gray-400 hover:text-white" onclick="closeViewCardModal()">
                                <i class="ri-close-line text-xl"></i>
                            </button>
                        </div>
                        <div class="space-y-4">
                            <div>
                                <p class="text-sm text-gray-400 mb-1">Card Type</p>
                                <p id="view-card-type" class="text-white font-medium"></p>
                            </div>
                            <div>
                                <p class="text-sm text-gray-400 mb-1">Bank Name</p>
                                <p id="view-bank-name" class="text-white font-medium"></p>
                            </div>
                            <div>
                                <p class="text-sm text-gray-400 mb-1">Card Number</p>
                                <div class="flex items-center justify-between">
                                    <p id="view-card-number" class="text-white font-medium"></p>
                                    <button onclick="copyToClipboard('view-card-number')" class="p-2 text-gray-400 hover:text-white transition-colors" title="Copy Card Number">
                                        <i class="ri-file-copy-line"></i>
                                    </button>
                                </div>
                            </div>
                            <div>
                                <p class="text-sm text-gray-400 mb-1">Card Holder</p>
                                <div class="flex items-center justify-between">
                                    <p id="view-card-holder" class="text-white font-medium"></p>
                                    <button onclick="copyToClipboard('view-card-holder')" class="p-2 text-gray-400 hover:text-white transition-colors" title="Copy Card Holder">
                                        <i class="ri-file-copy-line"></i>
                                    </button>
                                </div>
                            </div>
                            <div>
                                <p class="text-sm text-gray-400 mb-1">Expiry Date</p>
                                <p id="view-expiry-date" class="text-white font-medium"></p>
                            </div>
                            <div>
                                <p class="text-sm text-gray-400 mb-1">CVV</p>
                                <div class="flex items-center justify-between">
                                    <p id="view-cvv" class="text-white font-medium"></p>
                                    <button onclick="copyToClipboard('view-cvv')" class="p-2 text-gray-400 hover:text-white transition-colors" title="Copy CVV">
                                        <i class="ri-file-copy-line"></i>
                                    </button>
                                </div>
                            </div>
                        </div>
                        <div class="flex justify-end mt-6">
                            <button type="button" class="px-4 py-2 bg-gray-700 hover:bg-gray-600 rounded-lg text-white" onclick="closeViewCardModal()">Close</button>
                        </div>
                    </div>
                </div>

                <!-- Edit Card Modal -->
                <div id="edit-card-modal" class="fixed inset-0 flex items-center justify-center bg-black bg-opacity-60 z-50 hidden">
                    <div class="bg-[#242424] rounded-lg p-8 shadow-lg max-w-md w-full">
                        <div class="flex justify-between items-center mb-6">
                            <h3 class="text-lg font-medium text-white">Edit Card</h3>
                            <button type="button" class="text-gray-400 hover:text-white" onclick="closeEditCardModal()">
                                <i class="ri-close-line text-xl"></i>
                            </button>
                        </div>
                        <?php if (isset($error)): ?>
                            <div class="bg-red-500 bg-opacity-20 border border-red-500 text-red-500 px-4 py-3 rounded relative mb-4" role="alert">
                                <span class="block sm:inline"><?php echo htmlspecialchars($error); ?></span>
                            </div>
                        <?php endif; ?>
                        <form id="edit-card-form" method="POST" action="cards.php" class="space-y-4">
                            <input type="hidden" name="action" value="edit_card">
                            <input type="hidden" name="card_id" id="edit-card-id">
                            
                            <!-- Card Type -->
                            <div>
                                <label class="block text-sm font-medium text-gray-300 mb-1">Card Type</label>
                                <select name="card_type" id="edit-card-type" class="w-full px-4 py-2 bg-gray-700 border border-gray-600 rounded-lg text-white focus:outline-none focus:border-secondary" required>
                                    <option value="">Select Card Type</option>
                                    <option value="visa">Visa</option>
                                    <option value="mastercard">Master Card</option>
                                    <option value="amex">American Express</option>
                                    <option value="edahabia">Edahabia (ALG)</option>
                                    <option value="other">Others</option>
                                </select>
                            </div>

                            <!-- Bank Name (Optional) -->
                            <div>
                                <label class="block text-sm font-medium text-gray-300 mb-1">
                                    Bank Name
                                    <span class="text-gray-500 text-xs">(Optional)</span>
                                </label>
                                <input type="text" name="bank_name" id="edit-bank-name" class="w-full px-4 py-2 bg-gray-700 border border-gray-600 rounded-lg text-white focus:outline-none focus:border-secondary" placeholder="Enter bank name">
                            </div>

                            <!-- Card Number -->
                            <div>
                                <label class="block text-sm font-medium text-gray-300 mb-1">Card Number</label>
                                <input type="text" name="card_number" id="edit-card-number" class="w-full px-4 py-2 bg-gray-700 border border-gray-600 rounded-lg text-white focus:outline-none focus:border-secondary" placeholder="XXXX XXXX XXXX XXXX" maxlength="19" required>
                            </div>

                            <!-- Card Holder Name -->
                            <div>
                                <label class="block text-sm font-medium text-gray-300 mb-1">Card Holder Name</label>
                                <input type="text" name="card_holder" id="edit-card-holder" class="w-full px-4 py-2 bg-gray-700 border border-gray-600 rounded-lg text-white focus:outline-none focus:border-secondary" placeholder="John Doe" required>
                            </div>

                            <!-- Expiry Date and CVV -->
                            <div class="grid grid-cols-2 gap-4">
                                <div>
                                    <label class="block text-sm font-medium text-gray-300 mb-1">Expiry Date</label>
                                    <input type="text" name="expiry_date" id="edit-expiry-date" class="w-full px-4 py-2 bg-gray-700 border border-gray-600 rounded-lg text-white focus:outline-none focus:border-secondary" placeholder="MM/YY" maxlength="5" required>
                                </div>
                                <div>
                                    <label class="block text-sm font-medium text-gray-300 mb-1">CVV</label>
                                    <input type="text" name="cvv" id="edit-cvv" class="w-full px-4 py-2 bg-gray-700 border border-gray-600 rounded-lg text-white focus:outline-none focus:border-secondary" placeholder="123" maxlength="4" required>
                                </div>
                            </div>

                            <!-- Submit Button -->
                            <div class="flex space-x-2 pt-4">
                                <button type="button" class="flex-1 px-4 py-2 bg-gray-700 hover:bg-gray-600 rounded-lg text-white" onclick="closeEditCardModal()">Cancel</button>
                                <button type="submit" class="flex-1 px-4 py-2 bg-secondary hover:bg-teal-600 rounded-lg text-white">Update Card</button>
                            </div>
                        </form>
                    </div>
                </div>

                <!-- Delete Confirmation Modal -->
                <div id="delete-card-modal" class="fixed inset-0 flex items-center justify-center bg-black bg-opacity-60 z-50 hidden">
                    <div class="bg-[#242424] rounded-lg p-8 shadow-lg text-center max-w-xs w-full">
                        <div class="w-12 h-12 bg-red-500 bg-opacity-20 rounded-full flex items-center justify-center mx-auto mb-4">
                            <i class="ri-delete-bin-line text-2xl text-red-500"></i>
                        </div>
                        <h3 class="text-lg font-medium text-white mb-2">Delete Card</h3>
                        <p class="text-gray-400 text-sm mb-4">Are you sure you want to delete this card? This action cannot be undone.</p>
                        <form id="delete-card-form" method="POST" action="cards.php" class="space-y-4">
                            <input type="hidden" name="action" value="delete_card">
                            <input type="hidden" name="card_id" id="delete-card-id">
                            <div class="flex space-x-2">
                                <button type="button" class="flex-1 px-4 py-2 bg-gray-700 hover:bg-gray-600 rounded-lg text-white" onclick="closeDeleteCardModal()">Cancel</button>
                                <button type="submit" class="flex-1 px-4 py-2 bg-red-500 hover:bg-red-600 rounded-lg text-white">Delete</button>
                            </div>
                        </form>
                    </div>
                </div>

                <!-- Success Notification -->
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

        <!-- Error Modal -->
        <div id="error-modal" class="fixed inset-0 flex items-center justify-center bg-black bg-opacity-60 z-50 hidden">
            <div class="bg-[#242424] rounded-lg p-8 shadow-lg text-center max-w-xs w-full">
                <div class="w-12 h-12 bg-red-500 bg-opacity-20 rounded-full flex items-center justify-center mx-auto mb-4">
                    <i class="ri-error-warning-line text-2xl text-red-500"></i>
                </div>
                <h3 class="text-lg font-medium text-white mb-2">Invalid Date</h3>
                <p id="error-message" class="text-gray-400 text-sm mb-4">Please enter a valid future expiry date.</p>
                <button type="button" class="w-full px-4 py-2 bg-gray-700 hover:bg-gray-600 rounded-lg text-white" onclick="closeErrorModal()">OK</button>
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

        // Add Card Modal functions
        function showAddCardModal() {
            document.getElementById('add-card-modal').classList.remove('hidden');
        }

        function closeAddCardModal() {
            document.getElementById('add-card-modal').classList.add('hidden');
            document.getElementById('add-card-form').reset();
        }

        // Reset timeout on modal interactions
        document.getElementById('logout-modal').addEventListener('mousemove', resetActivityTimeout);
        document.getElementById('logout-modal').addEventListener('keypress', resetActivityTimeout);
        document.getElementById('add-card-modal').addEventListener('mousemove', resetActivityTimeout);
        document.getElementById('add-card-modal').addEventListener('keypress', resetActivityTimeout);

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

        // Handle type filtering
        document.querySelectorAll('.filter-type').forEach(button => {
            button.addEventListener('click', function() {
                const selectedType = this.dataset.type;
                const cards = document.querySelectorAll('.card-container');
                const filterButton = document.getElementById('filter-button');
                
                // Update filter button text
                filterButton.innerHTML = `<i class="ri-filter-3-line mr-2"></i> ${this.textContent.trim()}`;
                
                // Hide dropdown
                document.getElementById('filter-dropdown').classList.add('hidden');
                
                // Filter cards
                cards.forEach(card => {
                    const cardType = card.querySelector('h3').textContent.trim().toLowerCase();
                    if (selectedType === 'all' || cardType === selectedType) {
                        card.style.display = 'block';
                    } else {
                        card.style.display = 'none';
                    }
                });

                // Update active state
                document.querySelectorAll('.filter-type').forEach(btn => {
                    btn.classList.remove('bg-gray-700');
                });
                this.classList.add('bg-gray-700');
            });
        });

        // Add real-time search functionality
        document.getElementById('search-input').addEventListener('input', function(e) {
            const searchTerm = e.target.value.toLowerCase().trim();
            const cards = document.querySelectorAll('.card-container');
            const activeFilter = document.querySelector('.filter-type.bg-gray-700')?.dataset.type || 'all';
            
            cards.forEach(card => {
                // Get all searchable fields
                const cardType = card.querySelector('h3').textContent.trim().toLowerCase();
                const cardHolder = card.querySelector('.font-medium').textContent.trim().toLowerCase();
                const bankName = card.querySelector('.text-emerald-200:nth-of-type(2)')?.textContent.trim().toLowerCase() || '';
                
                // Check if any field matches the search term
                const matchesSearch = searchTerm === '' || 
                    cardType.includes(searchTerm) || 
                    cardHolder.includes(searchTerm) || 
                    bankName.includes(searchTerm);
                
                // Check if card matches the active filter
                const matchesFilter = activeFilter === 'all' || cardType === activeFilter;
                
                // Show/hide card based on both search and filter criteria
                if (matchesSearch && matchesFilter) {
                    card.style.display = 'block';
                    // Highlight matching text if search term exists
                    if (searchTerm !== '') {
                        highlightMatchingText(card, searchTerm);
                    } else {
                        removeHighlights(card);
                    }
                } else {
                    card.style.display = 'none';
                    removeHighlights(card);
                }
            });
        });

        // Function to highlight matching text
        function highlightMatchingText(card, searchTerm) {
            const elements = card.querySelectorAll('h3, .font-medium, .text-emerald-200');
            elements.forEach(element => {
                const text = element.textContent;
                const lowerText = text.toLowerCase();
                if (lowerText.includes(searchTerm)) {
                    const regex = new RegExp(searchTerm, 'gi');
                    element.innerHTML = text.replace(regex, match => `<span class="bg-yellow-500 bg-opacity-30 text-yellow-200">${match}</span>`);
                }
            });
        }

        // Function to remove highlights
        function removeHighlights(card) {
            const elements = card.querySelectorAll('h3, .font-medium, .text-emerald-200');
            elements.forEach(element => {
                element.innerHTML = element.textContent;
            });
        }

        // Clear search when filter changes
        document.querySelectorAll('.filter-type').forEach(button => {
            button.addEventListener('click', function() {
                const searchInput = document.getElementById('search-input');
                searchInput.value = '';
                // Trigger search to reset highlights
                searchInput.dispatchEvent(new Event('input'));
            });
        });

        // Add card number formatting
        document.getElementById('card-number').addEventListener('input', function(e) {
            let value = e.target.value.replace(/\D/g, ''); // Remove non-digits
            let formattedValue = '';
            
            // Format based on card type
            const cardType = document.getElementById('card-type').value;
            if (cardType === 'amex') {
                // American Express: XXXX XXXXXX XXXXX
                for (let i = 0; i < value.length; i++) {
                    if (i === 4 || i === 10) {
                        formattedValue += ' ';
                    }
                    formattedValue += value[i];
                }
                e.target.maxLength = 17; // 15 digits + 2 spaces
            } else {
                // All other cards: XXXX XXXX XXXX XXXX
                for (let i = 0; i < value.length; i++) {
                    if (i > 0 && i % 4 === 0) {
                        formattedValue += ' ';
                    }
                    formattedValue += value[i];
                }
                e.target.maxLength = 19; // 16 digits + 3 spaces
            }
            
            e.target.value = formattedValue;
        });

        // Update card number format when card type changes
        document.getElementById('card-type').addEventListener('change', function(e) {
            const cardNumber = document.getElementById('card-number');
            cardNumber.value = ''; // Clear the input
            if (e.target.value === 'amex') {
                cardNumber.placeholder = 'XXXX XXXXXX XXXXX';
                cardNumber.maxLength = 17;
            } else {
                cardNumber.placeholder = 'XXXX XXXX XXXX XXXX';
                cardNumber.maxLength = 19;
            }
        });

        // Add expiry date formatting and validation
        document.querySelector('input[placeholder="MM/YY"]').addEventListener('input', function(e) {
            let value = e.target.value.replace(/\D/g, '');
            
            // Format as MM/YY
            if (value.length > 2) {
                value = value.slice(0, 2) + '/' + value.slice(2, 4);
            }
            
            // Validate month
            const month = parseInt(value.slice(0, 2));
            if (month > 12) {
                value = '12' + value.slice(2);
            }
            
            e.target.value = value;
        });

        // Error Modal functions
        function showErrorModal(message) {
            document.getElementById('error-message').textContent = message;
            document.getElementById('error-modal').classList.remove('hidden');
        }

        function closeErrorModal() {
            document.getElementById('error-modal').classList.add('hidden');
        }

        // Validate expiry date on blur
        document.querySelector('input[placeholder="MM/YY"]').addEventListener('blur', function(e) {
            const value = e.target.value;
            if (value.length === 5) { // MM/YY format
                const [month, year] = value.split('/');
                const currentDate = new Date();
                const currentYear = currentDate.getFullYear() % 100; // Get last 2 digits
                const currentMonth = currentDate.getMonth() + 1; // getMonth() returns 0-11
                
                const expiryYear = parseInt(year);
                const expiryMonth = parseInt(month);
                
                // Check if date is in the past
                if (expiryYear < currentYear || (expiryYear === currentYear && expiryMonth < currentMonth)) {
                    e.target.value = ''; // Clear invalid date
                    showErrorModal('Please enter a valid future expiry date');
                }
            }
        });

        // Reset timeout on error modal interactions
        document.getElementById('error-modal').addEventListener('mousemove', resetActivityTimeout);
        document.getElementById('error-modal').addEventListener('keypress', resetActivityTimeout);

        // View Card Modal functions
        function viewCard(cardId) {
            // Fetch card details via AJAX
            fetch(`get_card.php?id=${cardId}`)
                .then(response => response.json())
                .then(data => {
                    if (data.success) {
                        document.getElementById('view-card-type').textContent = data.card.card_type.toUpperCase();
                        document.getElementById('view-bank-name').textContent = data.card.bank_name || 'Not specified';
                        document.getElementById('view-card-number').textContent = data.card.card_number;
                        document.getElementById('view-card-holder').textContent = data.card.card_holder;
                        document.getElementById('view-expiry-date').textContent = data.card.expiry_date;
                        document.getElementById('view-cvv').textContent = data.card.cvv;
                        document.getElementById('view-card-modal').classList.remove('hidden');
                    } else {
                        alert('Error loading card details');
                    }
                })
                .catch(error => {
                    console.error('Error:', error);
                    alert('Error loading card details');
                });
        }

        function closeViewCardModal() {
            document.getElementById('view-card-modal').classList.add('hidden');
        }

        // Delete Card Modal functions
        function deleteCard(cardId) {
            document.getElementById('delete-card-id').value = cardId;
            document.getElementById('delete-card-modal').classList.remove('hidden');
        }

        function closeDeleteCardModal() {
            document.getElementById('delete-card-modal').classList.add('hidden');
        }

        // Reset timeout on modal interactions
        document.getElementById('view-card-modal').addEventListener('mousemove', resetActivityTimeout);
        document.getElementById('view-card-modal').addEventListener('keypress', resetActivityTimeout);

        // Add copy to clipboard functionality
        function copyToClipboard(elementId) {
            const element = document.getElementById(elementId);
            const text = element.textContent;
            
            // Create a temporary input element
            const tempInput = document.createElement('input');
            tempInput.value = text;
            document.body.appendChild(tempInput);
            
            // Select and copy the text
            tempInput.select();
            document.execCommand('copy');
            
            // Remove the temporary input
            document.body.removeChild(tempInput);
            
            // Show success message
            const button = element.nextElementSibling;
            const originalIcon = button.innerHTML;
            button.innerHTML = '<i class="ri-check-line"></i>';
            button.classList.add('text-green-500');
            
            // Reset button after 2 seconds
            setTimeout(() => {
                button.innerHTML = originalIcon;
                button.classList.remove('text-green-500');
            }, 2000);
        }

        // Edit Card Modal functions
        function editCard(cardId) {
            // Fetch card details via AJAX
            fetch(`get_card.php?id=${cardId}`)
                .then(response => response.json())
                .then(data => {
                    if (data.success) {
                        document.getElementById('edit-card-id').value = cardId;
                        document.getElementById('edit-card-type').value = data.card.card_type;
                        document.getElementById('edit-bank-name').value = data.card.bank_name || '';
                        document.getElementById('edit-card-number').value = data.card.card_number;
                        document.getElementById('edit-card-holder').value = data.card.card_holder;
                        document.getElementById('edit-expiry-date').value = data.card.expiry_date;
                        document.getElementById('edit-cvv').value = data.card.cvv;
                        document.getElementById('edit-card-modal').classList.remove('hidden');
                    } else {
                        alert('Error loading card details');
                    }
                })
                .catch(error => {
                    console.error('Error:', error);
                    alert('Error loading card details');
                });
        }

        function closeEditCardModal() {
            document.getElementById('edit-card-modal').classList.add('hidden');
            document.getElementById('edit-card-form').reset();
        }

        // Add event listeners for edit card modal
        document.getElementById('edit-card-modal').addEventListener('mousemove', resetActivityTimeout);
        document.getElementById('edit-card-modal').addEventListener('keypress', resetActivityTimeout);

        // Add card number formatting for edit form
        document.getElementById('edit-card-number').addEventListener('input', function(e) {
            let value = e.target.value.replace(/\D/g, ''); // Remove non-digits
            let formattedValue = '';
            
            // Format based on card type
            const cardType = document.getElementById('edit-card-type').value;
            if (cardType === 'amex') {
                // American Express: XXXX XXXXXX XXXXX
                for (let i = 0; i < value.length; i++) {
                    if (i === 4 || i === 10) {
                        formattedValue += ' ';
                    }
                    formattedValue += value[i];
                }
                e.target.maxLength = 17; // 15 digits + 2 spaces
            } else {
                // All other cards: XXXX XXXX XXXX XXXX
                for (let i = 0; i < value.length; i++) {
                    if (i > 0 && i % 4 === 0) {
                        formattedValue += ' ';
                    }
                    formattedValue += value[i];
                }
                e.target.maxLength = 19; // 16 digits + 3 spaces
            }
            
            e.target.value = formattedValue;
        });

        // Update card number format when card type changes in edit form
        document.getElementById('edit-card-type').addEventListener('change', function(e) {
            const cardNumber = document.getElementById('edit-card-number');
            if (e.target.value === 'amex') {
                cardNumber.placeholder = 'XXXX XXXXXX XXXXX';
                cardNumber.maxLength = 17;
            } else {
                cardNumber.placeholder = 'XXXX XXXX XXXX XXXX';
                cardNumber.maxLength = 19;
            }
        });

        // Add expiry date formatting for edit form
        document.getElementById('edit-expiry-date').addEventListener('input', function(e) {
            let value = e.target.value.replace(/\D/g, '');
            
            // Format as MM/YY
            if (value.length > 2) {
                value = value.slice(0, 2) + '/' + value.slice(2, 4);
            }
            
            // Validate month
            const month = parseInt(value.slice(0, 2));
            if (month > 12) {
                value = '12' + value.slice(2);
            }
            
            e.target.value = value;
        });

        // Validate expiry date on blur for edit form
        document.getElementById('edit-expiry-date').addEventListener('blur', function(e) {
            const value = e.target.value;
            if (value.length === 5) { // MM/YY format
                const [month, year] = value.split('/');
                const currentDate = new Date();
                const currentYear = currentDate.getFullYear() % 100; // Get last 2 digits
                const currentMonth = currentDate.getMonth() + 1; // getMonth() returns 0-11
                
                const expiryYear = parseInt(year);
                const expiryMonth = parseInt(month);
                
                // Check if date is in the past
                if (expiryYear < currentYear || (expiryYear === currentYear && expiryMonth < currentMonth)) {
                    e.target.value = ''; // Clear invalid date
                    showErrorModal('Please enter a valid future expiry date');
                }
            }
        });
    </script>
</body>
</html> 