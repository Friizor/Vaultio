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

// Handle note creation
if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['action']) && $_POST['action'] === 'add_note') {
    try {
        // Validate input
        if (empty($_POST['title']) || empty($_POST['content'])) {
            throw new Exception('Title and content are required');
        }

        $title = trim($_POST['title']);
        $content = trim($_POST['content']);
        $tags = isset($_POST['tags']) ? trim($_POST['tags']) : '';

        // Insert into database
        $stmt = $pdo->prepare("INSERT INTO notes (user_id, title, content, author) VALUES (?, ?, ?, ?)");
        $result = $stmt->execute([
            $_SESSION['user_id'],
            $title,
            $content,
            $_SESSION['user']
        ]);

        if (!$result) {
            throw new Exception('Failed to save note');
        }

        header('Location: notes.php?success=1');
        exit;

    } catch (Exception $e) {
        $error = $e->getMessage();
    }
}

// Handle note deletion
if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['action']) && $_POST['action'] === 'delete_note') {
    try {
        if (empty($_POST['note_id'])) {
            throw new Exception('Note ID is required');
        }

        $stmt = $pdo->prepare("DELETE FROM notes WHERE id = ? AND user_id = ?");
        $result = $stmt->execute([$_POST['note_id'], $_SESSION['user_id']]);

        if (!$result) {
            throw new Exception('Failed to delete note');
        }

        header('Location: notes.php?deleted=1');
        exit;

    } catch (Exception $e) {
        $error = $e->getMessage();
    }
}

// Add success/error message display
if (isset($_GET['success'])) {
    $success = "Note saved successfully!";
    $notification_type = "success";
} elseif (isset($_GET['deleted'])) {
    $success = "Note deleted successfully!";
    $notification_type = "error";
}

// Fetch user's notes
try {
    $stmt = $pdo->prepare("SELECT * FROM notes WHERE user_id = ? ORDER BY last_updated DESC");
    $stmt->execute([$_SESSION['user_id']]);
    $notes = $stmt->fetchAll(PDO::FETCH_ASSOC);
} catch (PDOException $e) {
    $error = "Error fetching notes: " . $e->getMessage();
    $notes = [];
}
?>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Vaultio | Notes</title>
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
            background-color: #333;
            color: #0D9488;
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
        .note-card {
            background-color: #2a2a2a;
            border-radius: 8px;
            padding: 1rem;
            margin-bottom: 1rem;
            transition: all 0.2s;
        }
        .note-card:hover {
            background-color: #333;
            transform: translateY(-2px);
        }
        /* Styles for search, filter, sort copied from passwords.php */
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
        .filter-category, .sort-option {
            /* Base styles from passwords.php, adapted for notes */
            display: flex;
            align-items: center;
            padding: 0.5rem 1rem;
            border-radius: 6px;
            color: #E5E5E5;
            text-decoration: none;
            transition: background-color 0.2s;
        }
        .filter-category:hover, .sort-option:hover {
            background-color: #333;
        }
        #filter-dropdown, #sort-dropdown {
            /* Styles for dropdowns */
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
        .filter-tag, .sort-option {
             width: 100%;
             text-align: left;
             padding: 0.5rem 0.75rem;
             border-radius: 4px;
             color: #E5E5E5;
             transition: background-color 0.2s;
        }
         .filter-tag:hover, .sort-option:hover {
             background-color: #333;
         }
        .note-editor {
            background-color: #333;
            border-radius: 8px;
            border: 1px solid #444;
            min-height: 200px;
            padding: 1rem;
            margin-bottom: 1rem;
            color: #E5E5E5;
            font-family: 'Inter', sans-serif;
            resize: vertical;
        }
        .note-editor:focus {
            outline: none;
            border-color: #0D9488;
            box-shadow: 0 0 0 2px rgba(13, 148, 136, 0.2);
        }
        .tag-input {
            background-color: #333;
            border: 1px solid #444;
            border-radius: 6px;
            padding: 0.5rem;
            color: #E5E5E5;
            font-size: 0.875rem;
        }
        .tag-input:focus {
            outline: none;
            border-color: #0D9488;
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
                <h1 class="text-2xl font-semibold text-white mb-6">Notes</h1>

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
                                <input type="text" id="search-input" placeholder="Search notes..." class="w-full px-4 py-2 bg-gray-700 border border-gray-600 rounded-lg text-white focus:outline-none focus:border-secondary">
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
                                        <h3 class="text-sm font-medium text-gray-300 mb-2">Filter by Tag</h3>
                                        <div class="space-y-1">
                                            <!-- Tags will be loaded here -->
                                            <button class="w-full text-left px-3 py-2 text-sm text-gray-300 hover:bg-gray-700 rounded-md filter-tag" data-tag="all">
                                                All Tags
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
                                            <button class="w-full text-left px-3 py-2 text-sm text-gray-300 hover:bg-gray-700 rounded-md sort-option" data-sort="title" data-order="asc">
                                                <i class="ri-sort-asc mr-2"></i> Title (A-Z)
                                            </button>
                                            <button class="w-full text-left px-3 py-2 text-sm text-gray-300 hover:bg-gray-700 rounded-md sort-option" data-sort="title" data-order="desc">
                                                <i class="ri-sort-desc mr-2"></i> Title (Z-A)
                                            </button>
                                            <button class="w-full text-left px-3 py-2 text-sm text-gray-300 hover:bg-gray-700 rounded-md sort-option" data-sort="date" data-order="desc">
                                                <i class="ri-sort-desc mr-2"></i> Recently Created
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

                <!-- Notes Grid -->
                <div class="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
                    <?php if (empty($notes)): ?>
                        <div class="col-span-full text-center text-gray-400 py-8">
                            <i class="ri-sticky-note-line text-4xl mb-4 block"></i>
                            <p class="text-lg mb-2">No notes yet</p>
                            <p class="text-sm">Create your first note to get started</p>
                        </div>
                    <?php else: ?>
                        <?php foreach ($notes as $note): ?>
                            <div class="note-card">
                                <div class="flex justify-between items-start mb-2">
                                    <h3 class="text-lg font-medium text-white"><?php echo htmlspecialchars($note['title']); ?></h3>
                                    <div class="flex space-x-2">
                                        <button class="text-gray-400 hover:text-white" title="Edit" onclick="editNote(<?php echo $note['id']; ?>)">
                                            <i class="ri-edit-line"></i>
                                        </button>
                                        <button class="text-gray-400 hover:text-white" title="Delete" onclick="deleteNote(<?php echo $note['id']; ?>)">
                                            <i class="ri-delete-bin-line"></i>
                                        </button>
                                    </div>
                                </div>
                                <p class="text-gray-400 text-sm mb-2"><?php echo htmlspecialchars(substr($note['content'], 0, 100)) . (strlen($note['content']) > 100 ? '...' : ''); ?></p>
                                <div class="flex justify-between items-center text-xs text-gray-500">
                                    <span><?php echo date('M d, Y', strtotime($note['last_updated'])); ?></span>
                                    <span>by <?php echo htmlspecialchars($note['author']); ?></span>
                                </div>
                            </div>
                        <?php endforeach; ?>
                    <?php endif; ?>
                </div>
            </div>
        </div>

        <!-- Add Note FAB -->
        <button class="fab" onclick="showAddNoteModal()">
            <i class="ri-add-line text-2xl"></i>
        </button>

        <!-- Add Note Modal -->
        <div id="add-note-modal" class="fixed inset-0 flex items-center justify-center bg-black bg-opacity-60 z-50 hidden" onclick="handleModalClick(event)">
            <div class="bg-[#242424] rounded-lg p-8 shadow-lg max-w-2xl w-full max-h-[90vh] overflow-y-auto" onclick="event.stopPropagation()">
                <div class="flex justify-between items-center mb-6">
                    <h3 class="text-lg font-medium text-white">Add New Note</h3>
                    <button type="button" class="text-gray-400 hover:text-white" onclick="closeAddNoteModal()">
                        <i class="ri-close-line text-xl"></i>
                    </button>
                </div>
                <?php if (isset($error)): ?>
                    <div class="bg-red-500 bg-opacity-20 border border-red-500 text-red-500 px-4 py-3 rounded relative mb-4" role="alert">
                        <span class="block sm:inline"><?php echo htmlspecialchars($error); ?></span>
                    </div>
                <?php endif; ?>
                <form id="add-note-form" method="POST" action="notes.php" class="space-y-4">
                    <input type="hidden" name="action" value="add_note">
                    
                    <!-- Title Field -->
                    <div>
                        <label for="note-title" class="block text-sm font-medium text-gray-300 mb-1">Title</label>
                        <input type="text" id="note-title" name="title" required class="w-full px-4 py-2 bg-gray-700 border border-gray-600 rounded-lg text-white focus:outline-none focus:border-secondary" placeholder="Enter note title">
                    </div>

                    <!-- Content Field -->
                    <div>
                        <label for="note-content" class="block text-sm font-medium text-gray-300 mb-1">Content</label>
                        <textarea id="note-content" name="content" required class="note-editor w-full" placeholder="Write your note content here..."></textarea>
                    </div>

                    <!-- Tags Field (Optional) -->
                    <div>
                        <label for="note-tags" class="block text-sm font-medium text-gray-300 mb-1">
                            Tags
                            <span class="text-gray-500 text-xs">(Optional - separate with commas)</span>
                        </label>
                        <input type="text" id="note-tags" name="tags" class="tag-input w-full" placeholder="work, ideas, personal">
                    </div>

                    <!-- Submit Button -->
                    <div class="flex space-x-2 pt-4">
                        <button type="button" class="flex-1 px-4 py-2 bg-gray-700 hover:bg-gray-600 rounded-lg text-white" onclick="closeAddNoteModal()">Cancel</button>
                        <button type="submit" class="flex-1 px-4 py-2 bg-secondary hover:bg-teal-600 rounded-lg text-white">Save Note</button>
                    </div>
                </form>
            </div>
        </div>

        <!-- Delete Confirmation Modal -->
        <div id="delete-note-modal" class="fixed inset-0 flex items-center justify-center bg-black bg-opacity-60 z-50 hidden">
            <div class="bg-[#242424] rounded-lg p-8 shadow-lg text-center max-w-xs w-full">
                <div class="flex justify-between items-center mb-4">
                    <h3 class="text-lg font-medium text-white">Delete Note</h3>
                    <button type="button" class="text-gray-400 hover:text-white" onclick="closeDeleteNoteModal()">
                        <i class="ri-close-line text-xl"></i>
                    </button>
                </div>
                <p class="text-gray-400 text-sm mb-4">Are you sure you want to delete this note? This action cannot be undone.</p>
                <form id="delete-note-form" method="POST" action="notes.php" class="space-y-4">
                    <input type="hidden" name="action" value="delete_note">
                    <input type="hidden" name="note_id" id="delete-note-id">
                    <div class="flex space-x-2">
                        <button type="button" class="flex-1 px-4 py-2 bg-gray-700 hover:bg-gray-600 rounded-lg text-white" onclick="closeDeleteNoteModal()">Cancel</button>
                        <button type="submit" class="flex-1 px-4 py-2 bg-red-600 hover:bg-red-700 rounded-lg text-white">Delete</button>
                    </div>
                </form>
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

        // Add Note Modal functions
        function showAddNoteModal() {
            document.getElementById('add-note-modal').classList.remove('hidden');
            // Focus on title input
            setTimeout(() => {
                document.getElementById('note-title').focus();
            }, 100);
        }

        function closeAddNoteModal() {
            document.getElementById('add-note-modal').classList.add('hidden');
            document.getElementById('add-note-form').reset();
        }

        function handleModalClick(event) {
            // Close add modal if clicking the backdrop (outside the form container)
            if (event.target.id === 'add-note-modal') {
                closeAddNoteModal();
            }
        }

        // Delete Note Modal functions
        function deleteNote(noteId) {
            document.getElementById('delete-note-id').value = noteId;
            document.getElementById('delete-note-modal').classList.remove('hidden');
        }

        function closeDeleteNoteModal() {
            document.getElementById('delete-note-modal').classList.add('hidden');
        }

        // Edit Note function (placeholder for future implementation)
        function editNote(noteId) {
            // TODO: Implement edit note functionality
            alert('Edit note functionality coming soon!');
        }

        // Reset timeout on modal interactions
        document.getElementById('logout-modal').addEventListener('mousemove', resetActivityTimeout);
        document.getElementById('logout-modal').addEventListener('keypress', resetActivityTimeout);
        document.getElementById('add-note-modal').addEventListener('mousemove', resetActivityTimeout);
        document.getElementById('add-note-modal').addEventListener('keypress', resetActivityTimeout);
        document.getElementById('delete-note-modal').addEventListener('mousemove', resetActivityTimeout);
        document.getElementById('delete-note-modal').addEventListener('keypress', resetActivityTimeout);

        // Add search functionality
        document.getElementById('search-input').addEventListener('input', function(e) {
            const searchTerm = e.target.value.toLowerCase();
            const noteCards = document.querySelectorAll('.note-card');
            
            noteCards.forEach(card => {
                const title = card.querySelector('h3').textContent.toLowerCase();
                const content = card.querySelector('p').textContent.toLowerCase();
                
                if (title.includes(searchTerm) || content.includes(searchTerm)) {
                    card.style.display = 'block';
                } else {
                    card.style.display = 'none';
                }
            });
        });

        // Reset timeout on search input
        document.getElementById('search-input').addEventListener('input', resetActivityTimeout);
    </script>
</body>
</html> 