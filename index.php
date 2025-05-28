<?php
session_start();

// Check if user is not logged in
if (!isset($_SESSION['logged_in']) || $_SESSION['logged_in'] !== true) {
    header('Location: login.php');
    exit;
}

// Handle logout
if (isset($_GET['logout'])) {
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
                <div class="w-8 h-8 flex items-center justify-center rounded-full bg-primary text-white cursor-pointer" onclick="showLogoutWarning()">
                    <span class="text-sm font-medium"><?php echo substr($_SESSION['user'], 0, 2); ?></span>
                </div>
            </div>
        </div>

        <!-- Rest of your existing dashboard content -->
        <!-- ... (keep all the existing dashboard content) ... -->

    </div>

    <script>
        // Your existing JavaScript functions
        // ... (keep all the existing JavaScript functions) ...

        // Modify the logout function to use PHP
        function logout() {
            window.location.href = 'index.php?logout=1';
        }
    </script>
</body>
</html> 