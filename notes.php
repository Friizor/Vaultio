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
        // Check for duplicate submission
        if (isset($_SESSION['last_note_submission']) && 
            $_SESSION['last_note_submission'] === $_POST['title'] . $_POST['content'] . (isset($_POST['todos']) ? $_POST['todos'] : '')) {
            // This is a duplicate submission, redirect without creating
            header('Location: notes.php?success=1');
            exit;
        }
        
        // Validate input
        if (empty($_POST['title']) || empty($_POST['content'])) {
            throw new Exception('Title and content are required');
        }

        $title = trim($_POST['title']);
        $content = trim($_POST['content']);
        $todos = isset($_POST['todos']) ? $_POST['todos'] : '';

        // Store submission hash to prevent duplicates
        $_SESSION['last_note_submission'] = $title . $content . $todos;

        // Insert note into database first
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

        $noteId = $pdo->lastInsertId();

        // Process todo list and insert into todos table
        if (!empty($todos)) {
            // Decode the JSON string to get the todos array
            $todosArray = json_decode($todos, true);
            
            if ($todosArray && is_array($todosArray)) {
                $todoStmt = $pdo->prepare("INSERT INTO todos (note_id, text, completed, position) VALUES (?, ?, ?, ?)");
                
                foreach ($todosArray as $index => $todo) {
                    if (isset($todo['text']) && !empty($todo['text'])) {
                        $completed = isset($todo['completed']) && $todo['completed'] ? 1 : 0;
                        $todoStmt->execute([
                            $noteId,
                            htmlspecialchars($todo['text']),
                            $completed,
                            $index
                        ]);
                    }
                }
            }
        }

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

// Handle delete all notes
if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['action']) && $_POST['action'] === 'delete_all_notes') {
    try {
        // Delete all notes for the current user (todos will be deleted automatically due to CASCADE)
        $stmt = $pdo->prepare("DELETE FROM notes WHERE user_id = ?");
        $result = $stmt->execute([$_SESSION['user_id']]);

        if (!$result) {
            throw new Exception('Failed to delete all notes');
        }

        header('Location: notes.php?deleted_all=1');
        exit;

    } catch (Exception $e) {
        $error = $e->getMessage();
    }
}

// Handle note editing
if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['action']) && $_POST['action'] === 'edit_note') {
    try {
        // Validate input
        if (empty($_POST['note_id']) || empty($_POST['title']) || empty($_POST['content'])) {
            throw new Exception('Note ID, title and content are required');
        }

        $noteId = $_POST['note_id'];
        $title = trim($_POST['title']);
        $content = trim($_POST['content']);
        $todos = isset($_POST['todos']) ? $_POST['todos'] : '';

        // First, verify that the note belongs to the current user
        $stmt = $pdo->prepare("SELECT id FROM notes WHERE id = ? AND user_id = ? LIMIT 1");
        $stmt->execute([$noteId, $_SESSION['user_id']]);
        $note = $stmt->fetch();

        if (!$note) {
            throw new Exception('Note not found or access denied');
        }

        // Update note in database
        $stmt = $pdo->prepare("UPDATE notes SET title = ?, content = ?, last_updated = NOW() WHERE id = ? AND user_id = ?");
        $result = $stmt->execute([
            $title,
            $content,
            $noteId,
            $_SESSION['user_id']
        ]);

        if (!$result) {
            throw new Exception('Failed to update note');
        }

        // Delete existing todos for this note
        $stmt = $pdo->prepare("DELETE FROM todos WHERE note_id = ?");
        $stmt->execute([$noteId]);

        // Process todo list and insert into todos table
        if (!empty($todos)) {
            // Decode the JSON string to get the todos array
            $todosArray = json_decode($todos, true);
            
            if ($todosArray && is_array($todosArray)) {
                $todoStmt = $pdo->prepare("INSERT INTO todos (note_id, text, completed, position) VALUES (?, ?, ?, ?)");
                
                foreach ($todosArray as $index => $todo) {
                    if (isset($todo['text']) && !empty($todo['text'])) {
                        $completed = isset($todo['completed']) && $todo['completed'] ? 1 : 0;
                        $todoStmt->execute([
                            $noteId,
                            htmlspecialchars($todo['text']),
                            $completed,
                            $index
                        ]);
                    }
                }
            }
        }

        header('Location: notes.php?success=1&action=edit');
        exit;

    } catch (Exception $e) {
        $error = $e->getMessage();
    }
}

// Add success/error message display
if (isset($_GET['success'])) {
    if (isset($_GET['action']) && $_GET['action'] === 'edit') {
        $success = "Note updated successfully!";
        $notification_type = "info";
    } else {
        $success = "Note saved successfully!";
        $notification_type = "success";
    }
} elseif (isset($_GET['deleted'])) {
    $success = "Note deleted successfully!";
    $notification_type = "error";
} elseif (isset($_GET['deleted_all'])) {
    $success = "All notes deleted successfully!";
    $notification_type = "error";
}

// Fetch user's notes with their todos
try {
    // Get all notes with a single query
    $stmt = $pdo->prepare("SELECT DISTINCT n.* FROM notes n WHERE n.user_id = ? ORDER BY n.last_updated DESC");
    $stmt->execute([$_SESSION['user_id']]);
    $notes = $stmt->fetchAll(PDO::FETCH_ASSOC);
    
    // Get todos for each note individually (simpler approach)
    foreach ($notes as $key => $note) {
        $todoStmt = $pdo->prepare("SELECT text FROM todos WHERE note_id = ? ORDER BY position ASC");
        $todoStmt->execute([$note['id']]);
        $todos = $todoStmt->fetchAll(PDO::FETCH_COLUMN);
        $notes[$key]['todos'] = $todos;
    }
} catch (PDOException $e) {
    $error = "Error fetching notes: " . $e->getMessage();
    $notes = [];
}

// Debug: Log the number of notes fetched
error_log("Fetched " . count($notes) . " notes for user " . $_SESSION['user_id']);

// Debug: Check for actual duplicates in database and clean them up
try {
    // Find duplicates
    $debugStmt = $pdo->prepare("SELECT id, title, content, COUNT(*) as count FROM notes WHERE user_id = ? GROUP BY title, content HAVING COUNT(*) > 1");
    $debugStmt->execute([$_SESSION['user_id']]);
    $duplicates = $debugStmt->fetchAll();
    
    if (!empty($duplicates)) {
        error_log("Found duplicate notes in database: " . json_encode($duplicates));
        
        // Remove duplicates (keep the first one, delete the rest)
        foreach ($duplicates as $duplicate) {
            $cleanupStmt = $pdo->prepare("DELETE n1 FROM notes n1 INNER JOIN notes n2 WHERE n1.id > n2.id AND n1.title = n2.title AND n1.content = n2.content AND n1.user_id = ? AND n2.user_id = ?");
            $cleanupStmt->execute([$_SESSION['user_id'], $_SESSION['user_id']]);
        }
        
        // Re-fetch notes after cleanup
        $stmt = $pdo->prepare("SELECT DISTINCT n.* FROM notes n WHERE n.user_id = ? ORDER BY n.last_updated DESC");
        $stmt->execute([$_SESSION['user_id']]);
        $notes = $stmt->fetchAll(PDO::FETCH_ASSOC);
        
        // Re-fetch todos for each note
        foreach ($notes as $key => $note) {
            $todoStmt = $pdo->prepare("SELECT text FROM todos WHERE note_id = ? ORDER BY position ASC");
            $todoStmt->execute([$note['id']]);
            $todos = $todoStmt->fetchAll(PDO::FETCH_COLUMN);
            $notes[$key]['todos'] = $todos;
        }
    }
} catch (Exception $e) {
    error_log("Debug query failed: " . $e->getMessage());
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
        .todo-list {
            background-color: #2a2a2a;
            border-radius: 8px;
            padding: 1rem;
            margin-top: 0.5rem;
            max-height: 200px;
            overflow-y: auto;
        }
        .todo-item {
            display: flex;
            align-items: center;
            padding: 0.5rem;
            margin-bottom: 0.5rem;
            background-color: #333;
            border-radius: 6px;
            transition: all 0.2s;
        }
        .todo-item:hover {
            background-color: #3a3a3a;
        }
        .todo-item input[type="text"] {
            flex: 1;
            background-color: transparent;
            border: none;
            color: #E5E5E5;
            font-size: 0.875rem;
            padding: 0.25rem;
            margin-right: 0.5rem;
        }
        .todo-item input[type="text"]:focus {
            outline: none;
            background-color: #444;
            border-radius: 4px;
        }
        .todo-item.completed input[type="text"] {
            text-decoration: line-through;
            color: #888;
        }
        .todo-actions {
            display: flex;
            gap: 0.25rem;
        }
        .todo-btn {
            padding: 0.25rem;
            border-radius: 4px;
            border: none;
            cursor: pointer;
            transition: all 0.2s;
            font-size: 0.75rem;
        }
        .todo-btn.complete {
            background-color: #10b981;
            color: white;
        }
        .todo-btn.complete:hover {
            background-color: #059669;
        }
        .todo-btn.delete {
            background-color: #ef4444;
            color: white;
        }
        .todo-btn.delete:hover {
            background-color: #dc2626;
        }
        .todo-btn.edit {
            background-color: #3b82f6;
            color: white;
        }
        .todo-btn.edit:hover {
            background-color: #2563eb;
        }
        .add-todo-btn {
            background-color: #0D9488;
            color: white;
            border: none;
            border-radius: 6px;
            padding: 0.5rem 1rem;
            cursor: pointer;
            transition: all 0.2s;
            font-size: 0.875rem;
            display: flex;
            align-items: center;
            gap: 0.5rem;
        }
        .add-todo-btn:hover {
            background-color: #0ca69a;
        }
        /* Enhanced Todo Input Group Styles */
        .todo-input-group {
            display: flex;
            gap: 0.75rem;
            margin-bottom: 1.5rem;
            background: linear-gradient(135deg, #2a2a2a 0%, #1f1f1f 100%);
            border: 1px solid #404040;
            border-radius: 12px;
            padding: 0.75rem;
            box-shadow: 0 4px 6px rgba(0, 0, 0, 0.1);
            transition: all 0.3s ease;
        }
        
        .todo-input-group:hover {
            border-color: #0D9488;
            box-shadow: 0 6px 12px rgba(13, 148, 136, 0.2);
            transform: translateY(-1px);
        }
        
        .todo-input-group input {
            flex: 1;
            background: linear-gradient(135deg, #333 0%, #2a2a2a 100%);
            border: 1px solid #555;
            border-radius: 8px;
            padding: 0.75rem 1rem;
            color: #E5E5E5;
            font-size: 0.875rem;
            transition: all 0.3s ease;
            box-shadow: inset 0 2px 4px rgba(0, 0, 0, 0.1);
        }
        
        .todo-input-group input:focus {
            outline: none;
            border-color: #0D9488;
            box-shadow: 0 0 0 3px rgba(13, 148, 136, 0.1), inset 0 2px 4px rgba(0, 0, 0, 0.1);
            background: linear-gradient(135deg, #2a2a2a 0%, #1f1f1f 100%);
        }
        
        .todo-input-group input::placeholder {
            color: #888;
            font-style: italic;
        }
        
        .todo-input-group button {
            background: linear-gradient(135deg, #0D9488 0%, #0ca69a 100%);
            color: white;
            border: none;
            border-radius: 8px;
            padding: 0.75rem 1.25rem;
            cursor: pointer;
            transition: all 0.3s ease;
            font-size: 0.875rem;
            font-weight: 500;
            box-shadow: 0 2px 4px rgba(13, 148, 136, 0.3);
            position: relative;
            overflow: hidden;
        }
        
        .todo-input-group button::before {
            content: '';
            position: absolute;
            top: 0;
            left: -100%;
            width: 100%;
            height: 100%;
            background: linear-gradient(90deg, transparent, rgba(255, 255, 255, 0.2), transparent);
            transition: left 0.5s;
        }
        
        .todo-input-group button:hover {
            background: linear-gradient(135deg, #0ca69a 0%, #0D9488 100%);
            transform: translateY(-2px);
            box-shadow: 0 4px 8px rgba(13, 148, 136, 0.4);
        }
        
        .todo-input-group button:hover::before {
            left: 100%;
        }
        
        .todo-input-group button:active {
            transform: translateY(0);
            box-shadow: 0 2px 4px rgba(13, 148, 136, 0.3);
        }
        
        .todo-input-group button:disabled {
            background: linear-gradient(135deg, #666 0%, #555 100%);
            cursor: not-allowed;
            transform: none;
            box-shadow: none;
        }
        
        /* Enhanced Todo List Styles */
        .todo-list {
            background: linear-gradient(135deg, #2a2a2a 0%, #1f1f1f 100%);
            border: 1px solid #404040;
            border-radius: 12px;
            padding: 1rem;
            margin-top: 1rem;
            box-shadow: 0 4px 6px rgba(0, 0, 0, 0.1);
            transition: all 0.3s ease;
        }
        
        .todo-list:hover {
            border-color: #0D9488;
            box-shadow: 0 6px 12px rgba(13, 148, 136, 0.1);
        }
        
        .todo-list:empty::before {
            content: 'No todos added yet. Add your first task above!';
            display: block;
            text-align: center;
            color: #888;
            font-style: italic;
            padding: 2rem;
            font-size: 0.875rem;
        }
        
        /* Enhanced Todo Item Styles */
        .todo-item {
            display: flex;
            align-items: center;
            gap: 0.75rem;
            background: linear-gradient(135deg, #333 0%, #2a2a2a 100%);
            border: 1px solid #555;
            border-radius: 10px;
            padding: 0.75rem;
            margin-bottom: 0.75rem;
            transition: all 0.3s ease;
            position: relative;
            overflow: hidden;
        }
        
        .todo-item::before {
            content: '';
            position: absolute;
            top: 0;
            left: -100%;
            width: 100%;
            height: 100%;
            background: linear-gradient(90deg, transparent, rgba(13, 148, 136, 0.1), transparent);
            transition: left 0.5s;
        }
        
        .todo-item:hover {
            border-color: #0D9488;
            transform: translateY(-2px);
            box-shadow: 0 4px 8px rgba(0, 0, 0, 0.2);
        }
        
        .todo-item:hover::before {
            left: 100%;
        }
        
        .todo-item:last-child {
            margin-bottom: 0;
        }
        
        .todo-item.completed {
            opacity: 0.8;
            background: linear-gradient(135deg, #2a2a2a 0%, #1f1f1f 100%);
            border-color: #0D9488;
        }
        
        .todo-item.completed::after {
            content: '';
            position: absolute;
            top: 0;
            left: 0;
            width: 100%;
            height: 2px;
            background: linear-gradient(90deg, #0D9488, #0ca69a);
            border-radius: 10px 10px 0 0;
        }
        
        .todo-item input[type="text"] {
            flex: 1;
            background: transparent;
            border: none;
            color: #E5E5E5;
            font-size: 0.875rem;
            padding: 0.25rem 0;
            transition: all 0.3s ease;
        }
        
        .todo-item input[type="text"]:focus {
            outline: none;
            background: rgba(13, 148, 136, 0.1);
            border-radius: 4px;
            padding: 0.25rem 0.5rem;
        }
        
        .todo-item.completed input[type="text"] {
            text-decoration: line-through;
            color: #888;
        }
        
        .todo-item.completed input[type="text"]:disabled {
            background: transparent;
        }
        
        /* Enhanced Todo Actions */
        .todo-actions {
            display: flex;
            gap: 0.5rem;
            opacity: 0.7;
            transition: opacity 0.3s ease;
        }
        
        .todo-item:hover .todo-actions {
            opacity: 1;
        }
        
        .todo-btn {
            width: 32px;
            height: 32px;
            border: none;
            border-radius: 6px;
            cursor: pointer;
            transition: all 0.3s ease;
            display: flex;
            align-items: center;
            justify-content: center;
            font-size: 0.875rem;
            position: relative;
            overflow: hidden;
        }
        
        .todo-btn::before {
            content: '';
            position: absolute;
            top: 0;
            left: -100%;
            width: 100%;
            height: 100%;
            background: linear-gradient(90deg, transparent, rgba(255, 255, 255, 0.2), transparent);
            transition: left 0.3s;
        }
        
        .todo-btn:hover::before {
            left: 100%;
        }
        
        .todo-btn.complete {
            background: linear-gradient(135deg, #0D9488 0%, #0ca69a 100%);
            color: white;
        }
        
        .todo-btn.complete:hover {
            transform: scale(1.1);
            box-shadow: 0 2px 8px rgba(13, 148, 136, 0.4);
        }
        
        .todo-btn.edit {
            background: linear-gradient(135deg, #3b82f6 0%, #2563eb 100%);
            color: white;
        }
        
        .todo-btn.edit:hover {
            transform: scale(1.1);
            box-shadow: 0 2px 8px rgba(59, 130, 246, 0.4);
        }
        
        .todo-btn.delete {
            background: linear-gradient(135deg, #ef4444 0%, #dc2626 100%);
            color: white;
        }
        
        .todo-btn.delete:hover {
            transform: scale(1.1);
            box-shadow: 0 2px 8px rgba(239, 68, 68, 0.4);
        }
        
        /* Todo Progress Indicator */
        .todo-progress-indicator {
            display: flex;
            align-items: center;
            gap: 0.5rem;
            margin-bottom: 1rem;
            padding: 0.75rem;
            background: linear-gradient(135deg, #2a2a2a 0%, #1f1f1f 100%);
            border: 1px solid #404040;
            border-radius: 8px;
            font-size: 0.875rem;
            color: #E5E5E5;
        }
        
        .todo-progress-indicator .progress-bar {
            flex: 1;
            height: 6px;
            background: #404040;
            border-radius: 3px;
            overflow: hidden;
        }
        
        .todo-progress-indicator .progress-fill {
            height: 100%;
            background: linear-gradient(90deg, #0D9488, #0ca69a);
            border-radius: 3px;
            transition: width 0.5s ease;
        }
        
        /* Search highlight effect */
        .search-highlight {
            border: 2px solid #0D9488;
            box-shadow: 0 0 10px rgba(13, 148, 136, 0.3);
            transform: scale(1.02);
            transition: all 0.2s ease;
        }
        
        .search-highlight:hover {
            transform: scale(1.03);
        }
        
        /* Show search match indicators when search is active */
        .search-highlight .search-match-indicators {
            display: block !important;
        }
        
        .search-highlight[data-title-match="true"] .title-match-indicator {
            display: inline-block !important;
        }
        
        .search-highlight[data-content-match="true"] .content-match-indicator {
            display: inline-block !important;
        }
        
        .search-highlight[data-todos-match="true"] .todos-match-indicator {
            display: inline-block !important;
        }
        
        /* Sort dropdown styles */
        .sort-option:hover {
            background-color: #374151;
        }
        
        .sort-option.active {
            background-color: #374151;
        }
        
        /* Responsive design for search and sort */
        @media (max-width: 768px) {
            .flex.gap-4.items-start {
                flex-direction: column;
                gap: 1rem;
            }
            
            #sort-button {
                width: 100%;
                justify-content: center;
            }
            
            #sort-dropdown {
                width: 100%;
                right: auto;
                left: 0;
            }
        }
        
        /* Enhanced Todo Styles for View Modal */
        .todo-item-view {
            position: relative;
            overflow: hidden;
        }
        
        .todo-item-view::before {
            content: '';
            position: absolute;
            top: 0;
            left: -100%;
            width: 100%;
            height: 100%;
            background: linear-gradient(90deg, transparent, rgba(13, 148, 136, 0.1), transparent);
            transition: left 0.5s;
        }
        
        .todo-item-view:hover::before {
            left: 100%;
        }
        
        .todo-item-view.completed {
            opacity: 0.8;
        }
        
        .todo-item-view.completed .todo-text {
            text-decoration: line-through;
            color: #9ca3af;
        }
        
        .todo-checkbox {
            position: relative;
            z-index: 2;
        }
        
        .todo-checkbox:hover {
            transform: scale(1.1);
        }
        
        .todo-checkbox-wrapper {
            position: relative;
        }
        
        .todo-checkbox-wrapper .animate-ping {
            animation: ping 1s cubic-bezier(0, 0, 0.2, 1) infinite;
        }
        
        @keyframes ping {
            75%, 100% {
                transform: scale(2);
                opacity: 0;
            }
        }
        
        /* Progress bar animation */
        .progress-bar-animate {
            animation: progressFill 1s ease-out;
        }
        
        @keyframes progressFill {
            from { width: 0%; }
            to { width: var(--progress-width); }
        }
        
        /* Todo item entrance animation */
        .todo-item-view {
            animation: slideInUp 0.3s ease-out;
        }
        
        @keyframes slideInUp {
            from {
                opacity: 0;
                transform: translateY(20px);
            }
            to {
                opacity: 1;
                transform: translateY(0);
            }
        }
        
        /* Stagger animation for multiple todos */
        .todo-item-view:nth-child(1) { animation-delay: 0.1s; }
        .todo-item-view:nth-child(2) { animation-delay: 0.2s; }
        .todo-item-view:nth-child(3) { animation-delay: 0.3s; }
        .todo-item-view:nth-child(4) { animation-delay: 0.4s; }
        .todo-item-view:nth-child(5) { animation-delay: 0.5s; }
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
                <div class="flex justify-between items-center mb-6">
                    <h1 class="text-2xl font-semibold text-white">Notes</h1>
                    <button onclick="openDeleteAllModal()" class="bg-red-600 hover:bg-red-700 text-white px-4 py-2 rounded-lg flex items-center space-x-2 transition-colors">
                        <i class="ri-delete-bin-line"></i>
                        <span>Delete All</span>
                    </button>
                </div>

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

                <!-- Search and Sort -->
                <div class="mb-6">
                    <div class="flex gap-4 items-start">
                        <!-- Search Input -->
                        <div class="flex-1 relative">
                        <input type="text" id="search-input" placeholder="Search notes by title, content, or todos..." class="w-full px-4 py-2 bg-gray-700 border border-gray-600 rounded-lg text-white focus:outline-none focus:border-secondary">
                        <i class="ri-search-line absolute right-3 top-1/2 transform -translate-y-1/2 text-gray-400"></i>
                        </div>
                        
                        <!-- Sort Dropdown -->
                        <div class="relative">
                            <button id="sort-button" class="flex items-center gap-2 px-4 py-2 bg-gray-700 border border-gray-600 rounded-lg text-white hover:bg-gray-600 transition-colors">
                                <i class="ri-sort-desc"></i>
                                <span id="sort-text">Newest First</span>
                                <i class="ri-arrow-down-s-line"></i>
                            </button>
                            
                            <!-- Sort Dropdown Menu -->
                            <div id="sort-dropdown" class="absolute right-0 top-full mt-1 bg-gray-800 border border-gray-600 rounded-lg shadow-lg z-50 hidden min-w-48">
                                <div class="p-2">
                                    <h3 class="text-xs text-gray-400 mb-2 px-2">Sort by</h3>
                                    <button class="sort-option w-full text-left px-3 py-2 rounded text-sm hover:bg-gray-700 transition-colors" data-sort="newest">
                                        <div class="flex items-center justify-between">
                                            <span>Newest First</span>
                                            <i class="ri-check-line text-secondary hidden"></i>
                                        </div>
                                    </button>
                                    <button class="sort-option w-full text-left px-3 py-2 rounded text-sm hover:bg-gray-700 transition-colors" data-sort="oldest">
                                        <div class="flex items-center justify-between">
                                            <span>Oldest First</span>
                                            <i class="ri-check-line text-secondary hidden"></i>
                                        </div>
                                    </button>
                                    <button class="sort-option w-full text-left px-3 py-2 rounded text-sm hover:bg-gray-700 transition-colors" data-sort="title-asc">
                                        <div class="flex items-center justify-between">
                                            <span>Title A-Z</span>
                                            <i class="ri-check-line text-secondary hidden"></i>
                                        </div>
                                    </button>
                                    <button class="sort-option w-full text-left px-3 py-2 rounded text-sm hover:bg-gray-700 transition-colors" data-sort="title-desc">
                                        <div class="flex items-center justify-between">
                                            <span>Title Z-A</span>
                                            <i class="ri-check-line text-secondary hidden"></i>
                                        </div>
                                    </button>
                                    <button class="sort-option w-full text-left px-3 py-2 rounded text-sm hover:bg-gray-700 transition-colors" data-sort="author">
                                        <div class="flex items-center justify-between">
                                            <span>Author</span>
                                            <i class="ri-check-line text-secondary hidden"></i>
                                        </div>
                                    </button>
                                    <button class="sort-option w-full text-left px-3 py-2 rounded text-sm hover:bg-gray-700 transition-colors" data-sort="todos">
                                        <div class="flex items-center justify-between">
                                            <span>Most Todos</span>
                                            <i class="ri-check-line text-secondary hidden"></i>
                                        </div>
                                    </button>
                                </div>
                            </div>
                        </div>
                    </div>
                    
                    <!-- Search results count displayed below the search input -->
                    <div id="search-results-count" class="mt-2 text-gray-400 text-sm hidden transition-all duration-200 ease-in-out">
                        <div class="flex items-center">
                            <i class="ri-search-line mr-1"></i>
                            <span id="results-count">0</span> results found
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
                        <!-- No search results message (hidden by default) -->
                        <div id="no-search-results" class="col-span-full text-center text-gray-400 py-8 hidden">
                            <i class="ri-search-line text-4xl mb-4 block"></i>
                            <p class="text-lg mb-2">No results found</p>
                            <p class="text-sm">Try adjusting your search terms</p>
                        </div>
                        
                        <?php foreach ($notes as $note): ?>
                    <div class="note-card" data-note-id="<?php echo $note['id']; ?>">
                        <div class="flex justify-between items-start mb-2">
                                    <h3 class="text-lg font-medium text-white"><?php echo htmlspecialchars($note['title']); ?></h3>
                            <div class="flex space-x-2">
                                        <button class="text-gray-400 hover:text-white" title="View" onclick="viewNote(<?php echo $note['id']; ?>)">
                                            <i class="ri-eye-line"></i>
                                        </button>
                                        <button class="text-gray-400 hover:text-white" title="Edit" onclick="editNote(<?php echo $note['id']; ?>)">
                                    <i class="ri-edit-line"></i>
                                </button>
                                        <button class="text-gray-400 hover:text-white" title="Delete" onclick="deleteNote(<?php echo $note['id']; ?>)">
                                    <i class="ri-delete-bin-line"></i>
                                </button>
                            </div>
                        </div>
                                <p class="text-gray-400 text-sm mb-2"><?php echo htmlspecialchars(substr($note['content'], 0, 100)) . (strlen($note['content']) > 100 ? '...' : ''); ?></p>
                        
                        <!-- Show todos preview if they exist -->
                        <?php if (!empty($note['todos'])): ?>
                        <div class="mb-2">
                            <div class="flex items-center text-xs text-gray-500 mb-1">
                                <i class="ri-checkbox-line mr-1"></i>
                                <span><?php echo count($note['todos']); ?> todo<?php echo count($note['todos']) > 1 ? 's' : ''; ?></span>
                            </div>
                            <div class="text-xs text-gray-600 max-h-16 overflow-hidden">
                                <?php 
                                $todoPreview = array_slice($note['todos'], 0, 3);
                                foreach ($todoPreview as $todo) {
                                    echo '<div class="flex items-center mb-1">';
                                    echo '<span class="w-2 h-2 bg-gray-600 rounded-full mr-2"></span>';
                                    echo '<span>' . htmlspecialchars(substr($todo, 0, 50)) . (strlen($todo) > 50 ? '...' : '') . '</span>';
                                    echo '</div>';
                                }
                                if (count($note['todos']) > 3) {
                                    echo '<div class="text-gray-500 text-xs">+' . (count($note['todos']) - 3) . ' more</div>';
                                }
                                ?>
                            </div>
                        </div>
                        <?php endif; ?>
                        
                        <div class="flex justify-between items-center text-xs text-gray-500">
                                    <span><?php echo date('M d, Y', strtotime($note['last_updated'])); ?></span>
                                    <span>by <?php echo htmlspecialchars($note['author']); ?></span>
                        </div>
                        
                        <!-- Search match indicators (hidden by default, shown via CSS when search is active) -->
                        <div class="search-match-indicators hidden mt-2 text-xs">
                            <div class="flex flex-wrap gap-1">
                                <span class="title-match-indicator bg-blue-500 text-white px-2 py-1 rounded hidden">Title</span>
                                <span class="content-match-indicator bg-green-500 text-white px-2 py-1 rounded hidden">Content</span>
                                <span class="todos-match-indicator bg-purple-500 text-white px-2 py-1 rounded hidden">Todos</span>
                            </div>
                        </div>
                        <!-- Hidden todo data for search functionality -->
                        <div class="hidden" data-todos="<?php echo htmlspecialchars(json_encode($note['todos'])); ?>"></div>
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
                    <input type="hidden" name="todos" id="todos-data" value="">
                    
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

                    <!-- Todo List Section -->
                    <div>
                        <label class="block text-sm font-medium text-gray-300 mb-3">
                            <i class="ri-checkbox-multiple-line mr-2 text-secondary"></i>
                            Todo List
                            <span class="text-gray-500 text-xs ml-2">(Optional - tasks will be added to note content)</span>
                        </label>
                        
                        <!-- Todo Progress Indicator -->
                        <div id="todo-progress" class="todo-progress-indicator hidden">
                            <i class="ri-bar-chart-line text-secondary"></i>
                            <span id="todo-progress-text">0/0 completed</span>
                            <div class="progress-bar">
                                <div class="progress-fill" id="todo-progress-fill" style="width: 0%"></div>
                            </div>
                        </div>
                        
                        <!-- Add Todo Input -->
                        <div class="todo-input-group">
                            <input type="text" id="todo-input" placeholder="✨ Enter a new task..." class="w-full">
                            <button type="button" id="add-todo-btn" onclick="addTodo()">
                                <i class="ri-add-line"></i> Add Task
                            </button>
                        </div>
                        
                        <!-- Todo List Container -->
                        <div id="todo-list" class="todo-list hidden">
                            <!-- Todo items will be added here dynamically -->
                        </div>
                    </div>

                    <!-- Submit Button -->
                    <div class="flex space-x-2 pt-4">
                        <button type="button" class="flex-1 px-4 py-2 bg-gray-700 hover:bg-gray-600 rounded-lg text-white" onclick="closeAddNoteModal()">Cancel</button>
                        <button type="submit" class="flex-1 px-4 py-2 bg-secondary hover:bg-teal-600 rounded-lg text-white">Save Note</button>
                    </div>
                </form>
            </div>
        </div>

        <!-- View Note Modal -->
        <div id="view-note-modal" class="fixed inset-0 flex items-center justify-center bg-black bg-opacity-60 z-50 hidden" onclick="handleViewModalClick(event)">
            <div class="bg-[#242424] rounded-lg p-8 shadow-lg max-w-4xl w-full max-h-[90vh] overflow-y-auto" onclick="event.stopPropagation()">
                <div class="flex justify-between items-center mb-6">
                    <h3 class="text-lg font-medium text-white">View Note</h3>
                    <button type="button" class="text-gray-400 hover:text-white" onclick="closeViewNoteModal()">
                        <i class="ri-close-line text-xl"></i>
                    </button>
                </div>
                <div class="space-y-4">
                    <div>
                        <p class="text-sm text-gray-400 mb-1">Title</p>
                        <p id="view-note-title" class="text-white font-medium text-lg"></p>
                    </div>
                    <div>
                        <p class="text-sm text-gray-400 mb-1">Content</p>
                        <div id="view-note-content" class="bg-gray-800 rounded-lg p-4 text-white whitespace-pre-wrap max-h-96 overflow-y-auto"></div>
                    </div>
                    <div id="view-note-todos" class="hidden">
                        <!-- Todos will be displayed here -->
                    </div>
                    <div class="flex justify-between items-center text-sm text-gray-400">
                        <span id="view-note-author"></span>
                        <span id="view-note-date"></span>
                    </div>
                </div>
                <div class="flex justify-end mt-6">
                    <button type="button" class="px-4 py-2 bg-gray-700 hover:bg-gray-600 rounded-lg text-white" onclick="closeViewNoteModal()">Close</button>
                </div>
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

        <!-- Delete Todo Confirmation Modal -->
        <div id="delete-todo-modal" class="fixed inset-0 flex items-center justify-center bg-black bg-opacity-60 z-50 hidden">
            <div class="bg-[#242424] rounded-lg p-8 shadow-lg text-center max-w-xs w-full">
                <div class="flex justify-between items-center mb-4">
                    <h3 class="text-lg font-medium text-white">Delete Todo</h3>
                    <button type="button" class="text-gray-400 hover:text-white" onclick="closeDeleteTodoModal()">
                        <i class="ri-close-line text-xl"></i>
                    </button>
                </div>
                <p class="text-gray-400 text-sm mb-4">Are you sure you want to delete this todo item? This action cannot be undone.</p>
                <div class="flex space-x-2">
                    <button type="button" class="flex-1 px-4 py-2 bg-gray-700 hover:bg-gray-600 rounded-lg text-white" onclick="closeDeleteTodoModal()">Cancel</button>
                    <button type="button" class="flex-1 px-4 py-2 bg-red-600 hover:bg-red-700 rounded-lg text-white" onclick="confirmDeleteTodo()">Delete</button>
                </div>
            </div>
        </div>

        <!-- Delete All Notes Confirmation Modal -->
        <div id="delete-all-modal" class="fixed inset-0 flex items-center justify-center bg-black bg-opacity-60 z-50 hidden">
            <div class="bg-[#242424] rounded-lg p-8 shadow-lg text-center max-w-md w-full">
                <div class="flex justify-between items-center mb-4">
                    <h3 class="text-lg font-medium text-white">Delete All Notes</h3>
                    <button type="button" class="text-gray-400 hover:text-white" onclick="closeDeleteAllModal()">
                        <i class="ri-close-line text-xl"></i>
                    </button>
                </div>
                <div class="mb-4">
                    <i class="ri-error-warning-line text-4xl text-red-500 mb-3"></i>
                    <p class="text-gray-400 text-sm mb-2">Are you sure you want to delete ALL your notes?</p>
                    <p class="text-red-400 text-xs">This action cannot be undone and will permanently remove all your notes and their associated todo items.</p>
                </div>
                <div class="flex space-x-2">
                    <button type="button" class="flex-1 px-4 py-2 bg-gray-700 hover:bg-gray-600 rounded-lg text-white" onclick="closeDeleteAllModal()">Cancel</button>
                    <button type="button" class="flex-1 px-4 py-2 bg-red-600 hover:bg-red-700 rounded-lg text-white" onclick="confirmDeleteAllNotes()">Delete All</button>
                </div>
            </div>
        </div>

        <!-- Edit Note Modal -->
        <div id="edit-note-modal" class="fixed inset-0 flex items-center justify-center bg-black bg-opacity-60 z-50 hidden" onclick="handleEditModalClick(event)">
            <div class="bg-[#242424] rounded-lg p-8 shadow-lg max-w-2xl w-full max-h-[90vh] overflow-y-auto" onclick="event.stopPropagation()">
                <div class="flex justify-between items-center mb-6">
                    <h3 class="text-lg font-medium text-white">Edit Note</h3>
                    <button type="button" class="text-gray-400 hover:text-white" onclick="closeEditNoteModal()">
                        <i class="ri-close-line text-xl"></i>
                    </button>
                </div>
                <form id="edit-note-form" method="POST" action="notes.php" class="space-y-4">
                    <input type="hidden" name="action" value="edit_note">
                    <input type="hidden" name="note_id" id="edit-note-id">
                    <input type="hidden" name="todos" id="edit-todos-data" value="">
                    
                    <!-- Title Field -->
                    <div>
                        <label for="edit-note-title" class="block text-sm font-medium text-gray-300 mb-1">Title</label>
                        <input type="text" id="edit-note-title" name="title" required class="w-full px-4 py-2 bg-gray-700 border border-gray-600 rounded-lg text-white focus:outline-none focus:border-secondary" placeholder="Enter note title">
                    </div>

                    <!-- Content Field -->
                    <div>
                        <label for="edit-note-content" class="block text-sm font-medium text-gray-300 mb-1">Content</label>
                        <textarea id="edit-note-content" name="content" required class="note-editor w-full" placeholder="Write your note content here..."></textarea>
                    </div>

                    <!-- Todo List Section -->
                    <div>
                        <label class="block text-sm font-medium text-gray-300 mb-3">
                            <i class="ri-checkbox-multiple-line mr-2 text-secondary"></i>
                            Todo List
                            <span class="text-gray-500 text-xs ml-2">(Optional - tasks will be added to note content)</span>
                        </label>
                        
                        <!-- Todo Progress Indicator -->
                        <div id="edit-todo-progress" class="todo-progress-indicator hidden">
                            <i class="ri-bar-chart-line text-secondary"></i>
                            <span id="edit-todo-progress-text">0/0 completed</span>
                            <div class="progress-bar">
                                <div class="progress-fill" id="edit-todo-progress-fill" style="width: 0%"></div>
                            </div>
                        </div>
                        
                        <!-- Add Todo Input -->
                        <div class="todo-input-group">
                            <input type="text" id="edit-todo-input" placeholder="✨ Enter a new task..." class="w-full">
                            <button type="button" id="edit-add-todo-btn" onclick="addEditTodo()">
                                <i class="ri-add-line"></i> Add Task
                            </button>
                        </div>
                        
                        <!-- Todo List Container -->
                        <div id="edit-todo-list" class="todo-list hidden">
                            <!-- Todo items will be added here dynamically -->
                        </div>
                    </div>

                    <!-- Submit Button -->
                    <div class="flex space-x-2 pt-4">
                        <button type="button" class="flex-1 px-4 py-2 bg-gray-700 hover:bg-gray-600 rounded-lg text-white" onclick="closeEditNoteModal()">Cancel</button>
                        <button type="submit" class="flex-1 px-4 py-2 bg-secondary hover:bg-teal-600 rounded-lg text-white">Update Note</button>
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
            // Reset todos array and clear todo list display
            todos = [];
            editingTodoIndex = -1;
            document.getElementById('todo-list').innerHTML = '';
            document.getElementById('todo-input').value = '';
            document.getElementById('add-todo-btn').innerHTML = '<i class="ri-add-line"></i> Add';
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

        // View Note function
        function viewNote(noteId) {
            // Fetch note details via AJAX
            fetch(`get_note.php?id=${noteId}`)
                .then(response => response.json())
                .then(data => {
                    if (data.success) {
                        document.getElementById('view-note-title').textContent = data.note.title;
                        // Display note content
                        document.getElementById('view-note-content').innerHTML = data.note.content.replace(/\n/g, '<br>');
                        
                        // Display todos if they exist
                        const todosContainer = document.getElementById('view-note-todos');
                        if (data.todos && data.todos.length > 0) {
                            const completedCount = data.todos.filter(todo => todo.completed == 1).length;
                            const totalCount = data.todos.length;
                            const progressPercentage = totalCount > 0 ? Math.round((completedCount / totalCount) * 100) : 0;
                            
                            let todosHTML = `
                                <div class="mt-6">
                                    <div class="flex items-center justify-between mb-4">
                                        <h4 class="text-lg font-medium text-white flex items-center">
                                            <i class="ri-checkbox-multiple-line mr-2 text-secondary"></i>
                                            Todo List
                                        </h4>
                                        <div class="flex items-center space-x-2">
                                            <span class="text-sm text-gray-400" id="todo-progress-text">${completedCount}/${totalCount} completed</span>
                                            <div class="w-16 h-2 bg-gray-700 rounded-full overflow-hidden">
                                                <div class="h-full bg-gradient-to-r from-secondary to-teal-400 rounded-full transition-all duration-300" style="width: ${progressPercentage}%"></div>
                                            </div>
                                        </div>
                                    </div>
                                    <div class="space-y-2">
                            `;
                            
                            data.todos.forEach((todo, index) => {
                                const isCompleted = todo.completed == 1;
                                todosHTML += `
                                    <div class="todo-item-view ${isCompleted ? 'completed' : ''} group relative bg-gradient-to-r from-gray-800 to-gray-700 hover:from-gray-700 hover:to-gray-600 border border-gray-600 hover:border-secondary rounded-xl p-4 transition-all duration-300 transform hover:scale-[1.02] hover:shadow-lg" data-todo-id="${todo.id}" data-todo-completed="${isCompleted}">
                                        <div class="flex items-center justify-between">
                                            <div class="flex items-center space-x-3 flex-1">
                                                <div class="todo-checkbox-wrapper relative">
                                                    <button class="todo-checkbox w-6 h-6 rounded-full border-2 border-gray-500 hover:border-secondary transition-all duration-200 flex items-center justify-center ${isCompleted ? 'bg-secondary border-secondary' : 'bg-transparent'}" data-todo-id="${todo.id}" title="${isCompleted ? 'Mark as incomplete' : 'Mark as complete'}" aria-label="${isCompleted ? 'Mark as incomplete' : 'Mark as complete'}">
                                                        ${isCompleted ? '<i class="ri-check-line text-white text-sm"></i>' : ''}
                                                    </button>
                                                    ${isCompleted ? '<div class="absolute inset-0 bg-secondary rounded-full animate-ping opacity-20"></div>' : ''}
                                        </div>
                                                <span class="todo-text ${isCompleted ? 'line-through text-gray-400' : 'text-white'} font-medium transition-all duration-200">${todo.text}</span>
                                            </div>
                                            <div class="flex items-center space-x-2 opacity-0 group-hover:opacity-100 transition-opacity duration-200">
                                                <button class="todo-delete w-8 h-8 rounded-full bg-red-500 hover:bg-red-600 text-white flex items-center justify-center transition-all duration-200 transform hover:scale-110" onclick="deleteTodoItem(${todo.id})" title="Delete todo">
                                                    <i class="ri-delete-bin-line text-sm"></i>
                                                </button>
                                            </div>
                                        </div>
                                        ${isCompleted ? '<div class="absolute top-0 left-0 w-full h-1 bg-gradient-to-r from-secondary to-teal-400 rounded-t-xl"></div>' : ''}
                                    </div>
                                `;
                            });
                            
                            todosHTML += `
                                    </div>
                                    <div class="mt-4 p-3 bg-gray-800 rounded-lg border border-gray-700">
                                        <div class="flex items-center justify-between text-sm">
                                            <span class="text-gray-400">Progress</span>
                                            <span class="text-secondary font-medium">${progressPercentage}%</span>
                                        </div>
                                        <div class="w-full h-2 bg-gray-700 rounded-full mt-2 overflow-hidden">
                                            <div class="h-full bg-gradient-to-r from-secondary to-teal-400 rounded-full transition-all duration-500 ease-out" style="width: ${progressPercentage}%"></div>
                                        </div>
                                    </div>
                                </div>
                            `;
                            todosContainer.innerHTML = todosHTML;
                            todosContainer.classList.remove('hidden');
                            
                            // Add event listeners to checkboxes
                            setTimeout(() => {
                                const checkboxes = todosContainer.querySelectorAll('.todo-checkbox');
                                checkboxes.forEach(checkbox => {
                                    checkbox.addEventListener('click', function() {
                                        const todoId = this.getAttribute('data-todo-id');
                                        const todoItem = this.closest('.todo-item-view');
                                        const currentStatus = todoItem.getAttribute('data-todo-completed') === 'true';
                                        toggleTodoStatus(todoId, currentStatus);
                                    });
                                });
                            }, 100);
                        } else {
                            todosContainer.innerHTML = '';
                            todosContainer.classList.add('hidden');
                        }
                        
                        document.getElementById('view-note-author').textContent = `by ${data.note.author}`;
                        document.getElementById('view-note-date').textContent = `Updated: ${new Date(data.note.last_updated).toLocaleDateString()}`;
                        document.getElementById('view-note-modal').classList.remove('hidden');
                        
                        // Update progress after modal is shown
                        setTimeout(() => {
                            updateTodoProgress();
                        }, 200);
                    } else {
                        alert('Error loading note details');
                    }
                })
                .catch(error => {
                    console.error('Error:', error);
                    alert('Error loading note details');
                });
        }

        // Process todo content to make it interactive
        function processTodoContent(content, noteId) {
            // Convert line breaks to <br> tags
            let processedContent = content.replace(/\n/g, '<br>');
            
            // Find todo list section and make items interactive
            const todoListRegex = /## Todo List:<br>(.*?)(?=<br><br>|$)/s;
            const match = processedContent.match(todoListRegex);
            
            if (match) {
                const todoListContent = match[1];
                const todoItems = todoListContent.split('<br>').filter(item => item.trim().startsWith('-'));
                
                let interactiveTodoList = '## Todo List:<br>';
                todoItems.forEach((item, index) => {
                    const todoText = item.replace(/^-\s*[✅⬜]\s*/, '').trim();
                    const isCompleted = item.includes('✅');
                    
                    interactiveTodoList += `
                        <div class="todo-item-view ${isCompleted ? 'completed' : ''}" data-note-id="${noteId}" data-todo-index="${index}">
                            <span class="todo-checkbox" onclick="toggleTodo(${noteId}, ${index}, ${isCompleted})">
                                ${isCompleted ? '✅' : '⬜'}
                            </span>
                            <span class="todo-text">${todoText}</span>
                            <span class="todo-delete" onclick="deleteTodo(${noteId}, ${index})">❌</span>
                        </div>
                    `;
                });
                
                processedContent = processedContent.replace(todoListRegex, interactiveTodoList);
            }
            
            return processedContent;
        }

        // Toggle todo completion status
        function toggleTodo(noteId, todoIndex, currentStatus) {
            // Send AJAX request to update todo status
            fetch('update_todo.php', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                },
                body: JSON.stringify({
                    note_id: noteId,
                    todo_index: todoIndex,
                    completed: !currentStatus
                })
            })
            .then(response => response.json())
            .then(data => {
                if (data.success) {
                    // Update the UI
                    const todoItem = document.querySelector(`[data-note-id="${noteId}"][data-todo-index="${todoIndex}"]`);
                    const checkbox = todoItem.querySelector('.todo-checkbox');
                    const todoText = todoItem.querySelector('.todo-text');
                    
                    if (!currentStatus) {
                        // Mark as completed
                        checkbox.textContent = '✅';
                        todoItem.classList.add('completed');
                        todoText.style.textDecoration = 'line-through';
                        todoText.style.color = '#888';
                    } else {
                        // Mark as incomplete
                        checkbox.textContent = '⬜';
                        todoItem.classList.remove('completed');
                        todoText.style.textDecoration = 'none';
                        todoText.style.color = '#E5E5E5';
                    }
                } else {
                    alert('Error updating todo status');
                }
            })
            .catch(error => {
                console.error('Error:', error);
                alert('Error updating todo status');
            });
        }

        // Delete todo item
        function deleteTodo(noteId, todoIndex) {
            if (!confirm('Are you sure you want to delete this todo item?')) {
                return;
            }
            
            // Send AJAX request to delete todo
            fetch('delete_todo.php', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                },
                body: JSON.stringify({
                    note_id: noteId,
                    todo_index: todoIndex
                })
            })
            .then(response => response.json())
            .then(data => {
                if (data.success) {
                    // Remove the todo item from UI
                    const todoItem = document.querySelector(`[data-note-id="${noteId}"][data-todo-index="${todoIndex}"]`);
                    todoItem.remove();
                } else {
                    alert('Error deleting todo item');
                }
            })
            .catch(error => {
                console.error('Error:', error);
                alert('Error deleting todo item');
            });
        }

        // Toggle todo status in view modal (for individual todo items)
        function toggleTodoStatus(todoId, currentStatus) {
            console.log(`Toggling todo ${todoId} from ${currentStatus ? 'completed' : 'incomplete'} to ${!currentStatus ? 'completed' : 'incomplete'}`);
            
            // Prevent double-clicking
            const todoItem = document.querySelector(`[data-todo-id="${todoId}"]`);
            const checkbox = todoItem.querySelector('.todo-checkbox');
            
            if (checkbox.disabled) {
                return; // Already processing
            }
            
            // Disable checkbox during request
            checkbox.disabled = true;
            checkbox.style.opacity = '0.6';
            
            // IMMEDIATE UI UPDATE - Update the UI right away for real-time feel
            const todoText = todoItem.querySelector('.todo-text');
            const checkboxWrapper = todoItem.querySelector('.todo-checkbox-wrapper');
            
            if (!currentStatus) {
                // Mark as completed
                checkbox.innerHTML = '<i class="ri-check-line text-white text-sm"></i>';
                checkbox.classList.add('bg-secondary', 'border-secondary');
                todoItem.classList.add('completed');
                todoItem.setAttribute('data-todo-completed', 'true');
                todoText.classList.add('line-through', 'text-gray-400');
                todoText.classList.remove('text-white');
                
                // Update accessibility attributes
                checkbox.setAttribute('title', 'Mark as incomplete');
                checkbox.setAttribute('aria-label', 'Mark as incomplete');
                
                // Add completion indicator
                if (!todoItem.querySelector('.completion-indicator')) {
                    const indicator = document.createElement('div');
                    indicator.className = 'absolute top-0 left-0 w-full h-1 bg-gradient-to-r from-secondary to-teal-400 rounded-t-xl completion-indicator';
                    todoItem.appendChild(indicator);
                }
                
                // Add ping animation
                const pingElement = document.createElement('div');
                pingElement.className = 'absolute inset-0 bg-secondary rounded-full animate-ping opacity-20';
                checkboxWrapper.appendChild(pingElement);
                
                // Remove ping after animation
                setTimeout(() => {
                    if (pingElement.parentNode) {
                        pingElement.remove();
                    }
                }, 1000);
                
                // Add success animation
                todoItem.style.transform = 'scale(1.05)';
                setTimeout(() => {
                    todoItem.style.transform = 'scale(1)';
                }, 200);
                
            } else {
                // Mark as incomplete
                checkbox.innerHTML = '';
                checkbox.classList.remove('bg-secondary', 'border-secondary');
                todoItem.classList.remove('completed');
                todoItem.setAttribute('data-todo-completed', 'false');
                todoText.classList.remove('line-through', 'text-gray-400');
                todoText.classList.add('text-white');
                
                // Update accessibility attributes
                checkbox.setAttribute('title', 'Mark as complete');
                checkbox.setAttribute('aria-label', 'Mark as complete');
                
                // Remove completion indicator
                const indicator = todoItem.querySelector('.completion-indicator');
                if (indicator) {
                    indicator.remove();
                }
            }
            
            // IMMEDIATE PROGRESS UPDATE - Update progress right away
            updateTodoProgress();
            
            // Send AJAX request to update todo status
            fetch('update_todo_status.php', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                },
                body: JSON.stringify({
                    todo_id: todoId,
                    completed: !currentStatus
                })
            })
            .then(response => response.json())
            .then(data => {
                if (data.success) {
                    // Server update successful - no need to update UI again since we did it immediately
                    console.log('Todo status updated successfully on server');
                } else {
                    // Server error - revert the UI changes
                    console.error('Server error:', data.message);
                    showNotification('Error updating todo status: ' + (data.message || 'Unknown error'), 'error');
                    
                    // Revert the UI changes
                    if (!currentStatus) {
                        // Revert from completed back to incomplete
                        checkbox.innerHTML = '';
                        checkbox.classList.remove('bg-secondary', 'border-secondary');
                        todoItem.classList.remove('completed');
                        todoItem.setAttribute('data-todo-completed', 'false');
                        todoText.classList.remove('line-through', 'text-gray-400');
                        todoText.classList.add('text-white');
                        checkbox.setAttribute('title', 'Mark as complete');
                        checkbox.setAttribute('aria-label', 'Mark as complete');
                        
                        const indicator = todoItem.querySelector('.completion-indicator');
                        if (indicator) {
                            indicator.remove();
                        }
                    } else {
                        // Revert from incomplete back to completed
                        checkbox.innerHTML = '<i class="ri-check-line text-white text-sm"></i>';
                        checkbox.classList.add('bg-secondary', 'border-secondary');
                        todoItem.classList.add('completed');
                        todoItem.setAttribute('data-todo-completed', 'true');
                        todoText.classList.add('line-through', 'text-gray-400');
                        todoText.classList.remove('text-white');
                        checkbox.setAttribute('title', 'Mark as incomplete');
                        checkbox.setAttribute('aria-label', 'Mark as incomplete');
                        
                        if (!todoItem.querySelector('.completion-indicator')) {
                            const indicator = document.createElement('div');
                            indicator.className = 'absolute top-0 left-0 w-full h-1 bg-gradient-to-r from-secondary to-teal-400 rounded-t-xl completion-indicator';
                            todoItem.appendChild(indicator);
                        }
                    }
                    
                    // Update progress bar again after revert
                    updateTodoProgress();
                }
            })
            .catch(error => {
                console.error('Network error:', error);
                showNotification('Network error while updating todo status', 'error');
                
                // Revert the UI changes on network error
                if (!currentStatus) {
                    // Revert from completed back to incomplete
                    checkbox.innerHTML = '';
                    checkbox.classList.remove('bg-secondary', 'border-secondary');
                        todoItem.classList.remove('completed');
                    todoItem.setAttribute('data-todo-completed', 'false');
                        todoText.classList.remove('line-through', 'text-gray-400');
                        todoText.classList.add('text-white');
                    checkbox.setAttribute('title', 'Mark as complete');
                    checkbox.setAttribute('aria-label', 'Mark as complete');
                    
                    const indicator = todoItem.querySelector('.completion-indicator');
                    if (indicator) {
                        indicator.remove();
                    }
                } else {
                    // Revert from incomplete back to completed
                    checkbox.innerHTML = '<i class="ri-check-line text-white text-sm"></i>';
                    checkbox.classList.add('bg-secondary', 'border-secondary');
                    todoItem.classList.add('completed');
                    todoItem.setAttribute('data-todo-completed', 'true');
                    todoText.classList.add('line-through', 'text-gray-400');
                    todoText.classList.remove('text-white');
                    checkbox.setAttribute('title', 'Mark as incomplete');
                    checkbox.setAttribute('aria-label', 'Mark as incomplete');
                    
                    if (!todoItem.querySelector('.completion-indicator')) {
                        const indicator = document.createElement('div');
                        indicator.className = 'absolute top-0 left-0 w-full h-1 bg-gradient-to-r from-secondary to-teal-400 rounded-t-xl completion-indicator';
                        todoItem.appendChild(indicator);
                    }
                }
                
                // Update progress bar again after revert
                updateTodoProgress();
            })
            .finally(() => {
                // Re-enable checkbox
                checkbox.disabled = false;
                checkbox.style.opacity = '1';
            });
        }
        
        // Update todo progress bar
        function updateTodoProgress() {
            // Look specifically within the view note modal
            const viewNoteModal = document.getElementById('view-note-modal');
            if (!viewNoteModal) return;
            
            const todoItems = viewNoteModal.querySelectorAll('.todo-item-view');
            const completedItems = viewNoteModal.querySelectorAll('.todo-item-view.completed');
            const totalCount = todoItems.length;
            const completedCount = completedItems.length;
            const progressPercentage = totalCount > 0 ? Math.round((completedCount / totalCount) * 100) : 0;
            
            console.log(`Progress update: ${completedCount}/${totalCount} completed (${progressPercentage}%)`);
            console.log('Todo items found:', todoItems.length);
            console.log('Completed items found:', completedItems.length);
            
            // Debug: Log each todo item and its completion status
            todoItems.forEach((item, index) => {
                const isCompleted = item.classList.contains('completed');
                const dataCompleted = item.getAttribute('data-todo-completed');
                console.log(`Todo ${index + 1}: class="completed"=${isCompleted}, data-todo-completed="${dataCompleted}"`);
            });
            
            // Update the main progress text using the specific ID
            const mainProgressText = viewNoteModal.querySelector('#todo-progress-text');
            if (mainProgressText) {
                mainProgressText.textContent = `${completedCount}/${totalCount} completed`;
                console.log('Updated main progress text:', mainProgressText.textContent);
            } else {
                console.log('Progress text element not found!');
            }
            
            // Update progress percentage
            const progressPercent = viewNoteModal.querySelector('.text-secondary.font-medium');
            if (progressPercent) {
                progressPercent.textContent = `${progressPercentage}%`;
                console.log('Updated progress percentage:', progressPercent.textContent);
            }
            
            // Update progress bars
            const progressBars = viewNoteModal.querySelectorAll('.bg-gradient-to-r.from-secondary.to-teal-400');
            progressBars.forEach(bar => {
                bar.style.width = `${progressPercentage}%`;
                console.log('Updated progress bar width:', bar.style.width);
            });
        }

        // Delete todo item in view modal
        function deleteTodoItem(todoId) {
            // Store the todo ID for confirmation
            window.todoToDelete = todoId;
            
            // Show the delete confirmation modal
            document.getElementById('delete-todo-modal').classList.remove('hidden');
        }

        // Confirm delete todo after modal confirmation
        function confirmDeleteTodo() {
            const todoId = window.todoToDelete;
            
            if (!todoId) {
                closeDeleteTodoModal();
                return;
            }
            
            // Send AJAX request to delete todo
            fetch('delete_todo_item.php', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                },
                body: JSON.stringify({
                    todo_id: todoId
                })
            })
            .then(response => response.json())
            .then(data => {
                if (data.success) {
                    // Remove the todo item from UI
                    const todoItem = document.querySelector(`[data-todo-id="${todoId}"]`);
                    todoItem.remove();
                    
                    // Check if there are no more todos
                    const remainingTodos = document.querySelectorAll('[data-todo-id]');
                    if (remainingTodos.length === 0) {
                        document.getElementById('view-note-todos').classList.add('hidden');
                    }
                    
                    // Show success notification
                    showNotification('Todo item deleted successfully', 'success');
                } else {
                    showNotification('Error deleting todo item', 'error');
                }
            })
            .catch(error => {
                console.error('Error:', error);
                showNotification('Error deleting todo item', 'error');
            })
            .finally(() => {
                closeDeleteTodoModal();
            });
        }

        // Close delete todo modal
        function closeDeleteTodoModal() {
            document.getElementById('delete-todo-modal').classList.add('hidden');
            window.todoToDelete = null;
        }

        // Open delete all notes modal
        function openDeleteAllModal() {
            document.getElementById('delete-all-modal').classList.remove('hidden');
        }

        // Close delete all notes modal
        function closeDeleteAllModal() {
            document.getElementById('delete-all-modal').classList.add('hidden');
        }

        // Confirm delete all notes
        function confirmDeleteAllNotes() {
            // Create and submit form
            const form = document.createElement('form');
            form.method = 'POST';
            form.action = 'notes.php';
            
            const actionInput = document.createElement('input');
            actionInput.type = 'hidden';
            actionInput.name = 'action';
            actionInput.value = 'delete_all_notes';
            
            form.appendChild(actionInput);
            document.body.appendChild(form);
            form.submit();
        }

        function closeViewNoteModal() {
            document.getElementById('view-note-modal').classList.add('hidden');
        }

        function handleViewModalClick(event) {
            // Close view modal if clicking the backdrop (outside the modal container)
            if (event.target.id === 'view-note-modal') {
                closeViewNoteModal();
            }
        }

        // Edit Note function
        function editNote(noteId) {
            // Fetch note details via AJAX
            fetch(`get_note.php?id=${noteId}`)
                .then(response => response.json())
                .then(data => {
                    if (data.success) {
                        // Populate the edit form
                        document.getElementById('edit-note-id').value = noteId;
                        document.getElementById('edit-note-title').value = data.note.title;
                        document.getElementById('edit-note-content').value = data.note.content;
                        
                        // Load existing todos
                        editTodos = [];
                        if (data.todos && data.todos.length > 0) {
                            data.todos.forEach(todo => {
                                editTodos.push({
                                    text: todo.text,
                                    completed: todo.completed == 1
                                });
                            });
                        }
                        
                        // Render the todo list
                        renderEditTodoList();
                        
                        // Show the edit modal
                        document.getElementById('edit-note-modal').classList.remove('hidden');
                        
                        // Focus on title input
                        setTimeout(() => {
                            document.getElementById('edit-note-title').focus();
                        }, 100);
                    } else {
                        showNotification('Error loading note details', 'error');
                    }
                })
                .catch(error => {
                    console.error('Error:', error);
                    showNotification('Error loading note details', 'error');
                });
        }

        // Close edit note modal
        function closeEditNoteModal() {
            document.getElementById('edit-note-modal').classList.add('hidden');
            document.getElementById('edit-note-form').reset();
            editTodos = [];
            editingEditTodoIndex = -1;
            document.getElementById('edit-todo-list').innerHTML = '';
            document.getElementById('edit-todo-input').value = '';
            document.getElementById('edit-add-todo-btn').innerHTML = '<i class="ri-add-line"></i> Add';
        }

        // Handle edit modal click outside
        function handleEditModalClick(event) {
            if (event.target.id === 'edit-note-modal') {
                closeEditNoteModal();
            }
        }

        // Reset timeout on modal interactions
        document.getElementById('logout-modal').addEventListener('mousemove', resetActivityTimeout);
        document.getElementById('logout-modal').addEventListener('keypress', resetActivityTimeout);
        document.getElementById('add-note-modal').addEventListener('mousemove', resetActivityTimeout);
        document.getElementById('add-note-modal').addEventListener('keypress', resetActivityTimeout);
        document.getElementById('view-note-modal').addEventListener('mousemove', resetActivityTimeout);
        document.getElementById('view-note-modal').addEventListener('keypress', resetActivityTimeout);
        document.getElementById('delete-note-modal').addEventListener('mousemove', resetActivityTimeout);
        document.getElementById('delete-note-modal').addEventListener('keypress', resetActivityTimeout);
        document.getElementById('delete-todo-modal').addEventListener('mousemove', resetActivityTimeout);
        document.getElementById('delete-todo-modal').addEventListener('keypress', resetActivityTimeout);
        document.getElementById('edit-note-modal').addEventListener('mousemove', resetActivityTimeout);
        document.getElementById('edit-note-modal').addEventListener('keypress', resetActivityTimeout);
        document.getElementById('delete-all-modal').addEventListener('mousemove', resetActivityTimeout);
        document.getElementById('delete-all-modal').addEventListener('keypress', resetActivityTimeout);

        // Close delete todo modal when clicking outside
        document.getElementById('delete-todo-modal').addEventListener('click', function(e) {
            if (e.target === this) {
                closeDeleteTodoModal();
            }
        });

        // Close delete all modal when clicking outside
        document.getElementById('delete-all-modal').addEventListener('click', function(e) {
            if (e.target === this) {
                closeDeleteAllModal();
            }
        });

        // Add search functionality
        document.getElementById('search-input').addEventListener('input', function(e) {
            const searchTerm = e.target.value.toLowerCase();
            const noteCards = document.querySelectorAll('.note-card');
            let visibleCount = 0;
            
            noteCards.forEach(card => {
                const title = card.querySelector('h3').textContent.toLowerCase();
                const content = card.querySelector('p').textContent.toLowerCase();
                
                // Get todos data for this note
                const todosElement = card.querySelector('[data-todos]');
                let todosText = '';
                if (todosElement) {
                    try {
                        const todos = JSON.parse(todosElement.getAttribute('data-todos'));
                        todosText = todos.join(' ').toLowerCase();
                    } catch (e) {
                        console.error('Error parsing todos data:', e);
                    }
                }
                
                // Search in title, content, and todos
                const titleMatch = title.includes(searchTerm);
                const contentMatch = content.includes(searchTerm);
                const todosMatch = todosText.includes(searchTerm);
                
                if (titleMatch || contentMatch || todosMatch) {
                    card.style.display = 'block';
                    visibleCount++;
                    
                    // Add highlight class if search term is found
                    if (searchTerm.length > 0) {
                        card.classList.add('search-highlight');
                        
                        // Add data attributes to show what matched
                        card.setAttribute('data-title-match', titleMatch);
                        card.setAttribute('data-content-match', contentMatch);
                        card.setAttribute('data-todos-match', todosMatch);
                    } else {
                        card.classList.remove('search-highlight');
                        card.removeAttribute('data-title-match');
                        card.removeAttribute('data-content-match');
                        card.removeAttribute('data-todos-match');
                    }
                } else {
                    card.style.display = 'none';
                    card.classList.remove('search-highlight');
                    card.removeAttribute('data-title-match');
                    card.removeAttribute('data-content-match');
                    card.removeAttribute('data-todos-match');
                }
            });
            
            // Update search results count
            const resultsCountElement = document.getElementById('results-count');
            const searchResultsCount = document.getElementById('search-results-count');
            
            // Show/hide no results message
            const noResultsElement = document.getElementById('no-search-results');
            
            if (searchTerm.length > 0) {
                if (resultsCountElement) {
                    if (visibleCount === 0) {
                        resultsCountElement.textContent = 'No';
                        searchResultsCount.innerHTML = '<div class="flex items-center"><i class="ri-search-line mr-1"></i><span id="results-count">No</span> results found</div>';
                        if (noResultsElement) {
                            noResultsElement.classList.remove('hidden');
                        }
                    } else {
                        resultsCountElement.textContent = visibleCount;
                        searchResultsCount.innerHTML = '<div class="flex items-center"><i class="ri-search-line mr-1"></i><span id="results-count">' + visibleCount + '</span> result' + (visibleCount === 1 ? '' : 's') + ' found</div>';
                        if (noResultsElement) {
                            noResultsElement.classList.add('hidden');
                        }
                    }
                }
                if (searchResultsCount) {
                    searchResultsCount.classList.remove('hidden');
                }
            } else {
                if (searchResultsCount) {
                    searchResultsCount.classList.add('hidden');
                }
                if (noResultsElement) {
                    noResultsElement.classList.add('hidden');
                }
                // Remove all highlights when search is cleared
                noteCards.forEach(card => {
                    card.classList.remove('search-highlight');
                });
            }
            
            // Re-apply current sort after search
            if (searchTerm.length === 0) {
                sortNotes(currentSort);
            }
        });

        // Reset timeout on search input
        document.getElementById('search-input').addEventListener('input', resetActivityTimeout);

        // Sort functionality
        let currentSort = 'newest';
        let allNotes = []; // Store all notes for sorting

        // Initialize sort system
        function initializeSort() {
            // Store all notes in the allNotes array
            const noteCards = document.querySelectorAll('.note-card');
            allNotes = Array.from(noteCards).map(card => {
                const title = card.querySelector('h3').textContent;
                const content = card.querySelector('p').textContent;
                const dateText = card.querySelector('.text-xs.text-gray-500 span').textContent;
                const author = card.querySelector('.text-xs.text-gray-500 span:last-child').textContent.replace('by ', '');
                const todosElement = card.querySelector('[data-todos]');
                let todos = [];
                if (todosElement) {
                    try {
                        todos = JSON.parse(todosElement.getAttribute('data-todos'));
                    } catch (e) {
                        console.error('Error parsing todos data:', e);
                    }
                }
                
                return {
                    element: card,
                    title: title,
                    content: content,
                    date: new Date(dateText),
                    author: author,
                    todosCount: todos.length,
                    todos: todos
                };
            });
        }

        // Sort notes function
        function sortNotes(sortType) {
            if (allNotes.length === 0) {
                initializeSort();
            }
            
            const notesContainer = document.querySelector('.grid');
            const noteCards = Array.from(allNotes);
            
            // Sort the notes array
            noteCards.sort((a, b) => {
                switch (sortType) {
                    case 'newest':
                        return b.date - a.date;
                    case 'oldest':
                        return a.date - b.date;
                    case 'title-asc':
                        return a.title.localeCompare(b.title);
                    case 'title-desc':
                        return b.title.localeCompare(a.title);
                    case 'author':
                        return a.author.localeCompare(b.author);
                    case 'todos':
                        return b.todosCount - a.todosCount;
                    default:
                        return 0;
                }
            });
            
            // Re-append notes in sorted order
            noteCards.forEach(note => {
                notesContainer.appendChild(note.element);
            });
            
            // Update sort button text
            const sortText = document.getElementById('sort-text');
            const sortOptions = {
                'newest': 'Newest First',
                'oldest': 'Oldest First',
                'title-asc': 'Title A-Z',
                'title-desc': 'Title Z-A',
                'author': 'Author',
                'todos': 'Most Todos'
            };
            sortText.textContent = sortOptions[sortType];
            
            // Update active sort option
            updateActiveSortOption(sortType);
        }

        // Update active sort option in dropdown
        function updateActiveSortOption(sortType) {
            // Remove all active indicators
            document.querySelectorAll('.sort-option i').forEach(icon => {
                icon.classList.add('hidden');
            });
            
            // Add active indicator to current sort option
            const activeOption = document.querySelector(`[data-sort="${sortType}"] i`);
            if (activeOption) {
                activeOption.classList.remove('hidden');
            }
        }

        // Toggle sort dropdown
        document.getElementById('sort-button').addEventListener('click', function(e) {
            e.stopPropagation();
            const dropdown = document.getElementById('sort-dropdown');
            dropdown.classList.toggle('hidden');
        });

        // Close dropdown when clicking outside
        document.addEventListener('click', function(e) {
            const dropdown = document.getElementById('sort-dropdown');
            const sortButton = document.getElementById('sort-button');
            
            if (!dropdown.contains(e.target) && !sortButton.contains(e.target)) {
                dropdown.classList.add('hidden');
            }
        });

        // Handle sort option clicks
        document.querySelectorAll('.sort-option').forEach(option => {
            option.addEventListener('click', function() {
                const sortType = this.getAttribute('data-sort');
                currentSort = sortType;
                sortNotes(sortType);
                document.getElementById('sort-dropdown').classList.add('hidden');
            });
        });

        // Initialize sort system when page loads
        document.addEventListener('DOMContentLoaded', function() {
            initializeSort();
            updateActiveSortOption(currentSort);
        });

        // Form submission handler to capture todos data
        document.getElementById('add-note-form').addEventListener('submit', function(e) {
            // Update todos data before submitting
            const todosData = JSON.stringify(todos);
            document.getElementById('todos-data').value = todosData;
        });

        // Todo List functionality
        let todos = [];
        let editingTodoIndex = -1;
        
        // Edit Todo List functionality
        let editTodos = [];
        let editingEditTodoIndex = -1;

        function addTodo() {
            const todoInput = document.getElementById('todo-input');
            const todoText = todoInput.value.trim();
            
            if (todoText === '') {
                return;
            }

            if (editingTodoIndex >= 0) {
                // Update existing todo
                todos[editingTodoIndex].text = todoText;
                editingTodoIndex = -1;
                document.getElementById('add-todo-btn').innerHTML = '<i class="ri-add-line"></i> Add Task';
            } else {
                // Add new todo
                todos.push({
                    text: todoText,
                    completed: false
                });
            }

            todoInput.value = '';
            renderTodoList();
            updateTodosData();
        }

        function renderTodoList() {
            const todoList = document.getElementById('todo-list');
            const todoProgress = document.getElementById('todo-progress');
            
            if (todos.length === 0) {
                todoList.classList.add('hidden');
                todoProgress.classList.add('hidden');
                return;
            }

            todoList.classList.remove('hidden');
            todoProgress.classList.remove('hidden');
            todoList.innerHTML = '';

            // Calculate progress
            const completedCount = todos.filter(todo => todo.completed).length;
            const totalCount = todos.length;
            const progressPercentage = totalCount > 0 ? Math.round((completedCount / totalCount) * 100) : 0;

            // Update progress indicator
            const progressText = document.getElementById('todo-progress-text');
            const progressFill = document.getElementById('todo-progress-fill');
            if (progressText) progressText.textContent = `${completedCount}/${totalCount} completed`;
            if (progressFill) progressFill.style.width = `${progressPercentage}%`;

            todos.forEach((todo, index) => {
                const todoItem = document.createElement('div');
                todoItem.className = `todo-item ${todo.completed ? 'completed' : ''}`;
                todoItem.style.animationDelay = `${index * 0.1}s`;
                todoItem.innerHTML = `
                    <input type="text" value="${todo.text}" ${todo.completed ? 'disabled' : ''} onchange="updateTodoText(${index}, this.value)" placeholder="Enter task text...">
                    <div class="todo-actions">
                        <button type="button" class="todo-btn complete" onclick="toggleTodoComplete(${index})" title="${todo.completed ? 'Mark incomplete' : 'Mark complete'}">
                            <i class="ri-${todo.completed ? 'checkbox-line' : 'checkbox-blank-line'}"></i>
                        </button>
                        <button type="button" class="todo-btn edit" onclick="editTodo(${index})" title="Edit task">
                            <i class="ri-edit-line"></i>
                        </button>
                        <button type="button" class="todo-btn delete" onclick="deleteTodo(${index})" title="Delete task">
                            <i class="ri-delete-bin-line"></i>
                        </button>
                    </div>
                `;
                todoList.appendChild(todoItem);
            });
        }

        function updateTodoText(index, newText) {
            if (newText.trim() !== '') {
                todos[index].text = newText.trim();
                updateTodosData();
            }
        }

        function toggleTodoComplete(index) {
            todos[index].completed = !todos[index].completed;
            renderTodoList();
            updateTodosData();
        }

        function editTodo(index) {
            editingTodoIndex = index;
            const todoInput = document.getElementById('todo-input');
            const addBtn = document.getElementById('add-todo-btn');
            
            todoInput.value = todos[index].text;
            addBtn.innerHTML = '<i class="ri-edit-line"></i> Update Task';
            todoInput.focus();
        }

        function deleteTodo(index) {
            todos.splice(index, 1);
            renderTodoList();
            updateTodosData();
        }

        function updateTodosData() {
            document.getElementById('todos-data').value = JSON.stringify(todos);
        }

        // Handle Enter key in todo input
        document.getElementById('todo-input').addEventListener('keypress', function(e) {
            if (e.key === 'Enter') {
                e.preventDefault();
                addTodo();
            }
        });

        // Update closeAddNoteModal to reset todos
        function closeAddNoteModal() {
            document.getElementById('add-note-modal').classList.add('hidden');
            document.getElementById('add-note-form').reset();
            todos = [];
            editingTodoIndex = -1;
            document.getElementById('todo-list').classList.add('hidden');
            document.getElementById('add-todo-btn').innerHTML = '<i class="ri-add-line"></i> Add';
            updateTodosData();
        }

        // Edit Todo Functions
        function addEditTodo() {
            const todoInput = document.getElementById('edit-todo-input');
            const todoText = todoInput.value.trim();
            
            if (todoText === '') {
                return;
            }

            if (editingEditTodoIndex >= 0) {
                // Update existing todo
                editTodos[editingEditTodoIndex].text = todoText;
                editingEditTodoIndex = -1;
                document.getElementById('edit-add-todo-btn').innerHTML = '<i class="ri-add-line"></i> Add Task';
            } else {
                // Add new todo
                editTodos.push({
                    text: todoText,
                    completed: false
                });
            }

            todoInput.value = '';
            renderEditTodoList();
            updateEditTodosData();
        }

        function renderEditTodoList() {
            const todoList = document.getElementById('edit-todo-list');
            const todoProgress = document.getElementById('edit-todo-progress');
            
            if (editTodos.length === 0) {
                todoList.classList.add('hidden');
                todoProgress.classList.add('hidden');
                return;
            }

            todoList.classList.remove('hidden');
            todoProgress.classList.remove('hidden');
            todoList.innerHTML = '';

            // Calculate progress
            const completedCount = editTodos.filter(todo => todo.completed).length;
            const totalCount = editTodos.length;
            const progressPercentage = totalCount > 0 ? Math.round((completedCount / totalCount) * 100) : 0;

            // Update progress indicator
            const progressText = document.getElementById('edit-todo-progress-text');
            const progressFill = document.getElementById('edit-todo-progress-fill');
            if (progressText) progressText.textContent = `${completedCount}/${totalCount} completed`;
            if (progressFill) progressFill.style.width = `${progressPercentage}%`;

            editTodos.forEach((todo, index) => {
                const todoItem = document.createElement('div');
                todoItem.className = `todo-item ${todo.completed ? 'completed' : ''}`;
                todoItem.style.animationDelay = `${index * 0.1}s`;
                todoItem.innerHTML = `
                    <input type="text" value="${todo.text}" ${todo.completed ? 'disabled' : ''} onchange="updateEditTodoText(${index}, this.value)" placeholder="Enter task text...">
                    <div class="todo-actions">
                        <button type="button" class="todo-btn complete" onclick="toggleEditTodoComplete(${index})" title="${todo.completed ? 'Mark incomplete' : 'Mark complete'}">
                            <i class="ri-${todo.completed ? 'checkbox-line' : 'checkbox-blank-line'}"></i>
                        </button>
                        <button type="button" class="todo-btn edit" onclick="editEditTodo(${index})" title="Edit task">
                            <i class="ri-edit-line"></i>
                        </button>
                        <button type="button" class="todo-btn delete" onclick="deleteEditTodo(${index})" title="Delete task">
                            <i class="ri-delete-bin-line"></i>
                        </button>
                    </div>
                `;
                todoList.appendChild(todoItem);
            });
        }

        function updateEditTodoText(index, newText) {
            if (newText.trim() !== '') {
                editTodos[index].text = newText.trim();
                updateEditTodosData();
            }
        }

        function toggleEditTodoComplete(index) {
            editTodos[index].completed = !editTodos[index].completed;
            renderEditTodoList();
            updateEditTodosData();
        }

        function editEditTodo(index) {
            editingEditTodoIndex = index;
            const todoInput = document.getElementById('edit-todo-input');
            const addBtn = document.getElementById('edit-add-todo-btn');
            
            todoInput.value = editTodos[index].text;
            addBtn.innerHTML = '<i class="ri-edit-line"></i> Update Task';
            todoInput.focus();
        }

        function deleteEditTodo(index) {
            editTodos.splice(index, 1);
            renderEditTodoList();
            updateEditTodosData();
        }

        function updateEditTodosData() {
            document.getElementById('edit-todos-data').value = JSON.stringify(editTodos);
        }

        // Handle Enter key in edit todo input
        document.getElementById('edit-todo-input').addEventListener('keypress', function(e) {
            if (e.key === 'Enter') {
                e.preventDefault();
                addEditTodo();
            }
        });

        // Form submission handler for edit note form
        document.getElementById('edit-note-form').addEventListener('submit', function(e) {
            // Update todos data before submitting
            const todosData = JSON.stringify(editTodos);
            document.getElementById('edit-todos-data').value = todosData;
        });
    </script>
</body>
</html> 