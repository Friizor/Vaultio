<?php
session_start();
require_once 'db.php';

// Check if user is logged in
if (!isset($_SESSION['logged_in']) || $_SESSION['logged_in'] !== true) {
    echo json_encode(['success' => false, 'message' => 'Not authenticated']);
    exit;
}

// Check if note ID is provided
if (!isset($_GET['id'])) {
    echo json_encode(['success' => false, 'message' => 'Note ID is required']);
    exit;
}

try {
    // Fetch note details
    $stmt = $pdo->prepare("SELECT * FROM notes WHERE id = ? AND user_id = ? LIMIT 1");
    $stmt->execute([$_GET['id'], $_SESSION['user_id']]);
    $note = $stmt->fetch();

    if (!$note) {
        echo json_encode(['success' => false, 'message' => 'Note not found']);
        exit;
    }

    // Fetch todos for this note
    $todoStmt = $pdo->prepare("SELECT * FROM todos WHERE note_id = ? ORDER BY position ASC");
    $todoStmt->execute([$note['id']]);
    $todos = $todoStmt->fetchAll(PDO::FETCH_ASSOC);

    // Return note details with todos
    echo json_encode([
        'success' => true,
        'note' => [
            'id' => $note['id'],
            'title' => $note['title'],
            'content' => $note['content'],
            'author' => $note['author'],
            'created_at' => $note['created_at'],
            'last_updated' => $note['last_updated']
        ],
        'todos' => $todos
    ]);

} catch (Exception $e) {
    echo json_encode(['success' => false, 'message' => 'Error fetching note details']);
}
?> 