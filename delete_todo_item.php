<?php
session_start();
require_once 'db.php';

// Set proper headers
header('Content-Type: application/json');
header('Access-Control-Allow-Origin: *');
header('Access-Control-Allow-Methods: POST');
header('Access-Control-Allow-Headers: Content-Type');

// Check if user is logged in
if (!isset($_SESSION['logged_in']) || $_SESSION['logged_in'] !== true) {
    http_response_code(401);
    echo json_encode(['success' => false, 'message' => 'Unauthorized']);
    exit;
}

// Get JSON input
$input = json_decode(file_get_contents('php://input'), true);

if (!isset($input['todo_id'])) {
    http_response_code(400);
    echo json_encode(['success' => false, 'message' => 'Todo ID is required']);
    exit;
}

try {
    $todoId = $input['todo_id'];
    
    // First, verify that the todo belongs to the current user
    $stmt = $pdo->prepare("
        SELECT t.id 
        FROM todos t 
        JOIN notes n ON t.note_id = n.id 
        WHERE t.id = ? AND n.user_id = ?
    ");
    $stmt->execute([$todoId, $_SESSION['user_id']]);
    $todo = $stmt->fetch();
    
    if (!$todo) {
        http_response_code(404);
        echo json_encode(['success' => false, 'message' => 'Todo not found or access denied']);
        exit;
    }
    
    // Delete the todo
    $deleteStmt = $pdo->prepare("DELETE FROM todos WHERE id = ?");
    $result = $deleteStmt->execute([$todoId]);
    
    if ($result) {
        echo json_encode(['success' => true, 'message' => 'Todo deleted successfully']);
    } else {
        throw new Exception('Failed to delete todo');
    }

} catch (Exception $e) {
    error_log("Error in delete_todo_item.php: " . $e->getMessage());
    http_response_code(500);
    echo json_encode(['success' => false, 'message' => 'Error deleting todo']);
}
?> 