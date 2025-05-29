<?php
session_start();
require_once 'db.php';

// Enable error reporting for debugging
error_reporting(E_ALL);
ini_set('display_errors', 1);

// Set proper headers
header('Content-Type: application/json');
header('Access-Control-Allow-Origin: *');
header('Access-Control-Allow-Methods: POST');
header('Access-Control-Allow-Headers: Content-Type');

// Check if user is logged in
if (!isset($_SESSION['logged_in']) || $_SESSION['logged_in'] !== true) {
    error_log("User not logged in");
    http_response_code(401);
    echo json_encode(['success' => false, 'message' => 'Unauthorized']);
    exit;
}

// Get JSON input
$input = json_decode(file_get_contents('php://input'), true);

// Debug log
error_log("Received request: " . print_r($input, true));
error_log("Session user_id: " . $_SESSION['user_id']);

if (!isset($input['password'])) {
    error_log("No password provided in request");
    http_response_code(400);
    echo json_encode(['success' => false, 'message' => 'No password provided']);
    exit;
}

try {
    // Get encryption key
    $key = $_SESSION['user_id'] . 'your-secret-salt';
    $key = substr(hash('sha256', $key, true), 0, 32);
    
    // Decode the stored data
    $data = base64_decode($input['password']);
    if ($data === false) {
        throw new Exception('Invalid password format');
    }
    
    // Extract IV and encrypted password
    $iv = substr($data, 0, 16);
    $encrypted = substr($data, 16);
    
    // Decrypt
    $decrypted = openssl_decrypt($encrypted, 'AES-256-CBC', $key, 0, $iv);
    
    if ($decrypted === false) {
        throw new Exception('Decryption failed');
    }

    error_log("Successfully decrypted password");
    echo json_encode(['success' => true, 'password' => $decrypted]);

} catch (Exception $e) {
    error_log("Error in decrypt_password.php: " . $e->getMessage());
    http_response_code(500);
    echo json_encode(['success' => false, 'message' => $e->getMessage()]);
} 