<?php
session_start();
require_once 'db.php';

// Enable error reporting for debugging
error_reporting(E_ALL);
ini_set('display_errors', 1);

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

if (!isset($input['password'])) {
    error_log("No password provided in request");
    http_response_code(400);
    echo json_encode(['success' => false, 'message' => 'No password provided']);
    exit;
}

try {
    // Get encryption key
    $encryption_key = hash('sha256', $_SESSION['user_id'] . 'your-secret-salt', true);
    
    // Decode the stored data
    $decoded = base64_decode($input['password']);
    if ($decoded === false) {
        throw new Exception('Invalid password format');
    }
    
    // Extract IV and encrypted password
    $iv_length = openssl_cipher_iv_length('aes-256-cbc');
    $iv = substr($decoded, 0, $iv_length);
    $encrypted_password = substr($decoded, $iv_length);
    
    // Decrypt
    $decrypted = openssl_decrypt(
        $encrypted_password,
        'aes-256-cbc',
        $encryption_key,
        OPENSSL_RAW_DATA,
        $iv
    );

    if ($decrypted === false) {
        throw new Exception('Decryption failed: ' . openssl_error_string());
    }

    echo json_encode(['success' => true, 'password' => $decrypted]);

} catch (Exception $e) {
    error_log("Error in decrypt_password.php: " . $e->getMessage());
    http_response_code(500);
    echo json_encode(['success' => false, 'message' => $e->getMessage()]);
} 