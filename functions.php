<?php
require_once 'db.php';

/**
 * Generates a unique random user ID between 10000000 and 99999999
 * @return int The generated unique user ID
 */
function generateUniqueUserId() {
    global $pdo;
    
    do {
        // Generate random number between 10000000 and 99999999
        $userId = mt_rand(10000000, 99999999);
        
        // Check if ID already exists
        $stmt = $pdo->prepare('SELECT id FROM users WHERE id = ?');
        $stmt->execute([$userId]);
    } while ($stmt->fetch()); // Keep generating until we find an unused ID
    
    return $userId;
} 