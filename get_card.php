<?php
session_start();
require_once 'db.php';

// Check if user is logged in
if (!isset($_SESSION['logged_in']) || $_SESSION['logged_in'] !== true) {
    echo json_encode(['success' => false, 'message' => 'Not authenticated']);
    exit;
}

// Check if card ID is provided
if (!isset($_GET['id'])) {
    echo json_encode(['success' => false, 'message' => 'Card ID is required']);
    exit;
}

try {
    // Fetch card details
    $stmt = $pdo->prepare("SELECT * FROM cards WHERE id = ? AND user_id = ? LIMIT 1");
    $stmt->execute([$_GET['id'], $_SESSION['user_id']]);
    $card = $stmt->fetch();

    if (!$card) {
        echo json_encode(['success' => false, 'message' => 'Card not found']);
        exit;
    }

    // Return card details
    echo json_encode([
        'success' => true,
        'card' => [
            'card_type' => $card['card_type'],
            'bank_name' => $card['bank_name'],
            'card_number' => $card['card_number'],
            'card_holder' => $card['card_holder'],
            'expiry_date' => $card['expiry_date'],
            'cvv' => $card['cvv']
        ]
    ]);

} catch (Exception $e) {
    echo json_encode(['success' => false, 'message' => 'Error fetching card details']);
}
?> 