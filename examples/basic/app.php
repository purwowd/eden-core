<?php
/**
 * Example PHP Laravel-style application for testing Eden protection
 * This demonstrates a simple Laravel-like structure
 */

class EdenApp {
    private $routes = [];
    private $middleware = [];
    private $name;
    
    public function __construct($name = "Eden Test PHP App") {
        $this->name = $name;
    }
    
    public function addRoute($method, $path, $callback) {
        $this->routes[$method][$path] = $callback;
    }
    
    public function addMiddleware($middleware) {
        $this->middleware[] = $middleware;
    }
    
    public function handleRequest($method, $path, $data = null) {
        echo "[REQUEST] {$this->name} - Processing {$method} request: {$path}\n";
        
        // Apply middleware
        foreach ($this->middleware as $mw) {
            $data = call_user_func($mw, $data);
        }
        
        if (isset($this->routes[$method][$path])) {
            return call_user_func($this->routes[$method][$path], $data);
        } else {
            return ["error" => "Not Found", "status" => 404];
        }
    }
}

// Logging middleware
function loggingMiddleware($data) {
    echo "[LOG] [" . date('Y-m-d H:i:s') . "] Request data: " . json_encode($data) . "\n";
    return $data;
}

// Authentication middleware
function authMiddleware($data) {
    if (isset($data['token']) && $data['token'] === 'eden_protected') {
        $data['authenticated'] = true;
    } else {
        $data['authenticated'] = false;
    }
    return $data;
}

// Create app instance
$app = new EdenApp("Eden Protected Laravel-style App");

// Add middleware
$app->addMiddleware('loggingMiddleware');
$app->addMiddleware('authMiddleware');

// Define routes
$app->addRoute('GET', '/', function($data) {
    return [
        "message" => "Welcome to Eden Protected PHP Application!",
        "status" => 200,
        "protected" => true,
        "algorithm" => "F = K · G (secp256k1)",
        "framework" => "Laravel-style",
        "timestamp" => date('c'),
        "authenticated" => $data['authenticated'] ?? false
    ];
});

$app->addRoute('GET', '/api/products', function($data) {
    $products = [
        ["id" => 1, "name" => "Laptop", "price" => 999.99],
        ["id" => 2, "name" => "Mouse", "price" => 29.99],
        ["id" => 3, "name" => "Keyboard", "price" => 79.99]
    ];
    
    return [
        "products" => $products,
        "count" => count($products),
        "status" => 200,
        "authenticated" => $data['authenticated'] ?? false
    ];
});

$app->addRoute('POST', '/api/orders', function($data) {
    if (!($data['authenticated'] ?? false)) {
        return ["error" => "Unauthorized", "status" => 401];
    }
    
    return [
        "message" => "Order created successfully!",
        "order_id" => rand(1000, 9999),
        "status" => 201,
        "protected_by" => "Eden Universal Protection",
        "customer_data" => $data
    ];
});

function main() {
    global $app;
    
    echo "[LAUNCH] Starting Eden Protected PHP Application...\n";
    echo str_repeat("=", 50) . "\n";
    
    // Simulate requests
    $requests = [
        ['GET', '/', ['user_id' => 123]],
        ['GET', '/api/products', ['token' => 'eden_protected']],
        ['POST', '/api/orders', ['token' => 'eden_protected', 'product_id' => 1, 'quantity' => 2]],
        ['GET', '/nonexistent', ['user_id' => 456]]
    ];
    
    foreach ($requests as $req) {
        $result = $app->handleRequest($req[0], $req[1], $req[2]);
        echo "[RESPONSE] Response: " . json_encode($result, JSON_PRETTY_PRINT) . "\n";
        echo str_repeat("-", 30) . "\n";
    }
    
    echo "[SUCCESS] PHP Application completed successfully!\n";
    echo "[SECURE] This code was protected by Eden Universal Protection System\n";
}

// Run the application
main();
?> 
