<?php
function heavyComputation() {
    $result = 0;
    for ($i = 0; $i < 100000; $i++) {
        $result += mt_rand() / mt_getrandmax() * $i;
    }
    return $result;
}

function main() {
    $start = microtime(true);
    
    // Business logic
    $data = [];
    for ($i = 0; $i < 1000; $i++) {
        $data[] = heavyComputation();
    }
    
    // Simulate database operations
    usleep(100000); // 0.1 second
    
    $end = microtime(true);
    $duration = $end - $start;
    
    echo "Computation completed in " . number_format($duration, 4) . " seconds\n";
    echo "Processed " . count($data) . " items\n";
    
    return $data;
}

main();
?>
