import time
import random

def heavy_computation():
    """Simulate heavy computation"""
    result = 0
    for i in range(100000):
        result += random.random() * i
    return result

def main():
    start = time.time()
    
    # Business logic
    data = []
    for i in range(1000):
        data.append(heavy_computation())
    
    # Simulate database operations
    time.sleep(0.1)
    
    end = time.time()
    print(f"Computation completed in {end - start:.4f} seconds")
    print(f"Processed {len(data)} items")
    return data

if __name__ == "__main__":
    main()
