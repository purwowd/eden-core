#!/usr/bin/env python3
"""
Example Python application for testing Eden protection
This is a simple Django-style application
"""

import json
from datetime import datetime


class SimpleApp:
    def __init__(self, name="Eden Test App"):
        self.name = name
        self.routes = {}
        self.middleware = []

    def route(self, path):
        def decorator(func):
            self.routes[path] = func
            return func
        return decorator

    def add_middleware(self, middleware):
        self.middleware.append(middleware)

    def handle_request(self, path, data=None):
        print(f"[REQUEST] {self.name} - Processing request: {path}")

        # Apply middleware
        for mw in self.middleware:
            data = mw(data)

        if path in self.routes:
            return self.routes[path](data)
        else:
            return {"error": "Not Found", "status": 404}


# Create app instance
app = SimpleApp("Eden Protected Django-style App")


# Add logging middleware
def logging_middleware(data):
    print(f"[LOG] [{datetime.now()}] Request data: {data}")
    return data


app.add_middleware(logging_middleware)


# Define routes
@app.route("/")
def home(data):
    return {
        "message": "Welcome to Eden Protected Application!",
        "status": 200,
        "protected": True,
        "algorithm": "F = K · G (secp256k1)",
        "timestamp": datetime.now().isoformat()
    }


@app.route("/api/users")
def get_users(data):
    users = [
        {"id": 1, "name": "Alice", "role": "admin"},
        {"id": 2, "name": "Bob", "role": "user"},
        {"id": 3, "name": "Charlie", "role": "moderator"}
    ]
    return {"users": users, "count": len(users), "status": 200}


@app.route("/api/protected")
def protected_endpoint(data):
    return {
        "message": "This is a protected endpoint!",
        "security": "Eden Universal Protection",
        "languages_supported": ["Python", "PHP", "JavaScript", "Go", "Java"],
        "performance": "Optimized for production",
        "status": 200
    }


def main():
    print("[LAUNCH] Starting Eden Protected Application...")
    print("=" * 50)

    # Simulate requests
    routes_to_test = ["/", "/api/users", "/api/protected", "/nonexistent"]

    for route in routes_to_test:
        result = app.handle_request(
            route, {"user_id": 123, "session": "abc123"}
        )
        print("[RESPONSE] Response:")
        print(json.dumps(result, indent=2))
        print("-" * 30)

    print("[SUCCESS] Application completed successfully!")
    msg = "[SECURE] This code was protected by Eden Universal Protection"
    print(msg)


if __name__ == "__main__":
    main()
