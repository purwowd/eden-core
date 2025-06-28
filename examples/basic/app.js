// Eden Protected Node.js Express-style Application
// Example JavaScript application for testing Eden protection

const fs = require('fs');
const path = require('path');

class EdenExpressApp {
    constructor(name = "Eden Test Node App") {
        this.name = name;
        this.routes = {};
        this.middleware = [];
    }
    
    use(middleware) {
        this.middleware.push(middleware);
    }
    
    get(path, handler) {
        this.addRoute('GET', path, handler);
    }
    
    post(path, handler) {
        this.addRoute('POST', path, handler);
    }
    
    addRoute(method, path, handler) {
        if (!this.routes[method]) {
            this.routes[method] = {};
        }
        this.routes[method][path] = handler;
    }
    
    async handleRequest(method, path, data = {}) {
        console.log(`🌍 ${this.name} - Processing ${method} request: ${path}`);
        
        // Apply middleware
        for (const mw of this.middleware) {
            data = await mw(data);
        }
        
        if (this.routes[method] && this.routes[method][path]) {
            return await this.routes[method][path](data);
        } else {
            return { error: "Not Found", status: 404 };
        }
    }
}

// Middleware functions
const loggingMiddleware = async (data) => {
    console.log(`📝 [${new Date().toISOString()}] Request data:`, JSON.stringify(data));
    return data;
};

const authMiddleware = async (data) => {
    if (data.headers && data.headers.authorization === 'Bearer eden_token') {
        data.authenticated = true;
    } else {
        data.authenticated = false;
    }
    return data;
};

// Create app instance
const app = new EdenExpressApp("Eden Protected Express-style App");

// Add middleware
app.use(loggingMiddleware);
app.use(authMiddleware);

// Define routes
app.get('/', async (data) => {
    return {
        message: "Welcome to Eden Protected Node.js Application!",
        status: 200,
        protected: true,
        algorithm: "F = K · G (secp256k1)",
        framework: "Express-style",
        timestamp: new Date().toISOString(),
        nodeVersion: process.version,
        authenticated: data.authenticated || false
    };
});

app.get('/api/posts', async (data) => {
    const posts = [
        { id: 1, title: "Eden Protection Guide", author: "Admin", likes: 42 },
        { id: 2, title: "Universal Code Security", author: "Security Team", likes: 38 },
        { id: 3, title: "Performance Optimization", author: "Dev Team", likes: 25 }
    ];
    
    return {
        posts: posts,
        count: posts.length,
        status: 200,
        authenticated: data.authenticated || false
    };
});

app.post('/api/comments', async (data) => {
    if (!data.authenticated) {
        return { error: "Unauthorized", status: 401 };
    }
    
    return {
        message: "Comment created successfully!",
        commentId: Math.floor(Math.random() * 10000),
        status: 201,
        protectedBy: "Eden Universal Protection",
        commentData: data
    };
});

async function main() {
    console.log("🚀 Starting Eden Protected Node.js Application...");
    console.log("=".repeat(50));
    
    // Simulate requests
    const requests = [
        ['GET', '/', { userId: 123 }],
        ['GET', '/api/posts', { headers: { authorization: 'Bearer eden_token' } }],
        ['POST', '/api/comments', { 
            headers: { authorization: 'Bearer eden_token' }, 
            body: { postId: 1, content: "Great article!" }
        }],
        ['GET', '/nonexistent', { userId: 456 }]
    ];
    
    for (const [method, path, data] of requests) {
        try {
            const result = await app.handleRequest(method, path, data);
            console.log("📤 Response:", JSON.stringify(result, null, 2));
            console.log("-".repeat(30));
        } catch (error) {
            console.error("❌ Error:", error.message);
        }
    }
    
    console.log("✅ Node.js Application completed successfully!");
    console.log("🔒 This code was protected by Eden Universal Protection System");
}

// Run the application
if (require.main === module) {
    main().catch(console.error);
} 
