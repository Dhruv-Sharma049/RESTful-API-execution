# Node.js Best Practices Guide

## Table of Contents
1. [Project Structure](#project-structure)
2. [Error Handling](#error-handling)
3. [Asynchronous Patterns](#asynchronous-patterns)
4. [Security Best Practices](#security-best-practices)
5. [Performance Optimization](#performance-optimization)
6. [Testing](#testing)
7. [Logging](#logging)
8. [Environment Configuration](#environment-configuration)
9. [Code Style and Linting](#code-style-and-linting)
10. [Dependency Management](#dependency-management)

## Project Structure

### Use a Layered Architecture

Organize your code into logical layers with clear responsibilities:

```javascript
// Example folder structure
/project-root
  /src
    /api           // API routes and controllers
    /services      // Business logic
    /models        // Data models
    /middleware    // Express middleware
    /utils         // Helper functions
    /config        // Configuration files
  /tests           // Test files
  /public          // Static assets
  server.js        // Entry point
  package.json
  .env.example
```

### Separate Business Logic from API Routes

```javascript
// routes/users.js - Keep routes simple, delegate to controllers
const express = require('express');
const userController = require('../controllers/userController');
const router = express.Router();

router.get('/', userController.getAllUsers);
router.post('/', userController.createUser);
router.get('/:id', userController.getUserById);

module.exports = router;

// controllers/userController.js - Controllers call services
const userService = require('../services/userService');

exports.getAllUsers = async (req, res, next) => {
  try {
    const users = await userService.getAllUsers();
    res.json(users);
  } catch (err) {
    next(err);
  }
};

// services/userService.js - Business logic lives here
const User = require('../models/user');

exports.getAllUsers = async () => {
  return await User.find({});
};
```

## Error Handling

### Use Async/Await with Try/Catch

```javascript
// Bad - Promise chain without proper error handling
app.get('/users', (req, res) => {
  getUsers()
    .then(users => {
      res.json(users);
    })
    // Missing error handling
});

// Good - Using async/await with try/catch
app.get('/users', async (req, res, next) => {
  try {
    const users = await getUsers();
    res.json(users);
  } catch (err) {
    next(err); // Pass to Express error handler
  }
});
```

### Centralized Error Handling

```javascript
// middleware/errorHandler.js
module.exports = (err, req, res, next) => {
  // Log error
  console.error(err);

  // Determine status code
  const statusCode = err.statusCode || 500;
  
  // Send error response
  res.status(statusCode).json({
    status: 'error',
    message: err.message || 'Internal Server Error',
    ...(process.env.NODE_ENV === 'development' && { stack: err.stack })
  });
};

// server.js - Add at the end of your middleware chain
const errorHandler = require('./middleware/errorHandler');
app.use(errorHandler);
```

### Custom Error Classes

```javascript
// utils/errors.js
class AppError extends Error {
  constructor(message, statusCode) {
    super(message);
    this.statusCode = statusCode;
    this.status = `${statusCode}`.startsWith('4') ? 'fail' : 'error';
    this.isOperational = true;
    
    Error.captureStackTrace(this, this.constructor);
  }
}

class NotFoundError extends AppError {
  constructor(message = 'Resource not found') {
    super(message, 404);
  }
}

class ValidationError extends AppError {
  constructor(message = 'Validation failed') {
    super(message, 400);
  }
}

module.exports = {
  AppError,
  NotFoundError,
  ValidationError
};

// Usage in service
const { NotFoundError } = require('../utils/errors');

exports.getUserById = async (id) => {
  const user = await User.findById(id);
  if (!user) {
    throw new NotFoundError(`User with id ${id} not found`);
  }
  return user;
};
```

## Asynchronous Patterns

### Prefer Async/Await Over Callbacks

```javascript
// Bad - Callback hell
function getUser(userId, callback) {
  db.query('SELECT * FROM users WHERE id = ?', [userId], (err, user) => {
    if (err) return callback(err);
    db.query('SELECT * FROM posts WHERE user_id = ?', [user.id], (err, posts) => {
      if (err) return callback(err);
      callback(null, { user, posts });
    });
  });
}

// Good - Using async/await
async function getUser(userId) {
  const user = await db.query('SELECT * FROM users WHERE id = ?', [userId]);
  const posts = await db.query('SELECT * FROM posts WHERE user_id = ?', [user.id]);
  return { user, posts };
}
```

### Use Promise.all for Parallel Operations

```javascript
// Sequential - Slower
async function getDataSequential(userId) {
  const user = await userService.getUser(userId);
  const posts = await postService.getUserPosts(userId);
  const comments = await commentService.getUserComments(userId);
  
  return { user, posts, comments };
}

// Parallel - Faster for independent operations
async function getDataParallel(userId) {
  const [user, posts, comments] = await Promise.all([
    userService.getUser(userId),
    postService.getUserPosts(userId),
    commentService.getUserComments(userId)
  ]);
  
  return { user, posts, comments };
}
```

### Handle Stream Backpressure

```javascript
const fs = require('fs');

// Create readable and writable streams
const readStream = fs.createReadStream('input.txt');
const writeStream = fs.createWriteStream('output.txt');

// Handle backpressure correctly
readStream.on('data', (chunk) => {
  // If writeStream can't keep up, pause reading
  const canContinue = writeStream.write(chunk);
  if (!canContinue) {
    readStream.pause();
  }
});

// Resume reading when writable stream is ready for more data
writeStream.on('drain', () => {
  readStream.resume();
});

readStream.on('end', () => {
  writeStream.end();
});

// Alternative: Use pipe which handles backpressure automatically
// readStream.pipe(writeStream);
```

## Security Best Practices

### Input Validation

```javascript
// Using express-validator middleware
const { body, validationResult } = require('express-validator');

app.post('/users',
  // Validate input
  [
    body('email').isEmail().normalizeEmail(),
    body('password').isLength({ min: 8 }).withMessage('Password must be at least 8 characters'),
    body('name').trim().escape()
  ],
  // Handle validation errors
  (req, res, next) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(400).json({ errors: errors.array() });
    }
    next();
  },
  // Process request if validation passed
  userController.createUser
);
```

### Use Environment Variables for Sensitive Data

```javascript
// Bad
const dbConnection = mysql.createConnection({
  host: 'localhost',
  user: 'root',
  password: 'password123',
  database: 'myapp'
});

// Good - Using dotenv
require('dotenv').config();

const dbConnection = mysql.createConnection({
  host: process.env.DB_HOST,
  user: process.env.DB_USER,
  password: process.env.DB_PASSWORD,
  database: process.env.DB_NAME
});
```

### Set Security HTTP Headers

```javascript
// Using Helmet middleware to set security headers
const helmet = require('helmet');
app.use(helmet());

// Or set headers manually
app.use((req, res, next) => {
  res.setHeader('X-XSS-Protection', '1; mode=block');
  res.setHeader('X-Content-Type-Options', 'nosniff');
  res.setHeader('X-Frame-Options', 'DENY');
  res.setHeader('Content-Security-Policy', "default-src 'self'");
  next();
});
```

### Prevent SQL Injection

```javascript
// Bad - String concatenation
const query = `SELECT * FROM users WHERE email = '${email}'`; // DON'T DO THIS

// Good - Parameterized queries
// With MySQL
connection.query('SELECT * FROM users WHERE email = ?', [email], (err, results) => {
  // Handle results
});

// With MongoDB
User.find({ email: email }); // Mongo sanitizes this input

// With Sequelize ORM
const user = await User.findOne({ where: { email } });
```

### CSRF Protection

```javascript
const csrf = require('csurf');
const cookieParser = require('cookie-parser');

// Setup CSRF protection
app.use(cookieParser());
app.use(csrf({ cookie: true }));

// Add CSRF token to all responses
app.use((req, res, next) => {
  res.locals.csrfToken = req.csrfToken();
  next();
});

// In your forms
// <form method="POST" action="/submit">
//   <input type="hidden" name="_csrf" value="<%= csrfToken %>">
//   <!-- other form fields -->
// </form>
```

## Performance Optimization

### Use Compression

```javascript
const compression = require('compression');

// Enable compression
app.use(compression());
```

### Caching Responses

```javascript
const mcache = require('memory-cache');

// Simple cache middleware
const cache = (duration) => {
  return (req, res, next) => {
    const key = `__express__${req.originalUrl || req.url}`;
    const cachedBody = mcache.get(key);
    
    if (cachedBody) {
      res.send(cachedBody);
      return;
    }
    
    // Capture the response
    const originalSend = res.send;
    res.send = (body) => {
      mcache.put(key, body, duration * 1000);
      originalSend.call(res, body);
    };
    
    next();
  };
};

// Use the cache middleware (cache for 10 minutes)
app.get('/api/popular-articles', cache(600), (req, res) => {
  // Fetch articles (this will only run when cache is empty)
  res.send(articles);
});
```

### Database Query Optimization

```javascript
// Bad - Fetching unnecessary fields
const users = await User.find({});

// Good - Select only needed fields
const users = await User.find({}).select('name email');

// Create indexes for frequently queried fields
// In Mongoose schema
const UserSchema = new mongoose.Schema({
  email: { type: String, required: true, index: true },
  name: String,
  createdAt: Date
});

// Or create index manually in MongoDB
db.users.createIndex({ email: 1 });
```

### Use Clustering to Utilize Multiple Cores

```javascript
// server.js
const cluster = require('cluster');
const os = require('os');

if (cluster.isMaster) {
  // Get number of CPUs
  const numCPUs = os.cpus().length;
  
  // Fork workers for each CPU
  for (let i = 0; i < numCPUs; i++) {
    cluster.fork();
  }
  
  // Handle worker crashes
  cluster.on('exit', (worker, code, signal) => {
    console.log(`Worker ${worker.process.pid} died`);
    // Restart the worker
    cluster.fork();
  });
} else {
  // Worker process - run the actual server
  const express = require('express');
  const app = express();
  
  // ... your app setup
  
  app.listen(3000, () => {
    console.log(`Worker ${process.pid} started`);
  });
}
```

## Testing

### Unit Testing with Jest

```javascript
// utils/calculator.js
function add(a, b) {
  return a + b;
}

module.exports = { add };

// tests/calculator.test.js
const { add } = require('../utils/calculator');

describe('Calculator', () => {
  test('should add two numbers correctly', () => {
    expect(add(2, 3)).toBe(5);
    expect(add(-1, 1)).toBe(0);
    expect(add(0, 0)).toBe(0);
  });
});
```

### API Testing with Supertest

```javascript
// tests/api.test.js
const request = require('supertest');
const app = require('../app');
const mongoose = require('mongoose');

describe('User API', () => {
  beforeAll(async () => {
    // Connect to test database
    await mongoose.connect(process.env.TEST_DB_URI);
  });

  afterAll(async () => {
    // Disconnect after tests
    await mongoose.connection.close();
  });

  it('should create a new user', async () => {
    const res = await request(app)
      .post('/api/users')
      .send({
        name: 'Test User',
        email: 'test@example.com',
        password: 'password123'
      });
    
    expect(res.statusCode).toEqual(201);
    expect(res.body).toHaveProperty('id');
    expect(res.body.name).toEqual('Test User');
  });
});
```

### Test Coverage with Istanbul/nyc

```json
// package.json
{
  "scripts": {
    "test": "jest",
    "test:coverage": "jest --coverage"
  }
}
```

## Logging

### Use a Structured Logger

```javascript
// Using Winston for structured logging
const winston = require('winston');

// Create a logger
const logger = winston.createLogger({
  level: process.env.NODE_ENV === 'production' ? 'info' : 'debug',
  format: winston.format.combine(
    winston.format.timestamp(),
    winston.format.json()
  ),
  transports: [
    // Console logs
    new winston.transports.Console(),
    // File logs
    new winston.transports.File({ filename: 'error.log', level: 'error' }),
    new winston.transports.File({ filename: 'combined.log' })
  ]
});

// Usage
logger.info('Server started', { port: 3000 });
logger.error('Database connection failed', { error: err.message });

// Middleware to log requests
app.use((req, res, next) => {
  const start = Date.now();
  
  res.on('finish', () => {
    const duration = Date.now() - start;
    logger.info('Request processed', {
      method: req.method,
      url: req.originalUrl,
      statusCode: res.statusCode,
      duration: `${duration}ms`
    });
  });
  
  next();
});
```

### Log Rotation

```javascript
const winston = require('winston');
require('winston-daily-rotate-file');

// Create a file rotator transport
const fileRotateTransport = new winston.transports.DailyRotateFile({
  filename: 'logs/application-%DATE%.log',
  datePattern: 'YYYY-MM-DD',
  maxSize: '20m',
  maxFiles: '14d'
});

const logger = winston.createLogger({
  level: 'info',
  format: winston.format.combine(
    winston.format.timestamp(),
    winston.format.json()
  ),
  transports: [
    new winston.transports.Console(),
    fileRotateTransport
  ]
});
```

## Environment Configuration

### Managing Environment Variables

```javascript
// config/config.js
const dotenv = require('dotenv');
const path = require('path');

// Load appropriate .env file based on NODE_ENV
dotenv.config({
  path: path.resolve(__dirname, `../.env.${process.env.NODE_ENV || 'development'}`)
});

// Export configuration
module.exports = {
  env: process.env.NODE_ENV || 'development',
  port: parseInt(process.env.PORT || '3000', 10),
  db: {
    uri: process.env.DATABASE_URI,
    options: {
      useNewUrlParser: true,
      useUnifiedTopology: true
    }
  },
  jwt: {
    secret: process.env.JWT_SECRET,
    expiresIn: process.env.JWT_EXPIRES_IN || '1d'
  },
  // Add more configuration as needed
};
```

### Environment-specific Configurations

```
# .env.development
PORT=3000
DATABASE_URI=mongodb://localhost:27017/myapp_dev
LOG_LEVEL=debug

# .env.test
PORT=3001
DATABASE_URI=mongodb://localhost:27017/myapp_test
LOG_LEVEL=error

# .env.production
PORT=80
DATABASE_URI=mongodb://user:password@db.example.com:27017/myapp
LOG_LEVEL=info
```

## Code Style and Linting

### ESLint Configuration

```javascript
// .eslintrc.js
module.exports = {
  env: {
    node: true,
    es2021: true,
    jest: true
  },
  extends: ['eslint:recommended', 'plugin:node/recommended'],
  parserOptions: {
    ecmaVersion: 12
  },
  rules: {
    'no-console': process.env.NODE_ENV === 'production' ? 'warn' : 'off',
    'no-unused-vars': ['error', { argsIgnorePattern: '^_' }],
    'node/exports-style': ['error', 'module.exports'],
    'node/file-extension-in-import': ['error', 'always'],
    'node/prefer-global/buffer': ['error', 'always'],
    'node/prefer-global/console': ['error', 'always'],
    'node/prefer-global/process': ['error', 'always'],
    'node/no-unpublished-require': 'off'
  }
};
```

### Prettier Configuration

```javascript
// .prettierrc
{
  "singleQuote": true,
  "trailingComma": "es5",
  "printWidth": 100,
  "tabWidth": 2,
  "semi": true
}

// Add to package.json
{
  "scripts": {
    "format": "prettier --write 'src/**/*.js'",
    "lint": "eslint --fix 'src/**/*.js'"
  }
}
```

## Dependency Management

### Keep Dependencies Updated Safely

```json
// package.json
{
  "scripts": {
    "deps:check": "npm-check",
    "deps:update": "npm-check -u"
  }
}
```

### Lock Dependencies

Always commit your `package-lock.json` or `yarn.lock` file to version control to ensure consistent installations across environments.

### Security Auditing

```json
// package.json
{
  "scripts": {
    "security:audit": "npm audit",
    "security:fix": "npm audit fix"
  }
}
```

### Minimize Dependencies

Before adding a new package, consider:
1. Do you really need it?
2. Could you implement the functionality yourself with minimal code?
3. Is the package well-maintained and secure?
4. What is the package's dependency tree size?

```javascript
// Instead of using a package for simple tasks, implement them yourself
// Example: Simple deep clone without using lodash
function deepClone(obj) {
  if (obj === null || typeof obj !== 'object') {
    return obj;
  }
  
  if (Array.isArray(obj)) {
    return obj.map(item => deepClone(item));
  }
  
  const cloned = {};
  for (const key in obj) {
    if (Object.prototype.hasOwnProperty.call(obj, key)) {
      cloned[key] = deepClone(obj[key]);
    }
  }
  
  return cloned;
}
```
