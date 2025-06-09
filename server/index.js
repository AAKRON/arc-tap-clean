/**
 * Arc-TAP NFC Redirection Server
 * 
 * This is the entry point for the Arc-TAP redirect service which handles NFC tag redirects.
 * It integrates with Vercel for deployment and Neon PostgreSQL for database storage.
 */
require('dotenv').config(); // Load .env file for local development
const express = require('express');
const { Pool } = require('pg');
const morgan = require('morgan'); // HTTP request logger

const app = express();

// --- Configuration ---
const PORT = process.env.PORT || 3000;
const POSTGRES_URL = process.env.POSTGRES_URL; // Expected from Vercel or .env
const DEFAULT_FALLBACK_URL = process.env.DEFAULT_FALLBACK_URL || 'https://aakronline.com/not-found';

// --- Logger (Simple Console Logger) ---
// In a production app, consider a more robust logger like Winston.
const logger = {
  info: (message, ...args) => console.log(`[INFO] ${new Date().toISOString()} - ${message}`, args.length > 0 ? args : ""),
  error: (message, ...args) => console.error(`[ERROR] ${new Date().toISOString()} - ${message}`, args.length > 0 ? args : ""),
  warn: (message, ...args) => console.warn(`[WARN] ${new Date().toISOString()} - ${message}`, args.length > 0 ? args : ""),
  debug: (message, ...args) => {
    if (process.env.NODE_ENV !== 'production') { // Only log debug in non-production
      console.debug(`[DEBUG] ${new Date().toISOString()} - ${message}`, args.length > 0 ? args : "");
    }
  },
};

// --- Database Setup ---
if (!POSTGRES_URL) {
  logger.error('FATAL ERROR: POSTGRES_URL environment variable is not set. The redirect service cannot function.');
  // In a real scenario, you might want to prevent the app from starting or handle this more gracefully.
  // For Vercel, this variable is critical.
  process.exit(1); 
}

const pool = new Pool({
  connectionString: POSTGRES_URL + (POSTGRES_URL.includes('?') ? '&sslmode=require' : '?sslmode=require'),
  // Recommended settings for serverless environments (Vercel):
  // max: 1, // Limits the number of active clients in the pool
  // idleTimeoutMillis: 5000, // Closes idle clients after 5 seconds
  // connectionTimeoutMillis: 2000, // Returns an error after 2 seconds if connection cannot be established
});

pool.on('connect', (client) => {
  logger.info('A new client has connected to the PostgreSQL database via the pool.');
  // You can set client-level settings here if needed, e.g., client.query('SET search_path TO my_schema');
});

pool.on('error', (err, client) => {
  logger.error('Unexpected error on idle PostgreSQL client within the pool', err);
  // This is a critical error for the pool; consider how to handle it.
  // For Vercel, exiting might be necessary to allow a fresh lambda instance.
  // process.exit(-1); // Potentially too aggressive, but ensures broken pool doesn't persist.
});

// Test database connection on startup (optional, but good for diagnostics)
(async () => {
  let client;
  try {
    client = await pool.connect();
    const res = await client.query('SELECT NOW()');
    logger.info('Successfully connected to PostgreSQL database. Server time: ' + res.rows[0].now);
  } catch (err) {
    logger.error('Failed to connect to PostgreSQL database on startup:', err);
    // Depending on severity, you might want to exit: process.exit(1);
  } finally {
    if (client) {
      client.release(); // Release client back to the pool
    }
  }
})();


// --- Express Application Middleware ---
// HTTP request logging using Morgan. 'tiny' format is concise.
app.use(morgan('tiny', { stream: { write: message => logger.info(message.trim()) } }));

// Security headers (basic set, consider Helmet.js for more comprehensive headers)
app.use((req, res, next) => {
    res.setHeader('X-Content-Type-Options', 'nosniff');
    res.setHeader('X-Frame-Options', 'DENY');
    // res.setHeader('Content-Security-Policy', "default-src 'self'; script-src 'self'"); // Example CSP
    next();
});


// --- Database Service Logic (encapsulated for clarity) ---
const databaseService = {
  getRedirectUrlForBatchId: async (batchId) => {
    if (!batchId || typeof batchId !== 'string') {
      logger.warn('Invalid batchId type or empty batchId received in databaseService.');
      return null; // Or throw an error
    }
    // Query prefers static_url if available, otherwise destination_url
    const query = 'SELECT static_url, destination_url FROM redirects WHERE batch_id ILIKE $1';
    logger.debug(`Executing query: ${query} with batchId: "${batchId}"`);
    
    let client;
    try {
      client = await pool.connect();
      const result = await client.query(query, [batchId.trim()]);
      logger.debug(`Query result for batchId "${batchId}": ${JSON.stringify(result.rows)}`);
      
      if (result.rows.length > 0) {
        const row = result.rows[0];
        return row.static_url || row.destination_url; // Prefer static_url
      }
      return null; // No redirect found for this batchId
    } catch (dbError) {
      logger.error(`Database error fetching redirect for batchId "${batchId}":`, dbError);
      throw dbError; // Re-throw to be caught by the route's error handler
    } finally {
      if (client) {
        client.release();
      }
    }
  },
};


// --- API Routes ---

// Root / Health Check Route
app.get('/', (req, res) => {
  res.status(200).send('Arc-TAP Redirect Service is running and healthy.');
});

// Main Redirect Route: /:batchId
app.get('/:batchId', async (req, res, next) => {
  const { batchId } = req.params;

  // Basic validation for batchId format (alphanumeric, hyphens, underscores)
  if (!batchId || !/^[a-zA-Z0-9_-]+$/.test(batchId.trim())) {
    logger.warn(`Invalid batchId format received: "${batchId}". Redirecting to fallback.`);
    // It's often better to redirect to a known fallback than to show an error for a bad ID format.
    return res.redirect(301, DEFAULT_FALLBACK_URL); 
  }

  logger.info(`Processing redirect request for batchId: "${batchId.trim()}"`);

  try {
    const destinationUrl = await databaseService.getRedirectUrlForBatchId(batchId.trim());

    if (destinationUrl) {
      logger.info(`Redirecting batchId "${batchId.trim()}" to: ${destinationUrl}`);
      res.redirect(301, destinationUrl); // HTTP 301 for permanent redirect
    } else {
      logger.warn(`No redirect URL found for batchId: "${batchId.trim()}". Redirecting to fallback.`);
      res.status(404).redirect(301, DEFAULT_FALLBACK_URL); // Not found, redirect to fallback
    }
  } catch (error) {
    // Pass the error to the centralized error handling middleware
    next(error); 
  }
});


// --- Error Handling Middleware ---

// Catch-all for 404s (if no other routes matched) - this should be defined after all your routes.
app.use((req, res, next) => {
  logger.warn(`Route not found: ${req.method} ${req.originalUrl}. Redirecting to fallback URL.`);
  res.status(404).redirect(301, DEFAULT_FALLBACK_URL);
});

// Centralized error handler - this should be the last middleware.
// Express identifies it as an error handler by its four arguments (err, req, res, next).
app.use((err, req, res, next) => {
  logger.error('Unhandled error caught by centralized handler:', err.stack || err.message || err);
  
  // Avoid sending detailed error messages to the client in production for security.
  const isProduction = process.env.NODE_ENV === 'production';
  const clientErrorMessage = isProduction ? 
    'An unexpected error occurred. Please try again later.' : 
    (err.message || 'Internal Server Error');
  
  // If headers have already been sent to the client, delegate to the default Express error handler.
  if (res.headersSent) {
    return next(err);
  }
  
  // For API-like errors, you might send JSON, but for a redirect service,
  // redirecting to a fallback on error is often preferred.
  // res.status(err.status || 500).json({ error: clientErrorMessage });
  logger.info(`Error handler redirecting to fallback URL due to error: ${err.message}`);
  res.status(err.status || 500).redirect(301, DEFAULT_FALLBACK_URL);
});


// --- Server Start ---
// Only start listening if not in a test environment (e.g., Jest typically sets NODE_ENV=test)
// Vercel will manage starting the server for serverless functions.
let serverInstance;
if (process.env.NODE_ENV !== 'test') {
  serverInstance = app.listen(PORT, () => {
    logger.info(`Arc-TAP Redirect Server listening on port ${PORT}`);
  });
}


// --- Graceful Shutdown Logic ---
// Important for cleaning up resources like database connections.
const gracefulShutdown = async (signal) => {
  logger.info(`Received ${signal}. Shutting down gracefully...`);
  
  if (serverInstance) {
    serverInstance.close(async () => {
      logger.info('HTTP server closed.');
      await shutdownDatabasePool();
      process.exit(0);
    });
  } else { // If server wasn't started (e.g. test env or Vercel lambda)
    await shutdownDatabasePool();
    process.exit(0);
  }

  // Force shutdown if graceful shutdown takes too long
  setTimeout(async () => {
    logger.error('Could not close connections in time, forcefully shutting down.');
    await shutdownDatabasePool(true); // Attempt to close pool even on forceful exit
    process.exit(1);
  }, 10000); // 10 seconds timeout
};

const shutdownDatabasePool = async (force = false) => {
  if (pool) {
    try {
      logger.info('Attempting to close PostgreSQL connection pool...');
      await pool.end(); // Closes all clients in the pool
      logger.info('PostgreSQL connection pool has been closed.');
    } catch (err) {
      logger.error('Error during PostgreSQL pool shutdown:', err);
      if (force) process.exit(1); // Exit if forced and pool closing fails
    }
  }
};

// Listen for termination signals
process.on('SIGTERM', () => gracefulShutdown('SIGTERM')); // Standard signal for termination
process.on('SIGINT', () => gracefulShutdown('SIGINT'));   // Ctrl+C in terminal

// Export the app for Vercel's serverless environment
// Vercel expects the handler to be the default export or a named export.
module.exports = app;
