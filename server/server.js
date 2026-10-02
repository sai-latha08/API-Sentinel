require('dotenv').config();
const express = require('express');
const cors = require('cors');
const helmet = require('helmet');
const morgan = require('morgan');
const rateLimit = require('express-rate-limit');

const { connectDB } = require('./services/db');
const { checkEngineHealth } = require('./services/securityEngineClient');
const errorHandler = require('./middleware/errorHandler');

const authRoutes = require('./routes/auth');
const scanRoutes = require('./routes/scans');
const projectRoutes = require('./routes/projects');
const aiRoutes = require('./routes/ai');
const compareRoutes = require('./routes/compare');
const reportRoutes = require('./routes/reports');

const app = express();
const PORT = process.env.PORT || 5000;

// Security & Middlewares
app.use(helmet({
  crossOriginResourcePolicy: { policy: "cross-origin" }
}));

const allowedOrigins = [
  'http://localhost:5173',
  'http://127.0.0.1:5173',
  'http://localhost:3000',
  process.env.CLIENT_URL
].filter(Boolean);

app.use(cors({
  origin: (origin, callback) => {
    // Allow requests with no origin (like mobile apps, curl or same-origin)
    if (!origin || allowedOrigins.includes(origin) || process.env.NODE_ENV !== 'production') {
      return callback(null, true);
    }
    callback(null, true); // Permissive in local dev
  },
  credentials: true
}));

app.use(morgan('dev'));
app.use(express.json({ limit: '20mb' }));
app.use(express.urlencoded({ extended: true, limit: '20mb' }));

// Global Rate Limiter
const apiLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 300,
  standardHeaders: true,
  legacyHeaders: false,
  message: { error: 'Too many requests, please try again after 15 minutes.' }
});
app.use('/api/', apiLimiter);

// Health Endpoint
app.get('/health', async (req, res) => {
  const engineHealth = await checkEngineHealth();
  res.json({
    status: 'online',
    product: 'API Sentinel',
    version: '1.0.0',
    backend: 'Node.js Express',
    securityEngine: engineHealth,
    timestamp: new Date().toISOString()
  });
});

// API Routes
app.use('/api/auth', authRoutes);
app.use('/api/scans', scanRoutes);
app.use('/api/projects', projectRoutes);
app.use('/api/ai', aiRoutes);
app.use('/api/compare', compareRoutes);
app.use('/api/reports', reportRoutes);

// Error Handling
app.use(errorHandler);

// Start server
async function startServer() {
  await connectDB();
  app.listen(PORT, () => {
    console.log(`[API Sentinel] Backend Server running on http://localhost:${PORT}`);
  });
}

startServer();

module.exports = app;
