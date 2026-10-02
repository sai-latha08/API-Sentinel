function errorHandler(err, req, res, next) {
  console.error('[API Sentinel Server Error]:', err.message || err);

  const status = err.status || err.statusCode || 500;
  const message = err.message || 'An unexpected internal server error occurred.';

  res.status(status).json({
    success: false,
    error: message,
    timestamp: new Date().toISOString()
  });
}

module.exports = errorHandler;
