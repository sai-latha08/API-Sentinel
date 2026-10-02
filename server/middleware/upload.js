const multer = require('multer');

// Memory storage for immediate processing
const storage = multer.memoryStorage();

const upload = multer({
  storage,
  limits: {
    fileSize: (parseInt(process.env.MAX_UPLOAD_SIZE_MB) || 15) * 1024 * 1024 // 15 MB default limit
  },
  fileFilter: (req, file, cb) => {
    const ext = file.originalname.toLowerCase();
    if (
      ext.endsWith('.json') ||
      ext.endsWith('.yaml') ||
      ext.endsWith('.yml') ||
      file.mimetype === 'application/json' ||
      file.mimetype === 'text/yaml' ||
      file.mimetype === 'application/x-yaml' ||
      file.mimetype === 'text/plain'
    ) {
      cb(null, true);
    } else {
      cb(new Error('Unsupported file format. Please upload an OpenAPI, Swagger, or Postman JSON/YAML file.'));
    }
  }
});

module.exports = upload;
