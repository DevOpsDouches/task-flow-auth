// auth-service/src/routes/authRoutes.js
const express = require('express');
const router = express.Router();
const authController = require('../controllers/authController');

// Auth endpoints
router.post('/register', authController.register);
router.post('/login', authController.login);
router.post('/verify', authController.verifyToken);
router.post('/logout', authController.logout);
router.get('/profile', authController.getProfile);

module.exports = router;
