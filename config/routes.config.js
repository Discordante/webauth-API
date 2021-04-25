const express = require('express');
const router = express.Router();
const defaultController = require('../controllers/default.controller')
const webauthnController = require('../controllers/webauthn.controller')


router.get('/isLoggedIn', defaultController.isLoggedIn)
router.get('/logout', defaultController.logout)
router.get('/personalInfo', defaultController.personalInfo)


router.post('/register', webauthnController.register)
router.post('/login', webauthnController.login)
router.post('/response', webauthnController.response)


module.exports = router;