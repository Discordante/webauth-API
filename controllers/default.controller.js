const database  = require('../config/db');

/* Returns if user is logged in */
module.exports.isLoggedIn = (req, res, next) => {
    if(!req.session.loggedIn) {
        res.json({
            'status': 'failed'
        })
    } else {
        res.json({
            'status': 'ok'
        })
    }
}

/* Logs user out */
module.exports.logout = (req, res, next) => {
    req.session.loggedIn = false;
    req.session.username = undefined;

    res.json({
        'status': 'ok'
    })
}

/* Returns personal info and THE SECRET INFORMATION */
module.exports.personalInfo = (req, res, next) => {
    if(!req.session.loggedIn) {
        res.json({
            'status': 'failed',
            'message': 'Access denied'
        })
    } else {
        res.json({
            'status': 'ok',
            'name': database[req.session.username].name,
        })
    }
}


