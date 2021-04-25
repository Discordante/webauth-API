const utils     = require('../utils');
const base64url = require('base64url');
const database  = require('../config/db');


//REGISTER
module.exports.register = (req, res, next) => {
    if(!req.body || !req.body.username || !req.body.name) {
        res.json({
            'status': 'failed',
            'message': 'req missing name or username field!'
        })
    }

    let username = req.body.username;
    let name     = req.body.name;

    if(database[username] && database[username].registered) {
        res.json({
            'status': 'failed',
            'message': `Username ${username} already exists`
        })
    }

    database[username] = {
        'name': name,
        'registered': false,
        'id': utils.randomBase64URLBuffer(),
        'authenticators': []
    }

    let challengeMakeCred = utils.generateServerMakeCredreq(username, name, database[username].id)
    challengeMakeCred.status = 'ok'

    req.session.challenge = challengeMakeCred.challenge;
    req.session.username  = username;

    res.json(challengeMakeCred)
    
}

//LOGIN
module.exports.login = (req, res, next) => {
    if(!req.body || !req.body.username) {
        res.json({
            'status': 'failed',
            'message': 'req missing username field!'
        })
    }

    let username = req.body.username;

    if(!database[username] || !database[username].registered) {
        res.json({
            'status': 'failed',
            'message': `User ${username} does not exist!`
        })
    }

    let getAssertion    = utils.generateServerGetAssertion(database[username].authenticators)
    getAssertion.status = 'ok'

    req.session.challenge = getAssertion.challenge;
    req.session.username  = username;

    res.json(getAssertion)
}


//RESPONSE
module.exports.response = (req, res, next) => {
    if(!req.body       || !req.body.id
    || !req.body.rawId || !req.body.res
    || !req.body.type  || req.body.type !== 'public-key' ) {
        res.json({
            'status': 'failed',
            'message': 'Response missing one or more of id/rawId/response/type fields, or type is not public-key!'
        })

        return
    }

    let webauthnResp = req.body
    let clientData   = JSON.parse(base64url.decode(webauthnResp.res.clientDataJSON));

    /* Check challenge... */
    if(clientData.challenge !== req.session.challenge) {
        res.json({
            'status': 'failed',
            'message': 'Challenges don\'t match!'
        })
    }

    /* ...and origin */
    if(clientData.origin !== process.env.URL || "http://localhost:3000") {
        res.json({
            'status': 'failed',
            'message': 'Origins don\'t match!'
        })
    }

    let result;
    if(webauthnResp.res.attestationObject !== undefined) {
        /* This is create cred */
        result = utils.verifyAuthenticatorAttestationResponse(webauthnResp);

        if(result.verified) {
            database[req.session.username].authenticators.push(result.authrInfo);
            database[req.session.username].registered = true
        }
    } else if(webauthnResp.res.authenticatorData !== undefined) {
        /* This is get assertion */
        result = utils.verifyAuthenticatorAssertionResponse(webauthnResp, database[req.session.username].authenticators);
    } else {
        res.json({
            'status': 'failed',
            'message': 'Can not determine type of response!'
        })
    }

    if(result.verified) {
        req.session.loggedIn = true;
        res.json({ 'status': 'ok' })
    } else {
        res.json({
            'status': 'failed',
            'message': 'Can not authenticate signature!'
        })
    }

}


