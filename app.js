require('dotenv').config();

const express       = require('express');
const cookieSession = require('cookie-session');
const cookieParser  = require('cookie-parser');
const urllib        = require('url');
const path          = require('path');
const crypto        = require('crypto');
const x509          = require('@fidm/x509');
const iso_3166_1    = require('iso-3166-1');

const defaultroutes = require('./config/routes.config');
const webuathnauth  = require('./config/routes.config');

const app = express();

/* Middlewares */

app.use(express.json());

/* ----- Routes ----- */

const routes = require('./config/routes.config')
app.use('/api', routes)

/* ----- session ----- */
app.use(cookieSession({
  name: 'session',
  keys: [crypto.randomBytes(32).toString('hex')],

  // Cookie Options
  maxAge: 24 * 60 * 60 * 1000 // 24 hours
}))

app.use(cookieParser())

/* ----- serve static ----- */
app.use(express.static(path.join(__dirname, 'static')));

app.use('/', defaultroutes)
app.use('/webauthn', webuathnauth)


const port = process.env.PORT || 3000

app.listen(port, () => {
    console.log(`Ready! Listen on port ${port}`);
})

module.exports = app;