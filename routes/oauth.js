var express = require('express');
var router = express.Router();
const { JWT } = require('jose');
const crypto = require('crypto');
const ClientOauth2 = require('client-oauth2');

const clientOauth = new ClientOauth2({
  clientId: process.env.CLIENT_ID,
  clientSecret: process.env.SECRET,
  accessTokenUri: process.env.ACCESS_TOKEN_URI,
  authorizationUri: process.env.AUTHORIZATION_URI,
  redirectUri: process.env.REDIRECT_URI,
  scopes: process.env.SCOPES
});

/* GET home page. */
router.get('/eko', async function(req, res, next) {
  try {
    if (!req.session.user) {
      // Generate random state
      const state = crypto.randomBytes(16).toString('hex');
      
      // Store state into session
      // const stateMap = req.session.stateMap || {};      
      // stateMap[state] = req.query.redirectTo;
      // req.session.stateMap = stateMap;
      req.session.state = state;
      req.session.redirectTo = req.query.redirectTo;

      const uri = clientOauth.code.getUri({ state });
      res.redirect(uri);
    } else {
      res.redirect(res.query.redirectTo);
    }
  } catch (error) {
    console.error(error);
    res.end(error.message);
  }
});

router.get('/eko/callback', async function(req, res, next) {
  try {
    // Make sure it is the callback from what we have initiated
    const state = req.session.state;
    const redirectTo = req.session.redirectTo;

    const { client, data } = await clientOauth.code.getToken(req.originalUrl, { state });
    const user = JWT.decode(data.id_token);
    req.session.user = user;

    // Get redirectTo from state
    // const stateMap = req.session.stateMap || {};
    // const redirectTo = stateMap[state] || 'https://sso.pud.local/error';
    // delete stateMap[state];
    // req.session.stateMap = stateMap;

    res.redirect(redirectTo);
  } catch (error) {
    console.error(error);
    res.end(error.message);
  }
});

router.get('/test', async (req, res, next) => {
  if (req.session.user) {
    res.end(`Hello ${req.session.user.firstname || req.session.user.name}`);
  } else {
    const redirectTo = `${req.protocol}://${req.get('host')}${req.originalUrl}`;
    res.redirect(`http://sso.pud.local:3001/connect/eko?redirectTo=${redirectTo}`);
  }
});

module.exports = router;
