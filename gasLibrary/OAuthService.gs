/*
 useful reading:
 https://developers.google.com/apps-script/guides/dialogs
 https://code.google.com/p/google-apps-script-issues/issues/detail?id=677
 https://code.google.com/p/google-apps-script-issues/issues/attachmentText?id=677&aid=6770029003&name=OAuth+-+Url+Shortening.rtf&token=ABZ6GAdZ8mF6yeiMCaFklm6jNLN1QgxUcw%3A1409448184529
 https://code.google.com/p/google-apps-script-issues/issues/attachmentText?id=677&aid=6770029000&name=OAuth+-+Authorization+stuff.rtf&token=ABZ6GAdjKlbFEE8TmA-DtRK35de--DN4RA%3A1409448184529
 http://oauthbible.com/
 http://developer.xero.com/documentation/getting-started/public-applications/
 https://dev.twitter.com/docs/auth/creating-signature
 https://dev.twitter.com/docs/auth/percent-encoding-parameters
 https://developer.yahoo.com/oauth/guide/oauth-signing.html
 https://developer.yahoo.com/oauth/guide/oauth-requesttoken.html
 http://underscorejs.org/#intersection
*/


var debug_ = true,
    scriptStart_ = Date.now(),
    PREFIX_ = 'ApiService-',
    defaults_,
    signatureParams_;

/**
 * getOAuthConfig uses the data types of the defaults properties to work out how to
 *   merge the data from different sources.
 *   that means that every key that will end up in the options object must be defined here, 
 *  and must be set to the correct type. This only applies to direct children of the options
 *  object.
 */
defaults_ = {
  serviceName: 'myService',   //how you will refer to this config when using fetch()
  enableDebug: false,         //whether library will log debug messages
  noHistory: false,           //sortof advanced
  reauthOnExpired: true,      //whether to show auth dialog when fetch detects expired token
  expiresAt: 0,               //advanced
  urls: {
    accessTokenUrl: false,    //get from api provider
    requestTokenUrl: false,
    authorizationUrl: false
  },
  oAuth: {                    //advanced
    oauth_callback: false,                
    oauth_consumer_key: false,
    oauth_consumer_secret: false,
    oauth_nonce: false,
    oauth_signature: false,
    oauth_signature_method: 'HMAC-SHA1',
    oauth_timestamp: false,
    oauth_token: false,
    oauth_token_secret: false,
    oauth_version: false,
    oauth_verifier: false
  },
  dialog: {
    displayName: 'groovy service',  //user readable serviceName
    appName: 'my awesome app',      //the name of your script
    showVerifierInput: true         //if your expecting the user to copypasta the verifier
  },
  reauthOn: {                 //advanced
    oauth_problem: [
      'token_expired'
    ]
  }
};
/**
 * creates the string for the Authorization header 
 *
 * @param {object} oAuthParams key/value list of oAuth parameters
 * @return {string}
 */
function createAuthHeader_(oAuthParams) {
  var header;
  
  header = _.map(oAuthParams, function(value, key) {
    return key + '="' + value + '"';
    //return key + '=' + value + ' ';
  });
  header = header.join(', ');
  header = 'OAuth ' + header;
  return header;
};

/**
 * returns random 32 char string
 *
 * @param {number} length (optional) length of string
 * @return {string}
 */
function createNonce_(length) {
  dump_('createNonce()');
  
  var chars,
      result,
      random;
  
  if (!length) {
    length = 32;
  }
  
  chars = '0123456789ABCDEFGHIJKLMNOPQRSTUVWXTZabcdefghiklmnopqrstuvwxyz';
  
  result = _.times(length, function(index) {
    random = _.random(0, chars.length);
    return chars.substring(random, random + 1);
  });
  
  return result.join('');
};

/**
 * creates timestamp
 */
function createTimestamp_() {
  var stamp;
  
  stamp = Date.now();
  stamp /= 1000;
  stamp = stamp.toFixed();
  
  return stamp;
};

/**
 * callback for dialog, calls leg three
 *
 * @param {string|number} verifier verifier code provided by service provider
 * @param {string} serviceName descriptor for oAuthConfig
 */
dialogOk = function(verifier, serviceName) {
  dump_('dialogOk');
  
  var oAuthConfig,
      response;
  
  oAuthConfig = getOAuthConfig(serviceName);
  
  response = oAuthConfig.authLegThree(verifier);
  
  return response;
  
};

/**
 * writes pretty logs
 *
 * @param {string} description Brief description of what's printed
 * @param {} output value to be dumped
 * @return null
 */
function dump_(description, output) {
  if (!debug_) {
    return;
  }
  
  if (_.isObject(description)) {
    output = description;
  }
  
  var log = '',
      ms;
  
  ms = Date.now() - scriptStart_;
  
  log += '[' + ('0000' + ms).split(-6) + 'ms ] ';
  log += description;
  
  if (output) {
    log += ":\n";
    log += JSON.stringify(output, undefined, 2);
  }
  
  Logger.log(log);
};

/**
 * enables debug messages
 */
function enableDebug() {
  debug_ = true;
};

/**
 * wrapper for UrlFetchApp.fetch() which injects oauth header
 *
 * @param {string} url target url
 * @param {object} options key value map of options suitable for
 *   UrlFetchApp.fetch() - include oAuthConfig
 */
function fetch(url, options) {
  var response,
      oAuthConfig;
  
  oAuthConfig = getOAuthConfig(options.oAuthConfig);
  
  //dump_('oAuthConfig.options', oAuthConfig.options);
  //dump_('fetch options', options);
  
  response = oAuthConfig.fetch(url, options);
  
  return response;
};

/**
 * creates oAuthConfig instance from options or stored instance
 *
 * @param {object|string} passedIn describing instance to be created
 * @param {binary} noHistory create only from passedIn, no stored
 *   details
 * @return {object}
 */
function getOAuthConfig(passedIn) {
  dump_('getOAuthConfig()');
  
  var allKeys,
      propKey,
      userProps,
      scriptProps,
      options,
      noHistory,
      oAuthConfig;
  
  if (_.isString(passedIn)) {
    passedIn = { 
      serviceName: passedIn 
    };
  }
  //deal with special options (see oAuthConfig constructor also)
  if (_.has(passedIn, 'noHistory')) {
    noHistory = passedIn.noHistory;
  }
  
  
  //retrieved stored info
  propKey = PREFIX_ + passedIn.serviceName;
  
  userProps = PropertiesService.getUserProperties().getProperty(propKey);
  userProps = JSON.parse(userProps);
  if (_.isNull(userProps) || noHistory) {
    userProps = {};
  }
  
  scriptProps = PropertiesService.getScriptProperties().getProperty(propKey);
  scriptProps = JSON.parse(scriptProps);
  if (_.isNull(scriptProps) || noHistory) {
    scriptProps = {};
  }
  
  
  //recursive merge, passedIn takes precedence
  options = _.deepExtend(
    defaults_,
    userProps,
    scriptProps,
    passedIn
  );

  oAuthConfig = new OAuthConfig_(options);
  
  return oAuthConfig;
};

/**
 * manages oauth parameters, requests tokens, manages ui flow
 *
 * @constructor
 * @param {object} options key value map describing config
 */
function OAuthConfig_(options) {
  dump_('OAuthConfig.constructor()');
  
  this.options = options;
  
  //deal with special options
  if (_.has(options, 'enableDebug') && options.enableDebug) {
    enableDebug();
  }
  
};

function OAuthError(message) {
  this.name = "OAuthError";
  this.message = message || "Default Message";
}
OAuthError.prototype = new Error();
OAuthError.prototype.constructor = OAuthError;

/**
 * initiates auth flow
 */
OAuthConfig_.prototype.authorize = function(showDoOver) {
  dump_('OAuthConfig.authorize()');
  
  this.authLegOne();
  this.authLegTwo(showDoOver);
};

/**
 * fire off a request to requestTokenUrl
 */
OAuthConfig_.prototype.authLegOne = function() {
  dump_('OAuthConfig.authLegOne()');
  
  var oAuthParams,
      options,
      url,
      response;
  
  
  options = {
    method: 'GET',
    muteHttpExceptions: true,
    headers: {}
  };
  dump_('options', this.options);
  url = this.options.urls.requestTokenUrl;
  oAuthParams = {
    //oauth_callback: getCallbackUrl(),
    oauth_nonce: createNonce_(),
    oauth_timestamp: createTimestamp_(),
    oauth_signature_method: this.options.oAuth.oauth_signature_method,
    oauth_consumer_key: this.options.oAuth.oauth_consumer_key
  };
  oAuthParams.oauth_signature = this.getSignature(url, options, oAuthParams);
  options.headers.Authorization = createAuthHeader_(oAuthParams);

  response = UrlFetchApp.fetch(url, options); 
  response = parseUri_('?' + response.getContentText()).queryKey; 
  
  this.options.oAuth.oauth_token_secret = response.oauth_token_secret;
  this.options.oAuth.oauth_token = response.oauth_token;
  
  dump_('auth leg one', response);
};

/**
 * show dialog with link to service provider and copypasta input box
 */
OAuthConfig_.prototype.authLegTwo = function(showDoOver) {
  dump_('OAuthConfig.authLegTwo()');
  
  var html;
  
  html = HtmlService.createTemplateFromFile('authDialog');
  html.url = this.options.urls.authorizationUrl + '?oauth_token=' + this.options.oAuth.oauth_token; 
  _.each(this.options.dialog, function(value, key) {
    html[key] = value;
  });
  html.serviceName = this.options.serviceName;
  html.doOverVisibility = showDoOver ? 'visible' : 'collapse';
  html.verifierInputVisibility = this.options.dialog.showVerifierInput ? 'visible' : 'collapse';
  
  output = html.evaluate().setWidth(400).setHeight(450);
  
  ui = SpreadsheetApp.getUi()
  ui.showModalDialog(output, 'Authorization Required');
  
  //after showing the dialog, this instance will die, so we need to store the config
  this.store();
};

/**
 * send the original token back to provider, along with verifier, and get an access token
 * 
 * @param {string|number} verifier verifier code received from service provider in leg two
 */
OAuthConfig_.prototype.authLegThree = function(verifier) {
  dump_('OAuthConfig.authLegThree()');
  
  var oAuthParams,
      options,
      url,
      response;
  
  options = {
    method: 'GET',
    headers: {}
  };
  url = this.options.urls.accessTokenUrl;
  oAuthParams = {
    oauth_nonce: createNonce_(),
    oauth_timestamp: createTimestamp_(),
    oauth_signature_method: this.options.oAuth.oauth_signature_method,
    oauth_token: this.options.oAuth.oauth_token,
    oauth_verifier: verifier,
    oauth_consumer_key: this.options.oAuth.oauth_consumer_key
  };
  oAuthParams.oauth_signature = this.getSignature(url, options, oAuthParams);
  options.headers.Authorization = createAuthHeader_(oAuthParams);
  
  response = UrlFetchApp.fetch(url, options); 
  response = parseUri_('?' + response.getContentText()).queryKey; 
  
  //check response contains expected keys
  if (_.has(response, 'oauth_token') && _.has(response, 'oauth_token_secret')) {
    
    //replace current token
    this.options.oAuth.oauth_token = response.oauth_token;
    this.options.oAuth.oauth_token_secret = response.oauth_token_secret;
    
    //set expiry time less 30 seconds
    if (_.has(response, 'oauth_expires_in')) {
      this.options.expiresAt = Date.now() + ((response.oauth_expires_in - 30) * 1000);
    }
    
    //finally.. store the token for future calls
    this.store();
    
  } else {
    //some failure condition
  }
  
  
  dump_('auth leg three', response);
  
  return response;
  
};

/**
 * clears instance's tokens, and those in userProperties
 */
OAuthConfig_.prototype.clear = function() {
  dump_('OAuthConfig.clear()');
  
  var propKey;
  
  propKey = PREFIX_ + this.serviceName;
  
  PropertiesService.getUserProperties().deleteProperty(propKey);
  
  this.options.oAuth = _.extend(
    this.options.oAuth,
    {
      oauth_token: false,
      oauth_token_secret: false,
      oauth_verifier: false
    }
  );
};

/**
 * populates options with oauth things checks the response for indications that reAuth is required
 *
 * @param {string} url target url
 * @param {object} options options key value map suitable for UrlFetchApp.fetch()
 */
OAuthConfig_.prototype.fetch = function(url, options) {
  dump_('OAuthConfig.fetch()');
  
  var response,
      oAuthParams,
      responseParams,
      reauth;
  
  if (this.hasExpired()) {
    if (this.options.reauthOnExpired) {
      this.authorize(true);
    }
    throw new OAuthError("authorization token has timed out");
  }
  
  options.headers = _.extend({}, options.headers, {muteHttpExceptions: true});
  
  oAuthParams = {
    oauth_nonce: createNonce_(),
    oauth_timestamp: createTimestamp_(),
    oauth_signature_method: this.options.oAuth.oauth_signature_method,
    oauth_token: this.options.oAuth.oauth_token,
    oauth_consumer_key: this.options.oAuth.oauth_consumer_key
  };
  oAuthParams.oauth_signature = this.getSignature(url, options, oAuthParams);
  options.headers = _.extend(
    {
      Authorization: createAuthHeader_(oAuthParams)
    },
    options.headers
  );
  
  //override default error handling
  options.muteHttpExceptions = true;
  
  response = UrlFetchApp.fetch(url, options);

  if (response.getResponseCode() != 200) {
    dump_('oAuthResponse (' + response.getResponseCode() + ')', response);
    response = parseUri_('?' + response).queryKey;
    reauth = _.some(
      _.values(parseUri_('?' + response).queryKey),
      function(uriValue) {
        return _.some(
          this.options.reauthOn,
          function(reauthValue) {
            return (uriValue == reauthValue);
          }
        );
      }
    );
    if (reauth) {
      this.authorize(true);
    }
    throw new OAuthError("response says oAuth token has expired");
  }
  
  return response;
};

/**
 * generates oAuth signature
 *
 * @param {string} url target url
 * @param {object} options key value map of options
 * @param {object} oAuthParams key value map of oAuth parameters
 * @return {string}
 */
OAuthConfig_.prototype.getSignature = function(url, options, oAuthParams) {
  dump_('OAuthConfig.getSignature()');
  
  var baseString = '',
      signingKey = '',
      signature,
      params = {},
      method;
  
  method = options.method.toUpperCase();
  
  
  
  //get all the params
  params = _.union(
    _.map(options.payload, percentEncodePair_),
    _.map(oAuthParams, percentEncodePair_),
    _.map(parseUri_(url).queryKey, function(value, key) { return key + "=" + value; })
  );
  params = params.sort();
  params = params.join('&');
  params = percentEncode_(params);

  url = percentEncode_(url.split('?')[0]);
  
  baseString = method + '&' + url + '&' + params;
  
  //create signing key
  signingKey += percentEncode_(this.options.oAuth.oauth_consumer_secret);
  signingKey += '&';
  if (this.options.oAuth.oauth_token_secret) {
    signingKey += percentEncode_(this.options.oAuth.oauth_token_secret);
  }
  
  //create signature
  signature = Utilities.computeHmacSignature(Utilities.MacAlgorithm.HMAC_SHA_1, baseString, signingKey);
  signature = Utilities.base64Encode(signature);
  signature = percentEncode_(signature);
  
  if (debug_) {
    signatureParams_ = {};
    signatureParams_.method = method;
    signatureParams_.url = url.split('?')[0];
    signatureParams_.parameters = _.union(
      _.map(options.payload, percentEncodePair_),
      _.map(parseUri_(url).queryKey, function(value, key) { return key + "=" + value; })
    ).sort().join('&');
    signatureParams_.version = oAuthParams.oauth_version;
    signatureParams_.consumerKey = oAuthParams.oauth_consumer_key;
    signatureParams_.consumerSecret = oAuthParams.oauth_consumer_secret;
    signatureParams_.token = oAuthParams.oauth_token;
    signatureParams_.tokenSecret = oAuthParams.oauth_token_secret;
    signatureParams_.timestamp = oAuthParams.oauth_timestamp;
    signatureParams_.nonce = oAuthParams.oauth_nonce;
    signatureParams_.signatureMethod = oAuthParams.signature_method;
  }
  
  return signature;
};

/*
 * returns true of Date.now() is greater than oauth_expires_in token
 */
OAuthConfig_.prototype.hasExpired = function() {
  if (
    (this.options.expiresAt) &&
    (Date.now() > this.options.expiresAt)
  ) {
    return true;
  }
  return false;
};

/**
 * stores this instance in userProperties
 */
OAuthConfig_.prototype.store = function() {
  dump_('OAuthConfig.store()');
  
  var propKey,
      userProps,
      scriptProps,
      sensitiveKeys;
  
  propKey = PREFIX_ + this.options.serviceName;
  
  sensitiveKeys = ['oauth_consumer_key', 'oauth_consumer_secret'];
  
  //not sure if this really protects your consumer secret or not,
  //  but it seems sensible to store the consumer secret in scriptProps rather
  //  than userProps
  scriptProps = {
    oAuth: _.pick(this.options.oAuth, sensitiveKeys)
  };
  PropertiesService.getScriptProperties().setProperty(
    propKey,
    JSON.stringify(scriptProps)
  );
  
  userProps = this.options;
  userProps.oAuth = _.omit(this.options.oAuth, sensitiveKeys);
  
  PropertiesService.getUserProperties().setProperty(
    propKey,
    JSON.stringify(userProps)
  );
  
};

/**
 * parseUri 1.2.2 (c) Steven Levithan <stevenlevithan.com>  MIT License (modified)
 *
 * @param {string} str The uri string
 * @return {object} 
 */
function parseUri_(str) {
  var o = {
    strictMode: false,
    key: ["source","protocol","authority","userInfo","user","password","host","port","relative","path","directory","file","query","anchor"],
    q:   {
      name:   "queryKey",
      parser: /(?:^|&)([^&=]*)=?([^&]*)/g
    },
    parser: {
      strict: /^(?:([^:\/?#]+):)?(?:\/\/((?:(([^:@]*)(?::([^:@]*))?)?@)?([^:\/?#]*)(?::(\d*))?))?((((?:[^?#\/]*\/)*)([^?#]*))(?:\?([^#]*))?(?:#(.*))?)/,
      loose:  /^(?:(?![^:@]+:[^:@\/]*@)([^:\/?#.]+):)?(?:\/\/)?((?:(([^:@]*)(?::([^:@]*))?)?@)?([^:\/?#]*)(?::(\d*))?)(((\/(?:[^?#](?![^?#\/]*\.[^?#\/.]+(?:[?#]|$)))*\/?)?([^?#\/]*))(?:\?([^#]*))?(?:#(.*))?)/
    }
  };
  var m   = o.parser[o.strictMode ? "strict" : "loose"].exec(str),
      uri = {},
      i   = 14;
  

  
  while (i--) uri[o.key[i]] = m[i] || "";
  
  uri[o.q.name] = {};
  uri[o.key[12]].replace(o.q.parser, function ($0, $1, $2) {
    if ($1) uri[o.q.name][$1] = $2;
  });
  
  return uri;
};

/**
 * encodes string to RFC 3986 percentEncode spec
 *
 * see https://dev.twitter.com/docs/auth/percent-encoding-parameters
 * RFC 3986, Section 2.1
 * @param {String} string
 * @return {String}
 */
function percentEncode_(string) {
  var char, 
      charCode, 
      i,
      encodedString = '';
  
  if (string === undefined) {
    return '';
  }
  
  for (i=0; i<string.length; i++) {
    char = string.charAt(i);
    if (
      (char >= '0' && char <= '9') ||
      (char >= 'A' && char <= 'Z') ||
      (char >= 'a' && char <= 'z') ||
        (char == '-') || (char == '.') ||
          (char == '_') || (char == '~')
          ) {
            encodedString += char;
          } else {
            charCode = string.charCodeAt(i);
            encodedString += '%' + charCode.toString(16).toUpperCase();
          }
  }
  return encodedString;
};

/**
 * percent encodes key value pair to string suitable for signature
 *   base string
 *
 * @param {string} value value from key value pair
 * @param {string} key key from key value pair
 * @return {string}
 */
function percentEncodePair_(value, key) {
 return percentEncode_(key) + '=' + percentEncode_(value);
};