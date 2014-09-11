function authorize() {
  var options,
      oAuthConfig;
  
  options = {
    serviceName: 'Xero',
    enableDebug: true,
    urls: {
      accessTokenUrl: 'https://api.xero.com/oauth/AccessToken',
      requestTokenUrl: 'https://api.xero.com/oauth/RequestToken',
      authorizationUrl: 'https://api.xero.com/oauth/Authorize'
    },
    oAuth: {
      oauth_consumer_key: '3KA2HL6XDBY3KA2HL6XDBY3KA2HL6XDBY', //not my real key
      oauth_consumer_secret: 'EJA76HYBHWEEJA76HYBHWEEJA76HYBHWE', //not my real secret
    },
    dialog: {
      displayName: 'Xero',
      showVerifierInput: true
    },
  };
  
  oAuthConfig = OAuthService.getOAuthConfig(options, true);
  oAuthConfig.authorize();
  
}

function testRequest() {
  var url,
      options,
      response;
  
  url = 'https://api.xero.com/api.xro/2.0/Invoices/21111';
  options = {
    method: 'GET',
    oAuthConfig: 'Xero'
  };
  
  try {
    response = OAuthService.fetch(url, options);
  } catch (e) {
    if (e instanceof OAuthService.OAuthError) {
      //error might explain what happened, but your token has probably expired
      Logger.log(e);
    }
  }
  
  Logger.log(response);
}

function dialogOk(verifier, serviceName) {
  OAuthService.dialogOk(verifier, serviceName);
}