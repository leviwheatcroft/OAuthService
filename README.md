### OAuthService for Google Apps Script

my half baked attempt at an oAuth flow for google apps scripts.

I have this working well in a few projects, but don't expect it to "just work" for you.. it really needs more testing.

## features

 * shows auth ui in container document
 * behaves much like UrlFetchApp.addOAuthService()
 
## a UrlFetchApp.addOAuthService() drop in replacement ??

Not really.. My inability to get callbacks working means:

 * your user has to copypasta the verifier code issued by the provider
 * if your script makes a request when a token has expired, the user will be prompted to reauth,
   but your script won't continue with the original request once a new token is received.

## usage

First, add OAuthService as a library in your script. The project key is:
MxTY6Yo_ej3FEME_TlKbYA78UMGluF7gO 

Next, add something like the contents of test.gs to your script.

There's a few other options in defaults[] declaration in gasLibrary/OAuthService.gs which you probably won't find that useful.

## a little help ?

If you try out this library as is, it's probably not gonna work. Please give me some feedback by opening an issue and posting your log.