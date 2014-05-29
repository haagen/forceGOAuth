forceGOAuth
===========

A GO library for simplifying OAuth flows with force.com

Please use GitHub Issues for this repository if you 
have any questions, thoughts or ideas around this go 
library. 

Supported OAuth flows:

	Web Server OAuth Authentication Flow

		Status: Full flow implemented

	User-Agent OAuth Authentication Flow

		Status: Authorization URL generation

	Username-Password OAuth Authentication Flow

		Status: Full flow implemented

	OAuth Refresh Token Process

		Status: Implemented for Web Server Flow

Force.com REST API Developer's Guide
https://www.salesforce.com/us/developer/docs/api_rest/

Examples
========

Full Web Server OAuth Authentication Flow

The following example is using the full web server flow from an
application where we are awaiting the callback. 

```
	OAuthSecurity := forceGOAuth.NewOAuthSecurity()
	OAuthSecurity.OAuthBaseURL = "https://test.salesforce.com/services/oauth2"
	OAuthSecurity.ConsumerKey = "XXXX"
	OAuthSecurity.ConsumerSecret = "YYYY"

	err := OAuthSecurity.DoFullWebServerFlow()
	if err != nil {
		fmt.Printf("DoFullWebflow failed: %s\n", err)
		return
	}
```

If the full web server flow will be used from a web application 

```
	OAuthSecurity.BuildAuthorizeURL(OAuthFlow_WebServer)
```

will be used to generate the URL the client should access. In the 
callback method/page OAuthSecurity.AuthCode should be populated
with the Authentication code recieved from the server. And then

```
	OAuthSecurity.GetAccessToken(GrantType_AuthorizationToken)
```

can be used to optain the token. 


Username-Password OAuth Authentication Flow

The following example uses the Username-Password OAuth authentication
flow to optain a token to use. 

```
	OAuthSecurity := forceGOAuth.NewOAuthSecurity()
	OAuthSecurity.OAuthBaseURL = "https://test.salesforce.com/services/oauth2"
	OAuthSecurity.ConsumerKey = "XXXX"
	OAuthSecurity.ConsumerSecret = "YYYY"
	OAuthSecurity.UserName = "user@domain.com"
	OAuthSecurity.Password = "supersecret"

	err := OAuthSecurity.DoFullUNFlow()
	if err != nil {
		fmt.Printf("DoFullUNFlow failed: %s\n", err)
		return
	}
```
