package forceGOAuth

import (
	"github.com/bmizerany/assert"
	"testing"
)

// test that all avialable commands come with at least a name and short usage information
func Test_BuildAuthorizeURL(t *testing.T) {
	oa := NewOAuthSecurity()
	oa.OAuthBaseURL = "https://test.salesforce.com/services/oauth2"
	oa.ConsumerKey = "XXXX"
	oa.ConsumerSecret = "YYYY"	
	oa.ConsumerCallback = "ZZZZ"
	oa.Scope = "SSSS"

	assert.Equal(t, oa.BuildAuthorizeURL(OAuthFlow_WebServer), oa.OAuthBaseURL+"/authorize?response_type=code&immediate=false&client_id=XXXX&redirect_uri=ZZZZ&scope=SSSS")
	assert.Equal(t, oa.BuildAuthorizeURL(OAuthFlow_UserAgent), oa.OAuthBaseURL+"/authorize?response_type=token&client_id=XXXX&redirect_uri=ZZZZ&scope=SSSS")
}
