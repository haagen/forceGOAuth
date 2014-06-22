package forceGOAuth

import (
	"fmt"
	"github.com/bmizerany/assert"
	"net/http"
	"net/http/httptest"
	"testing"
)

var (
	mux    *http.ServeMux
	server *httptest.Server
	client *OAuthSecurity
)

func setup() {
	mux = http.NewServeMux()
	server = httptest.NewServer(mux)
	client = NewOAuthSecurity()
	client.OAuthBaseURL = server.URL
}

func teardown() {
	server.Close()
}

func testMethod(t *testing.T, r *http.Request, want string) {
	if want != r.Method {
		t.Errorf("Request method = %v, want %v", r.Method, want)
	}
}

type values map[string]string

func testFormValues(t *testing.T, r *http.Request, values values) {
	for key, want := range values {
		if v := r.FormValue(key); v != want {
			t.Errorf("Request parameter %v = %v, want %v", key, v, want)
		}
	}
}

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

func Test_GetAccessToken_AccessToken(t *testing.T) {
	setup()
	defer teardown()

	client.AuthCode = "TheAuthCode"
	client.ConsumerCallback = "TheCallBack"
	client.ConsumerKey = "TheConsumerKey"
	client.ConsumerSecret = "TheConsumerSecret"
	mux.HandleFunc("/token", func(w http.ResponseWriter, r *http.Request) {
		testMethod(t, r, "POST")
		testFormValues(t, r, values{
			"code":          "TheAuthCode",
			"redirect_uri":  "TheCallBack",
			"grant_type":    "authorization_code",
			"client_id":     "TheConsumerKey",
			"client_secret": "TheConsumerSecret",
			"format":        "json",
		})
		fmt.Fprint(w, `
{
   "id":"TheId",
   "issued_at":"TheIssuedAt",
   "scope":"full refresh_token",
   "instance_url":"TheInstanceURL",
   "token_type":"Bearer",
   "refresh_token":"TheRefreshToken",
   "id_token":"TheIdToken",
   "signature":"TheSignature",
   "access_token":"TheAccessToken"
}`)
	})

	err := client.GetAccessToken(GrantType_AuthorizationToken)
	assert.Equal(t, err, nil)
	assert.Equal(t, client.AccessToken, "TheAccessToken")
	assert.Equal(t, client.InstanceUrl, "TheInstanceURL")
	assert.Equal(t, client.RefreshToken, "TheRefreshToken")
	assert.Equal(t, client.Id, "TheId")
	assert.Equal(t, client.IssuedAt, "TheIssuedAt")
	assert.Equal(t, client.Signature, "TheSignature")
}

func Test_GetAccessToken_DoFullUNFlow(t *testing.T) {
	setup()
	defer teardown()

	client.AuthCode = "TheAuthCode"
	client.ConsumerCallback = "TheCallBack"
	client.ConsumerKey = "TheConsumerKey"
	client.ConsumerSecret = "TheConsumerSecret"
	client.UserName = "TheUsername"
	client.Password = "ThePassword"
	mux.HandleFunc("/token", func(w http.ResponseWriter, r *http.Request) {
		testMethod(t, r, "POST")
		testFormValues(t, r, values{
			"grant_type":    "password",
			"client_id":     "TheConsumerKey",
			"client_secret": "TheConsumerSecret",
			"format":        "json",
			"username":      "TheUsername",
			"password":      "ThePassword",
		})
		fmt.Fprint(w, `
{
   "id":"TheId",
   "issued_at":"TheIssuedAt",
   "scope":"full refresh_token",
   "instance_url":"TheInstanceURL",
   "token_type":"Bearer",
   "refresh_token":"TheRefreshToken",
   "id_token":"TheIdToken",
   "signature":"TheSignature",
   "access_token":"TheAccessToken"
}`)
	})

	err := client.DoFullUNFlow()
	assert.Equal(t, err, nil)
	assert.Equal(t, client.AccessToken, "TheAccessToken")
	assert.Equal(t, client.InstanceUrl, "TheInstanceURL")
	assert.Equal(t, client.RefreshToken, "TheRefreshToken")
	assert.Equal(t, client.Id, "TheId")
	assert.Equal(t, client.IssuedAt, "TheIssuedAt")
	assert.Equal(t, client.Signature, "TheSignature")
}

func callLocalServer() {
	resp, err := http.Get(client.ConsumerCallback + "/?code=TheCode")
	if err != nil {
		defer resp.Body.Close()
	}
}

func Test_LocalServer(t *testing.T) {

	client.ConsumerCallback = "http://localhost:" + PORT
	ch := make(chan OAuthSecurity)
	_, err := startLocalHttpServer(ch)
	assert.Equal(t, err, nil)

	go callLocalServer()
	var out OAuthSecurity = <-ch
	assert.Equal(t, out.AuthCode, "TheCode")
}

func Test_LoadSave_Settings(t *testing.T) {

	client.ConsumerKey = "ConsumerKey"
	client.ConsumerSecret = "ConsumerSecret"
	client.ConsumerCallback = "ConsumerCallback"
	client.OAuthBaseURL = "OAuthBaseURL"
	client.AuthCode = "AuthCode"
	client.AccessToken = "AccessToken"
	client.RefreshToken = "RefreshToken"
	client.InstanceUrl = "InstanceUrl"
	client.Id = "Id"
	client.IssuedAt = "IssuedAt"
	client.Signature = "Signature"
	client.Scope = "Scope"
	client.AutoRefreshToken = true
	client.UserName = "UserName"
	client.Password = "Password"

	newClient := NewOAuthSecurity()
	settings, err := client.ExportSettingsJSON()
	assert.Equal(t, err, nil)
	err = newClient.ImportSettingsJSON(settings)
	assert.Equal(t, err, nil)

	assert.Equal(t, newClient.ConsumerKey, "ConsumerKey")
	assert.Equal(t, newClient.ConsumerSecret, "ConsumerSecret")
	assert.Equal(t, newClient.ConsumerCallback, "ConsumerCallback")
	assert.Equal(t, newClient.OAuthBaseURL, "OAuthBaseURL")
	assert.Equal(t, newClient.AuthCode, "AuthCode")
	assert.Equal(t, newClient.AccessToken, "AccessToken")
	assert.Equal(t, newClient.RefreshToken, "RefreshToken")
	assert.Equal(t, newClient.InstanceUrl, "InstanceUrl")
	assert.Equal(t, newClient.Id, "Id")
	assert.Equal(t, newClient.IssuedAt, "IssuedAt")
	assert.Equal(t, newClient.Signature, "Signature")
	assert.Equal(t, newClient.Scope, "Scope")
	assert.Equal(t, newClient.AutoRefreshToken, true)
	assert.Equal(t, newClient.UserName, "UserName")
	assert.Equal(t, newClient.Password, "Password")

}

func Test_CharsToString(t *testing.T) {

	bytes := []byte{97, 98, 99, 100, 101}
	assert.Equal(t, CharsToString(bytes), "abcde")

}

var Test_RefreshUNToken_counter int = 0

func Test_RefreshUNToken(t *testing.T) {
	setup()
	defer teardown()

	client.AuthCode = "TheAuthCode"
	client.ConsumerCallback = "TheCallBack"
	client.ConsumerKey = "TheConsumerKey"
	client.ConsumerSecret = "TheConsumerSecret"
	client.UserName = "TheUsername"
	client.Password = "ThePassword"

	var statusOk string = `
{
	"status":"ok"
}`

	mux.HandleFunc("/testCall", func(w http.ResponseWriter, r *http.Request) {
		testMethod(t, r, "GET")
		if Test_RefreshUNToken_counter == 0 {
			http.Error(w, "NO TOKEN!", 401) // This should simulate token being expired
		}
		if Test_RefreshUNToken_counter == 1 {
			fmt.Fprint(w, statusOk) // Second attempt should be successful
		}
		Test_RefreshUNToken_counter++
	})

	mux.HandleFunc("/token", func(w http.ResponseWriter, r *http.Request) {
		testMethod(t, r, "POST")
		testFormValues(t, r, values{
			"grant_type":    "password",
			"client_id":     "TheConsumerKey",
			"client_secret": "TheConsumerSecret",
			"format":        "json",
			"username":      "TheUsername",
			"password":      "ThePassword",
		})
		fmt.Fprint(w, `
{
   "id":"TheIdRefreshed",
   "issued_at":"TheIssuedAtRefreshed",
   "scope":"full refresh_token",
   "instance_url":"TheInstanceURLRefreshed",
   "token_type":"Bearer",
   "refresh_token":"Refreshed",
   "id_token":"TheIdTokenRefreshed",
   "signature":"TheSignatureRefreshed",
   "access_token":"TheAccessTokenRefreshed"
}`)
	})

	body, err := client.Get(client.OAuthBaseURL+"/testCall", "")
	assert.Equal(t, Test_RefreshUNToken_counter, 2)
	assert.Equal(t, err, nil)
	assert.Equal(t, CharsToString(body), statusOk)
	assert.Equal(t, client.AccessToken, "TheAccessTokenRefreshed")
	assert.Equal(t, client.RefreshToken, "Refreshed")
	assert.Equal(t, client.InstanceUrl, "TheInstanceURLRefreshed")
	assert.Equal(t, client.Id, "TheIdRefreshed")
	assert.Equal(t, client.IssuedAt, "TheIssuedAtRefreshed")
	assert.Equal(t, client.Signature, "TheSignatureRefreshed")
	assert.Equal(t, client.Scope, "full refresh_token")
	assert.Equal(t, client.AutoRefreshToken, true)
}

/*
Response for GetAccessToken for RefreshToken
{
   "id":"TheId",
   "issued_at":"TheIssuedAt",
   "scope":"full refresh_token",
   "instance_url":"TheInstanceURL",
   "token_type":"Bearer",
   "signature":"TheSignature",
   "access_token":"TheAccessToken"
}
*/
