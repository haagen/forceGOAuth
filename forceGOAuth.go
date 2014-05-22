package forceGOAuth

import (
	"bytes"
	"errors"
	"fmt"
	"encoding/json"
	"html/template"
	"io"
	"io/ioutil"
	"net"
	"net/http"
	"net/url"
)

const (
	PORT = "8080"
)

const (
	GrantType_AuthorizationToken = iota 
	GrantType_RefreshToken
	GrantType_Password
)

const (
	OAuthFlow_WebServer = iota
	OAuthFlow_UserAgent
	OAuthFlow_Password
)

var HTTPClient *http.Client = nil

type OAuthSecurity struct {
    ConsumerKey string
    ConsumerSecret string
    ConsumerCallback string
    OAuthBaseURL string
    AuthCode string
    AccessToken string
    RefreshToken string
    InstanceUrl string
    Id string
    IssuedAt string
    Scope string
    AutoRefreshToken bool
    UserName string
    Password string
}

type ForceResponse map[string]interface{}

func NewOAuthSecurity()(oa *OAuthSecurity) {
	oa = &OAuthSecurity {
		AutoRefreshToken: true,
	}
	return
}

func (oa *OAuthSecurity) ImportSettingsJSON(settingsJson []byte) (err error) {
	err = json.Unmarshal(settingsJson, &oa)
	return
}

func (oa *OAuthSecurity) ExportSettingsJSON() (settingsJson []byte, err error) {
	settingsJson, err = json.Marshal(oa)
	return
}

func (oa *OAuthSecurity) DoFullWebServerFlow()(err error) {
	oa.ConsumerCallback = "http://localhost:"+PORT
	ch := make(chan OAuthSecurity)
	_, err = startLocalHttpServer(ch)
	Open(oa.BuildAuthorizeURL(OAuthFlow_WebServer))
	var out OAuthSecurity = <-ch
	if out.AuthCode == "" {
		err = errors.New("AuthCode was not recieved from Salesforce")
		return
	}
	oa.AuthCode = out.AuthCode
	err = oa.GetAccessToken(GrantType_AuthorizationToken)
	return
}

func (oa *OAuthSecurity) DoFullUserAgentFlow()(err error) {
	oa.ConsumerCallback = "http://localhost:"+PORT
	ch := make(chan OAuthSecurity)
	_, err = startLocalHttpServer(ch)
	Open(oa.BuildAuthorizeURL(OAuthFlow_UserAgent))
	var out OAuthSecurity = <-ch
	if out.AccessToken == "" {
		err = errors.New("AccessToken was not recieved from Salesforce")
		return
	}
	oa.AccessToken = out.AccessToken
	oa.RefreshToken = out.RefreshToken
	oa.InstanceUrl = out.InstanceUrl
	return
}

func (oa *OAuthSecurity) BuildAuthorizeURL(OAuthFlow int)(AuthorizeURL string) {
	if OAuthFlow_WebServer == OAuthFlow {
		var AuthURL string = "%s/authorize?response_type=code&immediate=false&client_id=%s&redirect_uri=%s&scope=%s"
	    AuthorizeURL = fmt.Sprintf(AuthURL, oa.OAuthBaseURL, url.QueryEscape(oa.ConsumerKey), url.QueryEscape(oa.ConsumerCallback), url.QueryEscape(oa.Scope))
	}
	if OAuthFlow_UserAgent == OAuthFlow {
		var AuthURL string = "%s/authorize?response_type=token&client_id=%s&redirect_uri=%s&scope=%s"
		AuthorizeURL = fmt.Sprintf(AuthURL, oa.OAuthBaseURL, url.QueryEscape(oa.ConsumerKey), url.QueryEscape(oa.ConsumerCallback), url.QueryEscape(oa.Scope))
	}
	return
}

func (oa *OAuthSecurity) GetAccessToken(GrantType int) (err error) {  
    values := make(map[string]string)
    myUrl := fmt.Sprintf("%s/token", oa.OAuthBaseURL)

    if GrantType == GrantType_RefreshToken {
        values["refresh_token"] = oa.RefreshToken
        values["grant_type"] = "refresh_token"
    }
    if GrantType == GrantType_AuthorizationToken {
        values["code"] = oa.AuthCode   
        values["redirect_uri"] = oa.ConsumerCallback
        values["grant_type"] = "authorization_code"
    }
    if GrantType == GrantType_Password {
    	values["username"] = oa.UserName
    	values["password"] = oa.Password
    	values["grant_type"] = "password"
    }
    values["client_id"] = oa.ConsumerKey
    values["client_secret"] = oa.ConsumerSecret
    values["format"] = "json"
    var res []byte
    fmt.Printf("GetAccessToken URL=%s\n", UrlEncode(values))
    var requestBody []byte = []byte(UrlEncode(values))
    if res, err = oa.httpPost(myUrl, requestBody, "application/x-www-form-urlencoded"); err != nil {
        return err
    }   
    var result ForceResponse
    json.Unmarshal(res, &result) 
    oa.AccessToken = "" 
    for idx, val := range(result) {         
        if idx == "access_token" {            
            oa.AccessToken = val.(string)            
        }
        if idx == "instance_url" {
            oa.InstanceUrl = val.(string)
        }
        if idx == "refresh_token" {
            oa.RefreshToken = val.(string)
        }
    }
    return nil
}


func (oa *OAuthSecurity) httpPost(theUrl string, requestBody []byte, contentType string) (body []byte, err error) {

    req, err := httpRequest("POST", theUrl, bytes.NewReader(requestBody))
    if err != nil {
        return
    }
    if oa.AccessToken != "" {
        req.Header.Add("Authorization", fmt.Sprintf("Bearer %s", oa.AccessToken))
    }
    if contentType != "" {
    	req.Header.Add("Content-Type", contentType)
    } else {
    	req.Header.Add("Content-Type", "application/json")
    }
    res, err := httpClient().Do(req)
    if err != nil {
        return
    }
    defer res.Body.Close()
    if res.StatusCode == 401 {
    	if oa.AutoRefreshToken && oa.RefreshToken != "" {
        	oa.AutoRefreshToken = false
        	oa.AccessToken = ""
        	err = oa.GetAccessToken(GrantType_RefreshToken)
        	if err != nil && oa.AccessToken != "" {
        		body, err = oa.httpPost(theUrl, requestBody, contentType)
        	}
			oa.AutoRefreshToken = true        	
			return
        }
        err = errors.New("authorization expired - could not refresh token")
        return
    }
    body, err = ioutil.ReadAll(res.Body)
    if res.StatusCode/100 != 2 {
     	err = errors.New(fmt.Sprintf("Status Code was not 200 (%d) - %s", res.StatusCode, CharsToString(body)))
        return
    }
    return
}

func UrlEncode(attrs map[string]string) (retUrl string) {
    retUrl = ""
    for key, val := range(attrs) {
        if len(retUrl) > 0 {
            retUrl += "&"
        }
        retUrl += url.QueryEscape(key) + "=" + url.QueryEscape(val)
    }    
    return
}

func httpRequest(method, url string, body io.Reader) (request *http.Request, err error) {
    request, err = http.NewRequest(method, url, body)
    if err != nil {
        return
    }
    request.Header.Add("User-Agent", "github.com/haagen/forceGOAuth")
    return
}

func httpClient() (client *http.Client) {
	if HTTPClient == nil {
    	client = &http.Client{}
    } else {
    	client = HTTPClient
    }
    return
}

// Stolen from force.com CLI -- github.com/heroku/force
func startLocalHttpServer(ch chan OAuthSecurity) (port int, err error) {
	listener, err := net.Listen("tcp", ":"+PORT)
	if err != nil {
		return
	}
	port = listener.Addr().(*net.TCPAddr).Port
	h := http.NewServeMux()
	h.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		query := r.URL.Query()
		fmt.Println(">> " + r.URL.RawQuery)
		var oa OAuthSecurity
		if query.Get("code") == "" {	// No AuthCode assume user-client flow			
			u, _ := r.URL.Parse("http://server/?" + r.URL.Fragment)
			query = u.Query()
		}		
		oa.AuthCode = query.Get("code")
		oa.AccessToken = query.Get("access_token")
		oa.RefreshToken = query.Get("refresh_token")
		oa.InstanceUrl = query.Get("instance_url")
		ch <- oa
		if _, ok := r.Header["X-Requested-With"]; ok == false {
			PrintError(w, "You can close your browser window now")
		}
		listener.Close()
	})
	go http.Serve(listener, h)
	return
}

var errorTemplate = template.Must(template.New("error").Parse(`
<html>
  <head>
    <title>Error</title>
  </head>
  <body>
    <h1>An error occured</h1>
    <pre>{{.}}</pre>
  </body>
  </html>
`))

func PrintError(w http.ResponseWriter, s string) {
    errorTemplate.Execute(w, s)    
}

func CharsToString(ca []byte) string { 
        s := make([]byte, len(ca)) 
        var lens int 
        for ; lens < len(ca); lens++ { 
                if ca[lens] == 0 { 
                        break 
                } 
                s[lens] = uint8(ca[lens]) 
        } 
        return string(s[0:lens]) 
} 

func InitF() {
	fmt.Println("Hello World!")
}