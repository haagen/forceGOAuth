package forceGOAuth

import (
	//"errors"
	"fmt"
	"encoding/json"
	"html/template"
	"io"
	"net"
	"net/http"
	"net/url"
)

const (
	PORT = "8080"
)

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
}

func NewOAuthSecurity()(ao *OAuthSecurity) {
	ao = &OAuthSecurity{}
	return
}

func (ao *OAuthSecurity) ImportSettingsJSON(settingsJson []byte) (err error) {
	err = json.Unmarshal(settingsJson, &ao)
	return
}

func (ao *OAuthSecurity) ExportSettingsJSON() (settingsJson []byte, err error) {
	settingsJson, err = json.Marshal(ao)
	return
}

func (ao *OAuthSecurity) BuildAuthorizeURL()(AuthorizeURL string) {
	var AuthURL string = "%s/authorize?response_type=code&immediate=false&client_id=%s&redirect_uri=%s"
    return fmt.Sprintf(AuthURL, ao.OAuthBaseURL, url.QueryEscape(ao.ConsumerKey), url.QueryEscape(ao.ConsumerCallback))
}

func (ao *OAuthSecurity) DoFullWebflow()(err error) {
	ao.ConsumerCallback = "http://localhost:"+PORT
	ch := make(chan OAuthSecurity)
	_, err = startLocalHttpServer(ch)
	Open(ao.BuildAuthorizeURL())
	var out OAuthSecurity 
	out = <-ch
	fmt.Printf("Returned: %s\n", out.AccessToken)
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
    client = &http.Client{}
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
		var creds OAuthSecurity
		creds.AccessToken = query.Get("access_token")
		creds.Id = query.Get("id")
		creds.InstanceUrl = query.Get("instance_url")
		creds.IssuedAt = query.Get("issued_at")
		creds.Scope = query.Get("scope")
		ch <- creds
		if _, ok := r.Header["X-Requested-With"]; ok == false {
			// TODO -o haagen : Write close browser message here
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


func InitF() {
	fmt.Println("Hello World!")
}