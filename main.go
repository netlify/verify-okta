package main

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/aws/aws-lambda-go/events"
	"github.com/aws/aws-lambda-go/lambda"
	jwt "github.com/dgrijalva/jwt-go"
)

const expiration = time.Hour

var client = &http.Client{}

type Authorization struct {
	Roles []string `json:"roles"`
}

type AppMetadata struct {
	Authorization Authorization `json:"authorization"`
}

type Claims struct {
	AppMetadata AppMetadata `json:"app_metadata"`
	jwt.StandardClaims
}

type data struct {
	OktaID string `json:"okta_id"`
}

type response struct {
	ID     string `json:"id"`
	UserID string `json:"userId"`
	Login  string `json:"login"`
	Status string `json:"status"`
}

func handleLogin(request events.APIGatewayProxyRequest) (events.APIGatewayProxyResponse, error) {
	var d data
	if err := json.NewDecoder(strings.NewReader(request.Body)).Decode(&d); err != nil {
		return events.APIGatewayProxyResponse{
			StatusCode: 500,
			Body:       fmt.Sprintf("Failed to parse payload: %v", err),
		}, nil
	}

	baseURL := os.Getenv("OKTA_BASE_URL")
	if baseURL == "" {
		return events.APIGatewayProxyResponse{
			StatusCode: 500,
			Body:       "No OKTA_BASE_URL in environment",
		}, nil
	}
	apiToken := os.Getenv("OKTA_API_TOKEN")
	if apiToken == "" {
		return events.APIGatewayProxyResponse{
			StatusCode: 500,
			Body:       "No OKTA_API_TOKEN in environment",
		}, nil
	}
	jwtSecret := os.Getenv("JWT_SECRET")
	if jwtSecret == "" {
		return events.APIGatewayProxyResponse{
			StatusCode: 500,
			Body:       "No JWT_SECRET in environment",
		}, nil
	}

	apiURL, err := url.Parse(baseURL)
	if err != nil {
		return events.APIGatewayProxyResponse{
			StatusCode: 500,
			Body:       fmt.Sprintf("Failed to parse OKTA_BASE_URL: %v", err),
		}, nil
	}

	apiURL.Path = "/api/v1/sessions/" + d.OktaID

	req, err := http.NewRequest("GET", apiURL.String(), nil)
	if err != nil {
		return events.APIGatewayProxyResponse{
			StatusCode: 500,
			Body:       fmt.Sprintf("Failed to construct okta request %v", err),
		}, nil
	}
	req.Header.Add("Accept", "application/json")
	req.Header.Add("Content-Type", "application/json")
	req.Header.Add("Authorization", "SSWS "+apiToken)

	resp, err := client.Do(req)
	if err != nil {
		return events.APIGatewayProxyResponse{
			StatusCode: 500,
			Body:       fmt.Sprintf("Okta session request failed: %v", err),
		}, nil
	}
	defer resp.Body.Close()

	var oktaResp response
	if err := json.NewDecoder(resp.Body).Decode(&oktaResp); err != nil {
		return events.APIGatewayProxyResponse{
			StatusCode: 500,
			Body:       fmt.Sprintf("Failed to parse response from Okta: %v", err),
		}, nil
	}

	if oktaResp.Status != "ACTIVE" {
		return events.APIGatewayProxyResponse{
			StatusCode: 500,
			Body:       fmt.Sprintf("Session status was not active (%v)", oktaResp.Status),
		}, nil
	}

	claims := &Claims{
		AppMetadata{
			Authorization: Authorization{
				Roles: []string{"user"},
			},
		},
		jwt.StandardClaims{
			ExpiresAt: time.Now().Add(expiration).Unix(),
			Subject:   oktaResp.UserID,
		},
	}
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	ss, err := token.SignedString([]byte(jwtSecret))
	if err != nil {
		return events.APIGatewayProxyResponse{
			StatusCode: 500,
			Body:       fmt.Sprintf("Failed to sign JWT: %v", err),
		}, nil
	}

	cookie := http.Cookie{
		Name:     "nf_jwt",
		Value:    ss,
		Path:     "/",
		Expires:  time.Now().Add(expiration),
		Secure:   true,
		HttpOnly: true,
	}

	return events.APIGatewayProxyResponse{
		StatusCode: 200,
		Body:       "{}",
		Headers:    map[string]string{"Set-Cookie": cookie.String()},
	}, nil
}

func handleJS(request events.APIGatewayProxyRequest) (events.APIGatewayProxyResponse, error) {
	baseURL := os.Getenv("OKTA_BASE_URL")
	if baseURL == "" {
		return events.APIGatewayProxyResponse{
			StatusCode: 500,
			Body:       "No OKTA_BASE_URL in environment",
		}, nil
	}
	clientID := os.Getenv("OKTA_CLIENT_ID")
	if clientID == "" {
		return events.APIGatewayProxyResponse{
			StatusCode: 500,
			Body:       "No OKTA_CLIENT_ID in environment",
		}, nil
	}

	return events.APIGatewayProxyResponse{
		StatusCode: 200,
		Headers:    map[string]string{"Content-Type": "text/javascript"},
		Body: `
		var baseURL = "` + baseURL + `";
		var clientId = "` + clientID + `";
		var oktaCDN = "https://ok1static.oktacdn.com/assets/js/sdk/okta-signin-widget/2.6.0";
		var js = "/js/okta-sign-in.min.js";
		var css = ["/css/okta-sign-in.min.css", "/css/okta-theme.css"];

		function addScript(script, cb) {
		  var tag = document.createElement("script");
		  tag.onload = cb;
		  tag.src = oktaCDN + script;
		  document.head.appendChild(tag);
		}

		function addCSS(url) {
		  var tag = document.createElement("link");
		  tag.rel = "stylesheet";
		  tag.href = oktaCDN + url;
		  document.head.appendChild(tag);
		}

		css.forEach(function (href) {
		  addCSS(href);
		});

		function ajax(method, url, body, cb) {
		  var request = new window.XMLHttpRequest();
		  request.open(method, url);
		  request.addEventListener("load", function (e) {
			cb(request.status == 200 ? null : request);
		  });
		  request.send(body);
		}

		addScript(js, function () {
		  var oktaSignIn = new OktaSignIn({
			baseUrl: baseURL,
			clientId: clientId,
			authParams: {
			  issuer: baseURL + "/oauth2/default",
			  responseType: ['id_token'],
			  display: 'page'
			}
		  });
		  if (oktaSignIn.token.hasTokensInUrl()) {
			oktaSignIn.token.parseTokensFromUrl(
			  function success(res) {
				var idToken = res[0];
				// Remove the tokens from the window location hash
				window.location.hash = '';
				ajax("POST", "/.netlify/functions/verify-okta", JSON.stringify({ okta_id: idToken.id }), function (err) {
				  if (err) {
					console.error("Error setting session cookie: ", err);
					return;
				  }
				  document.location.reload();
				});
			  },
			  function error(err) {
				// handle errors as needed
				console.error(err);
			  }
			);
		  } else {
			oktaSignIn.session.get(function (res) {
			  // Session exists, show logged in state.
			  if (res.status === 'ACTIVE') {
				console.log("AJAX!!!");
				ajax("POST", "/.netlify/functions/verify-okta", JSON.stringify({ okta_id: res.id }), function (err) {
				  if (err) {
					console.error("Error setting session cookie: ", err);
					return;
				  }
				  document.location.reload();
				});
				return;
			  }
			  // No session, show the login form
			  oktaSignIn.renderEl(
				{ el: '#okta-login-container' },
				function success(res) {
				  // Nothing to do in this case, the widget will automatically redirect
				  // the user to Okta for authentication, then back to this page if successful
				},
				function error(err) {
				  // handle errors as needed
				  console.error(err);
				}
			  );
			});
		  }
		});`,
	}, nil
}

func handler(request events.APIGatewayProxyRequest) (events.APIGatewayProxyResponse, error) {
	if request.HTTPMethod == "GET" && strings.HasSuffix(request.Path, "/okta.js") {
		return handleJS(request)
	}

	if request.HTTPMethod == "POST" {
		return handleLogin(request)
	}

	return events.APIGatewayProxyResponse{
		StatusCode: 400,
		Body:       "Bad Request",
	}, nil
}

type LocalServer struct{}

func (l *LocalServer) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	body, err := ioutil.ReadAll(r.Body)
	if err != nil {
		log.Printf("Error reading request body: %v", err)
		w.WriteHeader(500)
		w.Write([]byte(fmt.Sprintf("Failed to write body: %v", err)))
		return
	}

	req := events.APIGatewayProxyRequest{
		Body: string(body),
	}
	resp, err := handler(req)
	if err != nil {
		log.Printf("Error handling request: %v", err)
		w.WriteHeader(500)
		w.Write([]byte(fmt.Sprintf("Error handling request: %v", err)))
		return
	}
	for k, v := range resp.Headers {
		w.Header().Add(k, v)
	}
	w.WriteHeader(resp.StatusCode)
	w.Write([]byte(resp.Body))
}

func local() {
	server := &LocalServer{}
	fmt.Println("Starting local dev server on :8999")
	http.ListenAndServe(":8999", server)
}

func main() {
	if os.Getenv("AWS_LAMBDA_FUNCTION_NAME") == "" {
		local()
	} else {
		// Make the handler available for Remote Procedure Call by AWS Lambda
		lambda.Start(handler)
	}
}
