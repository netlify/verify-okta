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

type data struct {
	OktaID string `json:"okta_id"`
}

type response struct {
	ID     string `json:"id"`
	UserID string `json:"userId"`
	Login  string `json:"login"`
	Status string `json:"status"`
}

func handler(request events.APIGatewayProxyRequest) (events.APIGatewayProxyResponse, error) {
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
	if err := json.NewDecoder(resp.Body).Decode(oktaResp); err != nil {
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

	claims := &jwt.StandardClaims{
		ExpiresAt: int64(expiration),
		Subject:   oktaResp.UserID,
	}
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	ss, err := token.SignedString([]byte(jwtSecret))
	if err != nil {
		return events.APIGatewayProxyResponse{
			StatusCode: 500,
			Body:       fmt.Sprintf("Failed to sign JWT: %v", err),
		}, nil
	}

	return events.APIGatewayProxyResponse{
		StatusCode: 200,
		Body:       "{}",
		Headers: map[string]string{
			"Cookie": "nf_jwt=" + ss + "; path=/; secure; HttpOnly",
		},
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
