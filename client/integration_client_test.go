package client_test

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"

	"blockchain-api/client"
)

var clientReqBody = client.ClientRequestBody{
	EnrollmentID: "blockclient",
	Secret:       "blockclientpw",
}

func init() {
	// Set environment variables for tests
	os.Setenv("SESSION_AUTH_KEY", "2ae78d6e2a6eb4f722422ae1d8da5c44557ee955da562129e472bebcdff2b3d6")
	os.Setenv("SESSION_ENC_KEY", "3b0b45871551d858151aa7c1fd808673e455059503ee66aaba63cf128ec4f42c")
}

func TestInitialize(t *testing.T) {
	_, err := client.Initialize(clientReqBody.EnrollmentID, clientReqBody.Secret)
	if err != nil {
		t.Fatalf("Failed to initialize OrgSetup: %v", err)
	}
}

func TestClientHandler(t *testing.T) {
	body, _ := json.Marshal(clientReqBody)
	req := httptest.NewRequest("POST", "/client/", bytes.NewReader(body))
	rec := httptest.NewRecorder()
	client.ClientHandler(rec, req)
	if rec.Code != http.StatusOK {
		t.Errorf("Expected 200 OK, got %d. Body: %s", rec.Code, rec.Body.String())
	} else {
		t.Logf("Client initialized successfully: %s", rec.Body.String())
	}
}

func TestInvokeHandlerWithoutInit(t *testing.T) {
	req := httptest.NewRequest("POST", "/client/invoke", nil)
	rec := httptest.NewRecorder()
	client.InvokeHandler(rec, req)
	if rec.Code == http.StatusOK {
		t.Errorf("Expected error when invoking without initialization. Body: %s", rec.Body.String())
	}
}

func TestQueryHandlerWithoutInit(t *testing.T) {
	req := httptest.NewRequest("POST", "/client/query", nil)
	rec := httptest.NewRecorder()
	client.QueryHandler(rec, req)
	if rec.Code == http.StatusOK {
		t.Errorf("Expected error when querying without initialization. Body: %s", rec.Body.String())
	}
}

func TestInvokeHandlerAfterInit(t *testing.T) {
	body, _ := json.Marshal(clientReqBody)
	initReq := httptest.NewRequest("POST", "/client/", bytes.NewReader(body))
	initRec := httptest.NewRecorder()
	client.ClientHandler(initRec, initReq)
	if initRec.Code != http.StatusOK {
		t.Fatalf("Initialization failed, got %d", initRec.Code)
	}

	// Prepare invoke request body (2-arg LogQuery: datasetID, queryBody)
	invokeBody := []byte(`{"chaincodeid":"dt4hCC","channelid":"dt4h","function":"LogQuery","args":["test-dataset","select metadata from test-dataset"]}`)
	invokeReq := httptest.NewRequest("POST", "/client/invoke", bytes.NewReader(invokeBody))
	invokeRec := httptest.NewRecorder()
	client.InvokeHandler(invokeRec, invokeReq)
	if invokeRec.Code != http.StatusOK {
		t.Errorf("Expected 200 OK for invoke after init, got %d; Message: %s", invokeRec.Code, invokeRec.Body.String())
	}
	t.Logf("Invoke Response: %s", invokeRec.Body.String())
}

func TestQueryHandlerAfterInit(t *testing.T) {

	body, _ := json.Marshal(clientReqBody)
	initReq := httptest.NewRequest("POST", "/client/", bytes.NewReader(body))
	initRec := httptest.NewRecorder()
	client.ClientHandler(initRec, initReq)
	if initRec.Code != http.StatusOK {
		t.Fatalf("Initialization failed, got %d", initRec.Code)
	}

	// Prepare query request as GET with query parameters
	queryReq := httptest.NewRequest("GET", "/client/query?chaincodeid=dt4hCC&channelid=dt4h&function=GetMyHistory", nil)
	queryRec := httptest.NewRecorder()
	client.QueryHandler(queryRec, queryReq)
	if queryRec.Code != http.StatusOK {
		t.Errorf("Expected 200 OK for query after init, got %d; Message: %s", queryRec.Code, queryRec.Body.String())
	}
	t.Logf("Query Response: %s", queryRec.Body.String())
}
