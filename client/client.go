package client

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"sync"
	"testing"

	"github.com/gorilla/sessions"
)

// Store the initialized OrgSetups per session token (thread-safe)
var orgGatewaysSessions sync.Map

var store *sessions.CookieStore
var storeOnce sync.Once
var orgSetup OrgSetup

func init() {
	if testing.Testing() {
		base := filepath.Join("..", "identities", "bsc", "blockclient", "msp")
		orgSetup = OrgSetup{
			OrgName:      getEnvWithDefault("ORG_NAME", "bsc"),
			MSPID:        getEnvWithDefault("MSP_ID", "BscMSP"),
			CryptoPath:   getEnvWithDefault("CRYPTO_PATH", base),
			CertPath:     getEnvWithDefault("CERT_PATH", filepath.Join(base, "signcerts", "cert.pem")),
			KeyPath:      getEnvWithDefault("KEY_PATH", filepath.Join(base, "keystore")),
			TLSCertPath:  getEnvWithDefault("TLS_CERT_PATH", filepath.Join(base, "tlscacerts", "cert.pem")),
			PeerEndpoint: getEnvWithDefault("PEER_ENDPOINT", "dns:///localhost:8020"),
			GatewayPeer:  getEnvWithDefault("GATEWAY_PEER", "peer0.bsc.dt4h.com"),
		}
	} else {
		orgSetup = OrgSetup{
			OrgName:      getEnvWithDefault("ORG_NAME", "bsc"),
			MSPID:        getEnvWithDefault("MSP_ID", "BscMSP"),
			TLSCertPath:  filepath.Join("/app/identities/bsc/bscTLS-root-cert", "tls-ca-cert.pem"),
			PeerEndpoint: getEnvWithDefault("PEER_ENDPOINT", "dns:///localhost:8020"),
			GatewayPeer:  getEnvWithDefault("GATEWAY_PEER", "peer0.bsc.dt4h.com"),
		}
	}
}

// getSessionStore initializes the session store lazily
func getSessionStore() *sessions.CookieStore {
	storeOnce.Do(func() {
		authKey, err := hex.DecodeString(os.Getenv("SESSION_AUTH_KEY"))
		if err != nil {
			log.Fatalf("Error decoding the authKey: %v", err)
		}
		encKey, err := hex.DecodeString(os.Getenv("SESSION_ENC_KEY"))
		if err != nil {
			log.Fatalf("Error decoding the encKey: %v", err)
		}

		if len(authKey) == 0 || len(encKey) == 0 {
			log.Fatal("SESSION_AUTH_KEY and SESSION_ENC_KEY environment variables must be set and non-empty.")
		}
		store = sessions.NewCookieStore(authKey, encKey)
	})
	return store
}

const gatewaySessionKey = "fabricGatewayKey"

func gatewayKeyFromSession(session *sessions.Session) (string, bool) {
	key, ok := session.Values[gatewaySessionKey].(string)
	return key, ok && key != ""
}

func ensureGatewaySessionKey(session *sessions.Session) string {
	if key, ok := gatewayKeyFromSession(session); ok {
		return key
	}
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		key := fmt.Sprintf("gw-%d", len(session.Values)+1)
		session.Values[gatewaySessionKey] = key
		return key
	}
	key := hex.EncodeToString(b[:])
	session.Values[gatewaySessionKey] = key
	return key
}

// Initialize the setup for the organization and store in session map.
func InitializeWithSession(clientRequestBody ClientRequestBody, session *sessions.Session, w http.ResponseWriter, r *http.Request) error {

	gateway, err := Initialize(clientRequestBody.EnrollmentID, clientRequestBody.Secret)
	if err != nil {
		return err
	}
	// CookieStore leaves session.ID empty; key gateways via a value stored in the cookie.
	key := ensureGatewaySessionKey(session)
	if old, ok := GetGateway(key); ok && old != gateway {
		_ = old.Close()
	}
	orgGatewaysSessions.Store(key, gateway)
	session.Options = &sessions.Options{
		Path:     "/",
		HttpOnly: true,
		Secure:   false, // Set to true if using HTTPS
	}
	return session.Save(r, w)
}

// Handler for /client/invoke
func InvokeHandler(w http.ResponseWriter, r *http.Request) {
	fmt.Println("Received Invoke request")
	session, _ := getSessionStore().Get(r, "fabric-session")
	key, ok := gatewayKeyFromSession(session)
	if !ok {
		http.Error(w, "Fabric client not initialized for this session. Call /client/ first.", http.StatusBadRequest)
		return
	}
	gateway, ok := GetGateway(key)
	if !ok {
		http.Error(w, "Fabric client not initialized for this session. Call /client/ first.", http.StatusBadRequest)
		return
	}
	var reqBody RequestBody
	if err := json.NewDecoder(r.Body).Decode(&reqBody); err != nil {
		http.Error(w, "Invalid request body: "+err.Error(), http.StatusBadRequest)
		return
	}
	InvokeWithBody(w, reqBody, gateway)
}

// Handler for /client/query
func QueryHandler(w http.ResponseWriter, r *http.Request) {
	fmt.Println("Received Query request")
	if r.Method == http.MethodGet {
		// Parse query parameters
		chaincodeId := r.URL.Query().Get("chaincodeid")
		channelId := r.URL.Query().Get("channelid")
		function := r.URL.Query().Get("function")
		args := r.URL.Query()["args"]
		if chaincodeId == "" || channelId == "" || function == "" {
			http.Error(w, "Missing required query parameters", http.StatusBadRequest)
			return
		}
		session, _ := getSessionStore().Get(r, "fabric-session")
		key, ok := gatewayKeyFromSession(session)
		if !ok {
			http.Error(w, "Fabric client not initialized for this session. Call /client/ first.", http.StatusBadRequest)
			return
		}
		gateway, ok := GetGateway(key)
		if !ok {
			http.Error(w, "Fabric client not initialized for this session. Call /client/ first.", http.StatusBadRequest)
			return
		}
		reqBody := RequestBody{
			ChaincodeId: chaincodeId,
			ChannelId:   channelId,
			Function:    function,
			Args:        args,
		}
		QueryWithBody(w, reqBody, gateway)
		return
	}
	http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
}

// Handler for /client/ (initializes connection to Fabric blockchain)
func ClientHandler(w http.ResponseWriter, r *http.Request) {

	var clientRequestBody ClientRequestBody
	if err := json.NewDecoder(r.Body).Decode(&clientRequestBody); err != nil {
		http.Error(w, "Invalid OrgSetup: "+err.Error(), http.StatusBadRequest)
		return
	}
	session, _ := getSessionStore().Get(r, "fabric-session")
	if err := InitializeWithSession(clientRequestBody, session, w, r); err != nil {
		http.Error(w, "Error initializing org: "+err.Error(), http.StatusInternalServerError)
		return
	}
	w.WriteHeader(http.StatusOK)
	w.Write([]byte("Fabric client connection initialized successfully."))
}

// Handler for /client/close
func CloseHandler(w http.ResponseWriter, r *http.Request) {
	session, _ := getSessionStore().Get(r, "fabric-session")
	key, ok := gatewayKeyFromSession(session)
	if !ok {
		http.Error(w, "No active Fabric client connection for this session.", http.StatusBadRequest)
		return
	}
	gateway, ok := GetGateway(key)
	if !ok {
		http.Error(w, "No active Fabric client connection for this session.", http.StatusBadRequest)
		return
	}
	err := gateway.Close()
	if err != nil {
		http.Error(w, "Error closing Fabric client connection: "+err.Error(), http.StatusInternalServerError)
		return
	}
	RemoveGateway(key)
	delete(session.Values, gatewaySessionKey)
	session.Options.MaxAge = -1 // Invalidate session cookie
	session.Save(r, w)
	w.WriteHeader(http.StatusOK)
	w.Write([]byte("Fabric client connection closed successfully."))
}
