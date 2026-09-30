package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"time"

	"blockchain-api/caapi"
	clientapi "blockchain-api/client"

	"blockchain-api/keystore"

	"github.com/gorilla/mux"
)

// IdentityInfo represents an identity to load
type IdentityInfo struct {
	Name         string `json:"name"`         // e.g., "admin0", "peer0", etc.
	Organization string `json:"organization"` // e.g., "bsc", "ub"
	Username     string `json:"username"`     // Combined name, e.g., "bsc-admin0"
	Password     string `json:"password"`     // Default password for testing
}

// StandardCredentials represents the structure of standard_credentials.json
type StandardCredentials struct {
	Organizations map[string]OrganizationCredentials `json:"organizations"`
}

// OrganizationCredentials represents credentials for a single organization
type OrganizationCredentials struct {
	Identities []IdentityInfo `json:"identities"`
}

func main() {
	// Initialize keystore
	keystoreType := os.Getenv("KEYSTORE_TYPE")
	if keystoreType == "" {
		keystoreType = "file" // Default to file-based keystore for tests
	}

	keystoreConfig := os.Getenv("KEYSTORE_CONFIG")
	if keystoreConfig == "" {
		// Default configuration for file-based keystore
		keystoreConfig = `{"basePath":"./keystore_data","salt":""}`
	}

	keystorePassword := os.Getenv("KEYSTORE_PASSWORD")
	if keystorePassword == "" {
		keystorePassword = "default_master_password" // Default for development
	}

	if err := keystore.InitializeKeystore(keystoreType, keystoreConfig, keystorePassword); err != nil {
		log.Fatalf("Failed to initialize keystore: %v", err)
	}
	log.Printf("Keystore initialized: type=%s, config=%s", keystoreType, keystoreConfig)

	// Load organization identities
	if err := LoadOrganizationIdentities(os.Getenv("ORG_NAME"), &keystore.GlobalKeystore); err != nil {
		log.Fatalf("Failed to load organization identities: %v", err)
	}

	r := mux.NewRouter()

	// Group under /client
	clientRouter := r.PathPrefix("/client").Subrouter()

	clientRouter.HandleFunc("/", clientapi.ClientHandler).Methods("POST")
	clientRouter.HandleFunc("/invoke", clientapi.InvokeHandler).Methods("POST")
	clientRouter.HandleFunc("/query", clientapi.QueryHandler).Methods("GET")
	clientRouter.HandleFunc("/close", clientapi.CloseHandler).Methods("GET")

	// Group under /fabricCA
	caRouter := r.PathPrefix("/fabricCA").Subrouter()
	caRouter.HandleFunc("/enroll", caapi.EnrollHandler).Methods("POST")
	caRouter.HandleFunc("/register", caapi.RegisterHandler).Methods("POST")
	caRouter.HandleFunc("/info", caapi.InfoHandler).Methods("POST")

	fmt.Println("Listening (http://localhost:3000/)...")

	go func() {
		time.Sleep(10 * time.Second) // Wait for server to be ready
		username := os.Getenv("BSC_TEST_USER")
		pwd := os.Getenv("BSC_TEST_PWD")
		if err := RegisterBSCUser(username, pwd); err != nil {
			log.Printf("Failed to register user: %v", err)
		}
	}()

	http.ListenAndServe(":3000", r)
}

// RegisterBSCUser registers a new user in the BSC organization using the CA API
// and then enrolls them to obtain their certificates.
// If the user is already registered with the CA, it loads their credentials from the identities folder.
func RegisterBSCUser(username, secret string) error {
	// Setup paths
	identitiesBasePath := os.Getenv("IDENTITIES_PATH")
	if identitiesBasePath == "" {
		identitiesBasePath = "./identities"
	}

	userIdentityPath := filepath.Join(identitiesBasePath, "bsc", username)
	keystoreDir := filepath.Join(userIdentityPath, "msp", "keystore")
	signcertsDir := filepath.Join(userIdentityPath, "msp", "signcerts")
	tlscacertsDir := filepath.Join(userIdentityPath, "msp", "tlscacerts")

	// Get admin credentials from environment or use defaults
	adminUsername := os.Getenv("BSC_REG_USERNAME")
	if adminUsername == "" {
		log.Panic("adminUsername empty")
	}

	adminPassword := os.Getenv("BSC_REG_PASSWORD")
	if adminPassword == "" {
		log.Panic("adminPassword empty")
	}

	// Get CA API URL
	apiURL := os.Getenv("BLOCKCHAIN_API_URL")
	if apiURL == "" {
		apiURL = "http://localhost:3000" // Default local URL
	}

	httpClient := &http.Client{Timeout: 30 * time.Second}

	// Step 1: Register the user
	log.Printf("Registering user %s in BSC organization...", username)

	regRequest := caapi.RegistrationRequest{
		AdminIdentity: caapi.AdminIdentity{
			EnrollmentID: adminUsername,
			Secret:       adminPassword,
		},
		UserRegistrationID: username,
		UserSecret:         secret,
		Type:               "client", // User type
	}

	regReqBody, err := json.Marshal(regRequest)
	if err != nil {
		return fmt.Errorf("failed to marshal registration request: %w", err)
	}

	regURL := fmt.Sprintf("%s/fabricCA/register", apiURL)
	regReq, err := http.NewRequest("POST", regURL, bytes.NewBuffer(regReqBody))
	if err != nil {
		return fmt.Errorf("failed to create registration request: %w", err)
	}
	regReq.Header.Set("Content-Type", "application/json")

	regResp, err := httpClient.Do(regReq)
	if err != nil {
		return fmt.Errorf("failed to send registration request: %w", err)
	}
	defer regResp.Body.Close()

	regBody, err := io.ReadAll(regResp.Body)
	if err != nil {
		return fmt.Errorf("failed to read registration response: %w", err)
	}

	// Check if registration failed because user already exists
	if regResp.StatusCode != http.StatusOK && regResp.StatusCode != http.StatusCreated {
		// Check if the error indicates user is already registered
		errorMsg := string(regBody)
		if bytes.Contains(regBody, []byte("already registered")) ||
			bytes.Contains(regBody, []byte("already exists")) ||
			(bytes.Contains(regBody, []byte("Identity")) && bytes.Contains(regBody, []byte("already registered"))) {
			log.Printf("User %s is already registered with CA, loading credentials from identities folder...", username)

			// Load credentials from files
			return loadExistingIdentity(username, secret, keystoreDir, signcertsDir, tlscacertsDir)
		}
		return fmt.Errorf("registration failed with status %d: %s", regResp.StatusCode, errorMsg)
	}

	var regResponse map[string]any
	if err := json.Unmarshal(regBody, &regResponse); err != nil {
		return fmt.Errorf("failed to parse registration response: %w", err)
	}

	if success, ok := regResponse["success"].(bool); !ok || !success {
		// Check if error message indicates already registered
		if errMsg, exists := regResponse["error"].(string); exists {
			if bytes.Contains([]byte(errMsg), []byte("already registered")) ||
				bytes.Contains([]byte(errMsg), []byte("already exists")) {
				log.Printf("User %s is already registered with CA, loading credentials from identities folder...", username)
				return loadExistingIdentity(username, secret, keystoreDir, signcertsDir, tlscacertsDir)
			}
		}
		return fmt.Errorf("registration failed: %v", regResponse)
	}

	log.Printf("✓ Successfully registered user %s in BSC organization", username)

	// Step 2: Enroll the user to get certificates
	log.Printf("Enrolling user %s to obtain certificates...", username)

	enrollRequest := caapi.EnrollmentRequest{
		EnrollmentID: username,
		Secret:       secret,
		CSRInfo: caapi.CSRInfo{
			CN: username,
			Names: []caapi.Name{
				{
					C:  "GR",
					ST: "Attica",
					L:  "Athens",
					O:  "bsc",
					OU: "client",
				},
			},
			Hosts: []string{"localhost", username + ".bsc.dt4h.com"},
		},
	}

	enrollReqBody, err := json.Marshal(enrollRequest)
	if err != nil {
		return fmt.Errorf("failed to marshal enrollment request: %w", err)
	}

	enrollURL := fmt.Sprintf("%s/fabricCA/enroll", apiURL)
	enrollReq, err := http.NewRequest("POST", enrollURL, bytes.NewBuffer(enrollReqBody))
	if err != nil {
		return fmt.Errorf("failed to create enrollment request: %w", err)
	}
	enrollReq.Header.Set("Content-Type", "application/json")

	enrollResp, err := httpClient.Do(enrollReq)
	if err != nil {
		return fmt.Errorf("failed to send enrollment request: %w", err)
	}
	defer enrollResp.Body.Close()

	enrollBody, err := io.ReadAll(enrollResp.Body)
	if err != nil {
		return fmt.Errorf("failed to read enrollment response: %w", err)
	}

	if enrollResp.StatusCode != http.StatusOK && enrollResp.StatusCode != http.StatusCreated {
		return fmt.Errorf("enrollment failed with status %d: %s", enrollResp.StatusCode, string(enrollBody))
	}

	var enrollResponse map[string]interface{}
	if err := json.Unmarshal(enrollBody, &enrollResponse); err != nil {
		return fmt.Errorf("failed to parse enrollment response: %w", err)
	}

	if success, ok := enrollResponse["success"].(bool); !ok || !success {
		return fmt.Errorf("enrollment failed: %v", enrollResponse)
	}

	// Step 3: Extract certificate and private key from keystore and save to files
	log.Printf("Saving certificates to identity files for %s...", username)

	// Retrieve the stored identity from keystore
	keystoreEntry, err := keystore.GlobalKeystore.RetrieveKey(username, secret)
	if err != nil {
		return fmt.Errorf("failed to retrieve enrolled identity from keystore: %w", err)
	}

	// Create directory structure: identities/bsc/<username>/msp/{keystore,signcerts,tlscacerts}
	// Create all directories
	for _, dir := range []string{keystoreDir, signcertsDir, tlscacertsDir} {
		if err := os.MkdirAll(dir, 0755); err != nil {
			return fmt.Errorf("failed to create directory %s: %w", dir, err)
		}
	}

	// Write private key to keystore/key.pem
	privateKeyPath := filepath.Join(keystoreDir, "key.pem")
	if err := os.WriteFile(privateKeyPath, keystoreEntry.PrivateKey, 0600); err != nil {
		return fmt.Errorf("failed to write private key: %w", err)
	}

	// Write certificate to signcerts/cert.pem
	certificatePath := filepath.Join(signcertsDir, "cert.pem")
	if err := os.WriteFile(certificatePath, keystoreEntry.Certificate, 0644); err != nil {
		return fmt.Errorf("failed to write certificate: %w", err)
	}

	// Write TLS CA certificate to tlscacerts/cert.pem
	if len(keystoreEntry.TLSCertificate) > 0 {
		tlsCertPath := filepath.Join(tlscacertsDir, "cert.pem")
		if err := os.WriteFile(tlsCertPath, keystoreEntry.TLSCertificate, 0644); err != nil {
			return fmt.Errorf("failed to write TLS CA certificate: %w", err)
		}
	}

	log.Printf("✓ Successfully enrolled user %s - certificates obtained and stored", username)
	log.Printf("✓ Identity files saved to: %s", userIdentityPath)
	log.Printf("✓ User %s is ready to use in BSC organization", username)

	// EnrollHandler already provisions on the enroll HTTP path; call again for
	// the case where enroll was handled elsewhere or auto-provision was skipped.
	if err := clientapi.ProvisionPrivacyBudget(username, secret); err != nil {
		return fmt.Errorf("privacy budget provisioning for %s: %w", username, err)
	}

	return nil
}

// LoadOrganizationIdentities loads all identities for a given organization into the file keystore
func LoadOrganizationIdentities(organization string, keystore *keystore.KeystoreManager) error {
	// Read credentials from JSON file
	credentialsPath := os.Getenv("CREDENTIALS_FILE")
	if credentialsPath == "" {
		credentialsPath = "./standard_credentials.json" // Default path
	}

	credentialsData, err := os.ReadFile(credentialsPath)
	if err != nil {
		return fmt.Errorf("failed to read credentials file %s: %w", credentialsPath, err)
	}

	var credentials StandardCredentials
	if err := json.Unmarshal(credentialsData, &credentials); err != nil {
		return fmt.Errorf("failed to parse credentials JSON: %w", err)
	}

	// Get identities for the specified organization
	orgCreds, exists := credentials.Organizations[organization]
	if !exists {
		return fmt.Errorf("organization %s not found in credentials file", organization)
	}

	identities := orgCreds.Identities
	if len(identities) == 0 {
		return fmt.Errorf("no identities found for organization %s", organization)
	}

	fmt.Printf("Loading identities for organization: %s\n", organization)

	// Load each identity
	for _, identity := range identities {
		fmt.Printf("Loading identity: %s\n", identity.Username)

		if err := loadIdentity(keystore, identity); err != nil {
			log.Printf("Failed to load identity %s: %v", identity.Username, err)
			continue
		}

		fmt.Printf("✓ Successfully loaded identity: %s\n", identity.Username)
	}

	fmt.Printf("\nIdentity loading completed for organization: %s\n", organization)

	// Verify loaded identities
	fmt.Printf("\nVerifying loaded identities for %s:\n", organization)
	for _, identity := range identities {
		entry, err := (*keystore).RetrieveKey(identity.Username, identity.Password)
		if err != nil {
			log.Printf("❌ Failed to verify identity %s: %v", identity.Username, err)
			continue
		}
		fmt.Printf("✓ Verified identity: %s (EnrollmentID: %s)\n", identity.Username, entry.EnrollmentID)
	}
	return nil
}

// loadExistingIdentity loads an already registered user's credentials from the identities folder
func loadExistingIdentity(username, secret, keystoreDir, signcertsDir, tlscacertsDir string) error {
	// Find private key using *.pem pattern
	privateKeyFiles, err := filepath.Glob(filepath.Join(keystoreDir, "*.pem"))
	if err != nil {
		return fmt.Errorf("failed to search for private key: %w", err)
	}
	if len(privateKeyFiles) == 0 {
		return fmt.Errorf("user %s is already registered but no private key found in %s", username, keystoreDir)
	}
	privateKeyPath := privateKeyFiles[0] // Use first .pem file found

	// Find certificate using *.pem pattern
	certificateFiles, err := filepath.Glob(filepath.Join(signcertsDir, "*.pem"))
	if err != nil {
		return fmt.Errorf("failed to search for certificate: %w", err)
	}
	if len(certificateFiles) == 0 {
		return fmt.Errorf("user %s is already registered but no certificate found in %s", username, signcertsDir)
	}
	certificatePath := certificateFiles[0]

	// Find TLS certificate using *.pem pattern (optional)
	tlsCertFiles, err := filepath.Glob(filepath.Join(tlscacertsDir, "*.pem"))
	if err != nil {
		return fmt.Errorf("failed to search for TLS certificate: %w", err)
	}

	// Read existing private key
	privateKeyPEM, err := os.ReadFile(privateKeyPath)
	if err != nil {
		return fmt.Errorf("failed to read existing private key: %w", err)
	}

	// Read existing certificate
	certificatePEM, err := os.ReadFile(certificatePath)
	if err != nil {
		return fmt.Errorf("failed to read existing certificate: %w", err)
	}

	// Read existing TLS certificate if found
	var tlsCertificatePEM []byte
	if len(tlsCertFiles) > 0 {
		tlsCertificatePEM, err = os.ReadFile(tlsCertFiles[0])
		if err != nil {
			log.Printf("Warning: failed to read TLS certificate: %v", err)
			tlsCertificatePEM = []byte{} // Use empty if failed
		}
	} else {
		tlsCertificatePEM = []byte{} // Use empty if not found
	}

	// Store in keystore
	if err := keystore.GlobalKeystore.StoreKey(username, secret, privateKeyPEM, certificatePEM, tlsCertificatePEM); err != nil {
		return fmt.Errorf("failed to store existing identity in keystore: %w", err)
	}

	log.Printf("✓ Successfully loaded existing identity for user %s from identities folder", username)
	log.Printf("✓ User %s is ready to use in BSC organization", username)

	if err := clientapi.ProvisionPrivacyBudget(username, secret); err != nil {
		return fmt.Errorf("privacy budget provisioning for %s: %w", username, err)
	}
	return nil
}

func loadIdentity(ks *keystore.KeystoreManager, identity IdentityInfo) error {
	// Build paths to identity directories
	basePath := filepath.Join("/app", "identities", identity.Organization, identity.Name)
	keystoreDir := filepath.Join(basePath, "msp", "keystore")
	signcertsDir := filepath.Join(basePath, "msp", "signcerts")

	// TLS CA certificate path: identities/{orgname}/{orgname}TLS-root-cert/
	tlsRootCertDir := filepath.Join("/app", "identities", identity.Organization, identity.Organization+"TLS-root-cert")

	// Find private key using *.pem pattern
	privateKeyFiles, err := filepath.Glob(filepath.Join(keystoreDir, "*.pem"))
	if err != nil {
		return fmt.Errorf("failed to search for private key: %w", err)
	}
	if len(privateKeyFiles) == 0 {
		return fmt.Errorf("no private key found in %s", keystoreDir)
	}
	privateKeyPath := privateKeyFiles[0] // Use first .pem file found

	// Find certificate using *.pem pattern
	certificateFiles, err := filepath.Glob(filepath.Join(signcertsDir, "*.pem"))
	if err != nil {
		return fmt.Errorf("failed to search for certificate: %w", err)
	}
	if len(certificateFiles) == 0 {
		return fmt.Errorf("no certificate found in %s", signcertsDir)
	}
	certificatePath := certificateFiles[0]

	// Find TLS CA certificate using *.pem pattern from root cert directory
	tlsCertFiles, err := filepath.Glob(filepath.Join(tlsRootCertDir, "*.pem"))
	if err != nil {
		return fmt.Errorf("failed to search for TLS CA certificate: %w", err)
	}

	// Read private key
	privateKeyPEM, err := readFile(privateKeyPath)
	if err != nil {
		return fmt.Errorf("failed to read private key: %w", err)
	}

	// Read certificate
	certificatePEM, err := readFile(certificatePath)
	if err != nil {
		return fmt.Errorf("failed to read certificate: %w", err)
	}

	// Read TLS CA certificate if found
	var tlsCertificatePEM []byte
	if len(tlsCertFiles) > 0 {
		tlsCertificatePEM, err = readFile(tlsCertFiles[0])
		if err != nil {
			log.Printf("Warning: failed to read TLS CA certificate for %s: %v", identity.Username, err)
			tlsCertificatePEM = []byte{} // Use empty if failed
		}
	} else {
		log.Printf("Warning: no TLS CA certificate found in %s for %s", tlsRootCertDir, identity.Username)
		tlsCertificatePEM = []byte{} // Use empty if not found
	}

	// Store in keystore
	return (*ks).StoreKey(identity.Username, identity.Password, privateKeyPEM, certificatePEM, tlsCertificatePEM)
}

func readFile(path string) ([]byte, error) {
	content, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("failed to open file %s: %w", path, err)
	}
	return content, nil
}
