package client

import (
	"fmt"
	"log"
	"os"
	"strings"
	"time"

	"github.com/hyperledger/fabric-gateway/pkg/client"
)

// ProvisionPrivacyBudget ensures dataset query costs and a per-user budget exist
// for an enrolled identity. Uses an org admin identity from the keystore.
//
// Env (defaults match fabric scripts/budget.sh for local testing):
//
//	AUTO_PROVISION_BUDGET   - "true"/"false" (default "true")
//	BUDGET_ADMIN_ID         - admin enrollment id (default "admin0")
//	BUDGET_ADMIN_SECRET     - keystore secret for that admin (required when enabled)
//	SEED_DATASETS           - space-separated dataset ids (default "test-dataset")
//	SEED_QUERY_COST         - ε cost per LogQuery (default "0.1")
//	SEED_EPSILON            - total budget ε (default "10.0")
//	CHANNEL_ID / CHAINCODE_ID - fabric channel/chaincode (defaults dt4h / dt4hCC)
func ProvisionPrivacyBudget(userEnrollmentID, userSecret string) error {
	if !autoProvisionEnabled() {
		log.Printf("AUTO_PROVISION_BUDGET disabled; skipping budget provisioning for %s", userEnrollmentID)
		return nil
	}

	adminID := getEnvWithDefault("BUDGET_ADMIN_ID", "admin0")
	adminSecret := os.Getenv("BUDGET_ADMIN_SECRET")
	if adminSecret == "" {
		return fmt.Errorf("BUDGET_ADMIN_SECRET is required when AUTO_PROVISION_BUDGET is enabled")
	}

	channelID := getEnvWithDefault("CHANNEL_ID", "dt4h")
	chaincodeID := getEnvWithDefault("CHAINCODE_ID", "dt4hCC")
	datasets := strings.Fields(getEnvWithDefault("SEED_DATASETS", "test-dataset"))
	if len(datasets) == 0 {
		datasets = []string{"test-dataset"}
	}
	queryCost := getEnvWithDefault("SEED_QUERY_COST", "0.1")
	totalEpsilon := getEnvWithDefault("SEED_EPSILON", "10.0")

	adminGW, err := Initialize(adminID, adminSecret)
	if err != nil {
		return fmt.Errorf("admin gateway for budget provisioning: %w", err)
	}
	defer adminGW.Close()

	userGW, err := Initialize(userEnrollmentID, userSecret)
	if err != nil {
		return fmt.Errorf("user gateway for WhoAmI: %w", err)
	}
	defer userGW.Close()

	userContract := userGW.GetNetwork(channelID).GetContract(chaincodeID)
	whoAmIBytes, err := userContract.EvaluateTransaction("PrivacyBudgetContract:WhoAmI")
	if err != nil {
		return fmt.Errorf("WhoAmI for %s: %s", userEnrollmentID, formatGatewayError("evaluate", err))
	}
	userID := strings.Trim(string(whoAmIBytes), "\"")
	if userID == "" {
		return fmt.Errorf("WhoAmI returned empty user id for %s", userEnrollmentID)
	}

	adminContract := adminGW.GetNetwork(channelID).GetContract(chaincodeID)
	for _, dataset := range datasets {
		if err := invokeAdmin(adminContract, "PrivacyBudgetContract:SetDatasetQueryCost", dataset, queryCost); err != nil {
			if !isIgnorableProvisionError(err) {
				return fmt.Errorf("SetDatasetQueryCost(%s): %w", dataset, err)
			}
			log.Printf("SetDatasetQueryCost(%s) already configured or ignorable: %v", dataset, err)
		}
		if err := invokeAdmin(adminContract, "PrivacyBudgetContract:InitializeBudget", userID, dataset, totalEpsilon); err != nil {
			if !isIgnorableProvisionError(err) {
				return fmt.Errorf("InitializeBudget(%s,%s): %w", userID, dataset, err)
			}
			log.Printf("InitializeBudget(%s,%s) already exists or ignorable: %v", userID, dataset, err)
		}
		log.Printf("Provisioned privacy budget for %s on %s (cost=%s, total=%s)", userID, dataset, queryCost, totalEpsilon)
	}
	return nil
}

func autoProvisionEnabled() bool {
	v := strings.ToLower(strings.TrimSpace(os.Getenv("AUTO_PROVISION_BUDGET")))
	if v == "" {
		return true
	}
	return v == "true" || v == "1" || v == "yes"
}

func invokeAdmin(contract *client.Contract, function string, args ...string) error {
	const maxAttempts = 3
	var lastErr error
	for attempt := 1; attempt <= maxAttempts; attempt++ {
		proposal, err := contract.NewProposal(function, client.WithArguments(args...))
		if err != nil {
			return err
		}
		endorsed, err := proposal.Endorse()
		if err != nil {
			lastErr = err
			if isIgnorableProvisionError(err) {
				return err
			}
			if !isMVCCConflict(err) || attempt == maxAttempts {
				return fmt.Errorf("%s", formatGatewayError("endorse", err))
			}
			time.Sleep(time.Duration(attempt) * 200 * time.Millisecond)
			continue
		}
		committed, err := endorsed.Submit()
		if err != nil {
			lastErr = err
			if !isMVCCConflict(err) || attempt == maxAttempts {
				return fmt.Errorf("%s", formatGatewayError("submit", err))
			}
			time.Sleep(time.Duration(attempt) * 200 * time.Millisecond)
			continue
		}
		status, err := committed.Status()
		if err != nil {
			lastErr = err
			if !isMVCCConflict(err) || attempt == maxAttempts {
				return fmt.Errorf("%s", formatGatewayError("commit status", err))
			}
			time.Sleep(time.Duration(attempt) * 200 * time.Millisecond)
			continue
		}
		if !status.Successful {
			lastErr = fmt.Errorf("transaction %s failed to commit with status code %v", status.TransactionID, status.Code)
			if !isMVCCConflict(lastErr) || attempt == maxAttempts {
				return lastErr
			}
			time.Sleep(time.Duration(attempt) * 200 * time.Millisecond)
			continue
		}
		return nil
	}
	return lastErr
}

func isIgnorableProvisionError(err error) bool {
	if err == nil {
		return false
	}
	msg := strings.ToLower(err.Error())
	return strings.Contains(msg, "already exists") ||
		strings.Contains(msg, "budget already exists")
}
