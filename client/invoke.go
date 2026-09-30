package client

import (
	"fmt"
	"net/http"
	"time"

	"github.com/hyperledger/fabric-gateway/pkg/client"
)

const invokeMaxAttempts = 3

// InvokeWithBody handles chaincode invoke requests with a pre-parsed RequestBody.
// It waits for commit status before reporting success, retries briefly on
// MVCC_READ_CONFLICT, and surfaces gateway/chaincode error details to the client.
func InvokeWithBody(w http.ResponseWriter, reqBody RequestBody, gateway *client.Gateway) {
	w.Header().Set("Content-Type", "text/plain")
	fmt.Println("Received Invoke request")

	var lastErr error
	for attempt := 1; attempt <= invokeMaxAttempts; attempt++ {
		txID, result, err := endorseAndCommit(gateway, reqBody)
		if err == nil {
			fmt.Fprintf(w, "Transaction ID : %s Response: %s", txID, result)
			return
		}
		lastErr = err
		if !isMVCCConflict(err) || attempt == invokeMaxAttempts {
			http.Error(w, formatGatewayError("Error invoking transaction", err), http.StatusBadRequest)
			return
		}
		fmt.Printf("MVCC conflict on attempt %d/%d; retrying: %v\n", attempt, invokeMaxAttempts, err)
		time.Sleep(time.Duration(attempt) * 200 * time.Millisecond)
	}
	http.Error(w, formatGatewayError("Error invoking transaction", lastErr), http.StatusBadRequest)
}

func endorseAndCommit(gateway *client.Gateway, reqBody RequestBody) (string, []byte, error) {
	network := gateway.GetNetwork(reqBody.ChannelId)
	contract := network.GetContract(reqBody.ChaincodeId)

	txnProposal, err := contract.NewProposal(reqBody.Function, client.WithArguments(reqBody.Args...))
	if err != nil {
		return "", nil, fmt.Errorf("creating txn proposal: %w", err)
	}
	txnEndorsed, err := txnProposal.Endorse()
	if err != nil {
		return "", nil, fmt.Errorf("endorsing txn: %w", err)
	}
	txnCommitted, err := txnEndorsed.Submit()
	if err != nil {
		return "", nil, fmt.Errorf("submitting transaction: %w", err)
	}

	status, err := txnCommitted.Status()
	if err != nil {
		return txnCommitted.TransactionID(), nil, fmt.Errorf("commit status for %s: %w", txnCommitted.TransactionID(), err)
	}
	if !status.Successful {
		return status.TransactionID, nil, fmt.Errorf(
			"transaction %s failed to commit with status code %v",
			status.TransactionID,
			status.Code,
		)
	}
	return status.TransactionID, txnEndorsed.Result(), nil
}
