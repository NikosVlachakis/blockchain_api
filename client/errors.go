package client

import (
	"errors"
	"fmt"
	"strings"

	gwclient "github.com/hyperledger/fabric-gateway/pkg/client"
	"github.com/hyperledger/fabric-protos-go-apiv2/gateway"
	"google.golang.org/grpc/status"
)

// formatGatewayError returns a client-facing message that includes chaincode /
// peer ErrorDetail payloads when the gateway embeds them in the gRPC status.
func formatGatewayError(prefix string, err error) string {
	if err == nil {
		return prefix
	}
	details := extractErrorDetails(err)
	if len(details) == 0 {
		return fmt.Sprintf("%s: %v", prefix, err)
	}
	return fmt.Sprintf("%s: %v | details: %s", prefix, err, strings.Join(details, "; "))
}

func extractErrorDetails(err error) []string {
	var messages []string

	var endorseErr *gwclient.EndorseError
	var submitErr *gwclient.SubmitError
	var commitStatusErr *gwclient.CommitStatusError
	var commitErr *gwclient.CommitError
	switch {
	case errors.As(err, &endorseErr):
		messages = append(messages, detailMessagesFromStatus(endorseErr)...)
	case errors.As(err, &submitErr):
		messages = append(messages, detailMessagesFromStatus(submitErr)...)
	case errors.As(err, &commitStatusErr):
		messages = append(messages, detailMessagesFromStatus(commitStatusErr)...)
	case errors.As(err, &commitErr):
		messages = append(messages, fmt.Sprintf("commit code=%v tx=%s", commitErr.Code, commitErr.TransactionID))
		messages = append(messages, detailMessagesFromStatus(commitErr)...)
	default:
		messages = append(messages, detailMessagesFromStatus(err)...)
	}

	return uniqueNonEmpty(messages)
}

func detailMessagesFromStatus(err error) []string {
	st := status.Convert(err)
	if st == nil {
		return nil
	}
	var messages []string
	for _, detail := range st.Details() {
		switch d := detail.(type) {
		case *gateway.ErrorDetail:
			if d.Message != "" {
				messages = append(messages, d.Message)
			}
		}
	}
	return messages
}

func isMVCCConflict(err error) bool {
	if err == nil {
		return false
	}
	if strings.Contains(err.Error(), "MVCC_READ_CONFLICT") {
		return true
	}
	var commitErr *gwclient.CommitError
	if errors.As(err, &commitErr) {
		return strings.Contains(commitErr.Code.String(), "MVCC_READ_CONFLICT")
	}
	return false
}

func uniqueNonEmpty(in []string) []string {
	seen := make(map[string]struct{}, len(in))
	out := make([]string, 0, len(in))
	for _, s := range in {
		s = strings.TrimSpace(s)
		if s == "" {
			continue
		}
		if _, ok := seen[s]; ok {
			continue
		}
		seen[s] = struct{}{}
		out = append(out, s)
	}
	return out
}
