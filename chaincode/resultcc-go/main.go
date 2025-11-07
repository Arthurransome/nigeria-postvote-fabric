package main

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"time"

	"github.com/hyperledger/fabric-contract-api-go/contractapi"
)

// Result represents a sealed polling-unit result recorded on-chain.
type Result struct {
	PUID         string         `json:"pu_id"`
	FormEC8AHash string         `json:"form_ec8a_hash"` // hex SHA-256 of EC8A (image/PDF)
	Snapshot     map[string]int `json:"snapshot"`       // e.g., {"APC":120,"PDP":100,"LP":80}
	UploaderMSP  string         `json:"uploader_msp"`
	UploaderID   string         `json:"uploader_id"`
	TimestampUTC string         `json:"timestamp_utc"`
	Sealed       bool           `json:"sealed"`
}

type SmartContract struct {
	contractapi.Contract
}

// CreateResult writes a new sealed result for a polling unit.
// PREVENTION: rejects overwrite (resultExists), enforces hash hygiene, seals immediately.
func (s *SmartContract) CreateResult(ctx contractapi.TransactionContextInterface, puID string, formHash string, snapshotJSON string) error {
	if puID == "" {
		return fmt.Errorf("puID is required")
	}

	exists, err := s.resultExists(ctx, puID)
	if err != nil {
		return err
	}
	if exists {
		return fmt.Errorf("result for %s already exists (overwrite not allowed)", puID)
	}

	// Expect a 64-char hex SHA-256 string
	if len(formHash) != 64 {
		return fmt.Errorf("form hash must be 64 hex chars (SHA-256)")
	}
	if _, err := hex.DecodeString(formHash); err != nil {
		return fmt.Errorf("form hash is not valid hex: %w", err)
	}

	var snapshot map[string]int
	if err := json.Unmarshal([]byte(snapshotJSON), &snapshot); err != nil {
		return fmt.Errorf("invalid snapshot JSON: %w", err)
	}

	mspID, _ := ctx.GetClientIdentity().GetMSPID()
	clientID, _ := ctx.GetClientIdentity().GetID()

	r := Result{
		PUID:         puID,
		FormEC8AHash: formHash,
		Snapshot:     snapshot,
		UploaderMSP:  mspID,
		UploaderID:   clientID,
		TimestampUTC: time.Now().UTC().Format(time.RFC3339),
		Sealed:       true,
	}

	b, _ := json.Marshal(r)
	if err := ctx.GetStub().PutState(puID, b); err != nil {
		return fmt.Errorf("putstate failed: %w", err)
	}

	// Event for monitoring/alerting
	if err := ctx.GetStub().SetEvent("ResultCreated", b); err != nil {
		return fmt.Errorf("set event failed: %w", err)
	}
	return nil
}

// GetResult returns the latest sealed result for a PU.
func (s *SmartContract) GetResult(ctx contractapi.TransactionContextInterface, puID string) (*Result, error) {
	b, err := ctx.GetStub().GetState(puID)
	if err != nil {
		return nil, fmt.Errorf("read error: %w", err)
	}
	if b == nil {
		return nil, fmt.Errorf("result for %s not found", puID)
	}
	var r Result
	if err := json.Unmarshal(b, &r); err != nil {
		return nil, fmt.Errorf("unmarshal error: %w", err)
	}
	return &r, nil
}

// GetResultHistory returns the full history for audit (DETECTION).
func (s *SmartContract) GetResultHistory(ctx contractapi.TransactionContextInterface, puID string) ([]map[string]interface{}, error) {
	it, err := ctx.GetStub().GetHistoryForKey(puID)
	if err != nil {
		return nil, err
	}
	defer it.Close()

	h := []map[string]interface{}{}
	for it.HasNext() {
		mod, err := it.Next()
		if err != nil {
			return nil, err
		}
		entry := map[string]interface{}{
			"tx_id":     mod.TxId,
			"timestamp": mod.Timestamp,
			"is_delete": mod.IsDelete,
			"value":     json.RawMessage(mod.Value),
		}
		h = append(h, entry)
	}
	return h, nil
}

// VerifyEC8AHash: given a base64 of file bytes, recompute SHA-256 and compare to on-chain hash.
// NOTE: For production you verify off-chain; this is for demos/tests only.
func (s *SmartContract) VerifyEC8AHash(ctx contractapi.TransactionContextInterface, puID string, docBase64 string) (bool, error) {
	data, err := base64.StdEncoding.DecodeString(docBase64)
	if err != nil {
		return false, fmt.Errorf("base64 decode error: %w", err)
	}
	sum := sha256.Sum256(data)
	onchain, err := s.GetResult(ctx, puID)
	if err != nil {
		return false, err
	}
	return hex.EncodeToString(sum[:]) == onchain.FormEC8AHash, nil
}

// helper
func (s *SmartContract) resultExists(ctx contractapi.TransactionContextInterface, puID string) (bool, error) {
	b, err := ctx.GetStub().GetState(puID)
	if err != nil {
		return false, err
	}
	return b != nil, nil
}

func main() {
	cc, err := contractapi.NewChaincode(new(SmartContract))
	if err != nil {
		panic(err)
	}
	if err := cc.Start(); err != nil {
		panic(err)
	}
}

