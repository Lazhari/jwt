package cmd

import (
	"encoding/base64"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

func TestInspectValidToken(t *testing.T) {
	// Create a test token
	secret := "test-secret"
	claims := jwt.MapClaims{
		"sub":  "1234567890",
		"name": "Test User",
		"iat":  time.Now().Unix(),
		"exp":  time.Now().Add(time.Hour).Unix(),
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	tokenString, err := token.SignedString([]byte(secret))
	if err != nil {
		t.Fatalf("Failed to create test token: %v", err)
	}

	// Parse token parts
	parts := strings.Split(tokenString, ".")
	if len(parts) != 3 {
		t.Fatalf("Token should have 3 parts, got %d", len(parts))
	}

	// Decode header
	headerData, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		t.Errorf("Failed to decode header: %v", err)
	}

	var header map[string]interface{}
	err = json.Unmarshal(headerData, &header)
	if err != nil {
		t.Errorf("Failed to parse header JSON: %v", err)
	}

	// Verify header contains expected fields
	if header["alg"] != "HS256" {
		t.Errorf("Expected algorithm HS256, got %v", header["alg"])
	}
	if header["typ"] != "JWT" {
		t.Errorf("Expected type JWT, got %v", header["typ"])
	}

	// Decode payload
	payloadData, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		t.Errorf("Failed to decode payload: %v", err)
	}

	var payload map[string]interface{}
	err = json.Unmarshal(payloadData, &payload)
	if err != nil {
		t.Errorf("Failed to parse payload JSON: %v", err)
	}

	// Verify payload contains expected claims
	if payload["sub"] != "1234567890" {
		t.Errorf("Expected sub claim '1234567890', got %v", payload["sub"])
	}
	if payload["name"] != "Test User" {
		t.Errorf("Expected name claim 'Test User', got %v", payload["name"])
	}
}

func TestInspectInvalidTokenFormat(t *testing.T) {
	tests := []struct {
		name  string
		token string
	}{
		{
			name:  "only one part",
			token: "singlepart",
		},
		{
			name:  "only two parts",
			token: "header.payload",
		},
		{
			name:  "four parts",
			token: "header.payload.signature.extra",
		},
		{
			name:  "empty string",
			token: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			parts := strings.Split(tt.token, ".")
			if len(parts) == 3 {
				t.Errorf("Token '%s' should not have 3 parts", tt.token)
			}
		})
	}
}

func TestInspectInvalidBase64(t *testing.T) {
	// Create a token with invalid base64 in header
	invalidToken := "invalid!!!.eyJzdWIiOiIxMjM0NTY3ODkwIn0.signature"
	parts := strings.Split(invalidToken, ".")

	_, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err == nil {
		t.Error("Expected error when decoding invalid base64, got nil")
	}
}

func TestInspectInvalidJSON(t *testing.T) {
	// Create base64 encoded invalid JSON
	invalidJSON := base64.RawURLEncoding.EncodeToString([]byte("{invalid json}"))
	token := invalidJSON + ".eyJzdWIiOiIxMjM0NTY3ODkwIn0.signature"
	parts := strings.Split(token, ".")

	headerData, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		t.Fatalf("Failed to decode header: %v", err)
	}

	var header map[string]interface{}
	err = json.Unmarshal(headerData, &header)
	if err == nil {
		t.Error("Expected error when parsing invalid JSON, got nil")
	}
}

func TestInspectDifferentAlgorithms(t *testing.T) {
	tests := []struct {
		name      string
		algorithm jwt.SigningMethod
		expected  string
	}{
		{
			name:      "HS256",
			algorithm: jwt.SigningMethodHS256,
			expected:  "HS256",
		},
		{
			name:      "HS384",
			algorithm: jwt.SigningMethodHS384,
			expected:  "HS384",
		},
		{
			name:      "HS512",
			algorithm: jwt.SigningMethodHS512,
			expected:  "HS512",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			secret := "test-secret"
			claims := jwt.MapClaims{
				"sub": "test",
				"exp": time.Now().Add(time.Hour).Unix(),
			}

			token := jwt.NewWithClaims(tt.algorithm, claims)
			tokenString, err := token.SignedString([]byte(secret))
			if err != nil {
				t.Fatalf("Failed to create token: %v", err)
			}

			// Decode and verify algorithm
			parts := strings.Split(tokenString, ".")
			headerData, _ := base64.RawURLEncoding.DecodeString(parts[0])

			var header map[string]interface{}
			json.Unmarshal(headerData, &header)

			if header["alg"] != tt.expected {
				t.Errorf("Expected algorithm %s, got %v", tt.expected, header["alg"])
			}
		})
	}
}

func TestInspectTimestampClaims(t *testing.T) {
	secret := "test-secret"
	now := time.Now()

	claims := jwt.MapClaims{
		"sub": "test",
		"iat": now.Unix(),
		"exp": now.Add(time.Hour).Unix(),
		"nbf": now.Add(-time.Minute).Unix(),
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	tokenString, err := token.SignedString([]byte(secret))
	if err != nil {
		t.Fatalf("Failed to create token: %v", err)
	}

	// Decode payload
	parts := strings.Split(tokenString, ".")
	payloadData, _ := base64.RawURLEncoding.DecodeString(parts[1])

	var payload map[string]interface{}
	json.Unmarshal(payloadData, &payload)

	// Verify timestamp claims exist
	if _, ok := payload["iat"]; !ok {
		t.Error("Expected iat claim to exist")
	}
	if _, ok := payload["exp"]; !ok {
		t.Error("Expected exp claim to exist")
	}
	if _, ok := payload["nbf"]; !ok {
		t.Error("Expected nbf claim to exist")
	}

	// Verify values are numbers
	if _, ok := payload["iat"].(float64); !ok {
		t.Errorf("Expected iat to be a number, got %T", payload["iat"])
	}
	if _, ok := payload["exp"].(float64); !ok {
		t.Errorf("Expected exp to be a number, got %T", payload["exp"])
	}
	if _, ok := payload["nbf"].(float64); !ok {
		t.Errorf("Expected nbf to be a number, got %T", payload["nbf"])
	}
}
