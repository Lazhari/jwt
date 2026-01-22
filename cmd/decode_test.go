package cmd

import (
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

func TestDecodeValidToken(t *testing.T) {
	// Create a valid test token
	secret := "test-secret-key"
	claims := jwt.MapClaims{
		"sub": "1234567890",
		"name": "John Doe",
		"iat": time.Now().Unix(),
		"exp": time.Now().Add(time.Hour).Unix(),
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	tokenString, err := token.SignedString([]byte(secret))
	if err != nil {
		t.Fatalf("Failed to create test token: %v", err)
	}

	// Parse the token
	parsedToken, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
		return []byte(secret), nil
	})

	if err != nil {
		t.Errorf("Failed to parse valid token: %v", err)
	}

	if !parsedToken.Valid {
		t.Error("Token should be valid but was marked invalid")
	}

	// Verify claims
	if parsedClaims, ok := parsedToken.Claims.(jwt.MapClaims); ok {
		if parsedClaims["sub"] != "1234567890" {
			t.Errorf("Expected sub claim to be '1234567890', got %v", parsedClaims["sub"])
		}
		if parsedClaims["name"] != "John Doe" {
			t.Errorf("Expected name claim to be 'John Doe', got %v", parsedClaims["name"])
		}
	} else {
		t.Error("Failed to extract claims from token")
	}
}

func TestDecodeInvalidToken(t *testing.T) {
	secret := "test-secret-key"
	invalidToken := "invalid.token.string"

	_, err := jwt.Parse(invalidToken, func(token *jwt.Token) (interface{}, error) {
		return []byte(secret), nil
	})

	if err == nil {
		t.Error("Expected error when parsing invalid token, got nil")
	}
}

func TestDecodeTokenWithWrongSecret(t *testing.T) {
	// Create token with one secret
	correctSecret := "correct-secret"
	wrongSecret := "wrong-secret"

	claims := jwt.MapClaims{
		"sub": "test",
		"exp": time.Now().Add(time.Hour).Unix(),
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	tokenString, err := token.SignedString([]byte(correctSecret))
	if err != nil {
		t.Fatalf("Failed to create test token: %v", err)
	}

	// Try to parse with wrong secret
	parsedToken, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
		return []byte(wrongSecret), nil
	})

	if err == nil {
		t.Error("Expected error when using wrong secret, got nil")
	}

	if parsedToken != nil && parsedToken.Valid {
		t.Error("Token should not be valid with wrong secret")
	}
}

func TestDecodeExpiredToken(t *testing.T) {
	secret := "test-secret-key"

	// Create an expired token
	claims := jwt.MapClaims{
		"sub": "test",
		"exp": time.Now().Add(-time.Hour).Unix(), // Expired 1 hour ago
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	tokenString, err := token.SignedString([]byte(secret))
	if err != nil {
		t.Fatalf("Failed to create test token: %v", err)
	}

	// Parse the expired token
	parsedToken, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
		return []byte(secret), nil
	})

	// jwt.Parse should return an error for expired tokens
	if err == nil {
		t.Error("Expected error for expired token, got nil")
	}

	if parsedToken != nil && parsedToken.Valid {
		t.Error("Expired token should not be valid")
	}
}

func TestDecodeTokenWithDifferentAlgorithms(t *testing.T) {
	tests := []struct {
		name      string
		algorithm jwt.SigningMethod
		secret    string
	}{
		{
			name:      "HS256",
			algorithm: jwt.SigningMethodHS256,
			secret:    "test-secret-hs256",
		},
		{
			name:      "HS384",
			algorithm: jwt.SigningMethodHS384,
			secret:    "test-secret-hs384",
		},
		{
			name:      "HS512",
			algorithm: jwt.SigningMethodHS512,
			secret:    "test-secret-hs512",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			claims := jwt.MapClaims{
				"sub": "test",
				"exp": time.Now().Add(time.Hour).Unix(),
			}

			token := jwt.NewWithClaims(tt.algorithm, claims)
			tokenString, err := token.SignedString([]byte(tt.secret))
			if err != nil {
				t.Fatalf("Failed to create token with %s: %v", tt.name, err)
			}

			// Parse the token
			parsedToken, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
				return []byte(tt.secret), nil
			})

			if err != nil {
				t.Errorf("Failed to parse token with %s: %v", tt.name, err)
			}

			if !parsedToken.Valid {
				t.Errorf("Token with %s should be valid", tt.name)
			}

			// Verify algorithm in header
			if parsedToken.Method.Alg() != tt.algorithm.Alg() {
				t.Errorf("Expected algorithm %s, got %s", tt.algorithm.Alg(), parsedToken.Method.Alg())
			}
		})
	}
}
