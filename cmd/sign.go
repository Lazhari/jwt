package cmd

import (
	"crypto/rand"
	"encoding/json"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/spf13/cobra"
)

// signCmd represents the sign command
var signCmd = &cobra.Command{
	Use:   "sign",
	Short: "Sign a JWT token",
	Long:  `Sign a JWT token with the provided payload, key, and algorithm. Supports standard JWT claims.`,
	Run: func(cmd *cobra.Command, args []string) {
		payload, _ := cmd.Flags().GetString("payload")
		secret, _ := cmd.Flags().GetString("secret")
		alg, _ := cmd.Flags().GetString("alg")

		var method jwt.SigningMethod
		switch alg {
		case "HS256":
			method = jwt.SigningMethodHS256
		case "HS384":
			method = jwt.SigningMethodHS384
		case "HS512":
			method = jwt.SigningMethodHS512
		default:
			fmt.Println("Unsupported algorithm")
			return
		}

		claims := jwt.MapClaims{}
		err := json.Unmarshal([]byte(payload), &claims)
		if err != nil {
			fmt.Println("Invalid JSON payload:", err)
			return
		}

		iss, _ := cmd.Flags().GetString("iss")
		if iss != "" {
			claims["iss"] = iss
		}

		sub, _ := cmd.Flags().GetString("sub")
		if sub != "" {
			claims["sub"] = sub
		}

		aud, _ := cmd.Flags().GetStringSlice("aud")
		if len(aud) > 0 {
			if len(aud) == 1 {
				claims["aud"] = aud[0]
			} else {
				claims["aud"] = aud
			}
		}

		// Determine iat time
		var iatTime time.Time
		iatStr, _ := cmd.Flags().GetString("iat")
		noIat, _ := cmd.Flags().GetBool("no-iat")
		if !noIat {
			if iatStr == "" || iatStr == "now" {
				iatTime = time.Now()
				claims["iat"] = iatTime.Unix()
			} else {
				if strings.HasPrefix(iatStr, "+") || strings.HasPrefix(iatStr, "-") {
					sign := 1
					if strings.HasPrefix(iatStr, "-") {
						sign = -1
					}
					dur, err := parseDuration(iatStr[1:])
					if err != nil {
						fmt.Println("Invalid iat:", err)
						return
					}
					iatTime = time.Now().Add(time.Duration(sign) * dur)
				} else {
					iatUnix, err := parseTime(iatStr)
					if err != nil {
						fmt.Println("Invalid iat:", err)
						return
					}
					iatTime = time.Unix(iatUnix, 0)
				}
				claims["iat"] = iatTime.Unix()
			}
		} else {
			iatTime = time.Now()
		}

		expStr, _ := cmd.Flags().GetString("exp")
		if expStr != "" {
			if strings.HasPrefix(expStr, "+") || strings.HasPrefix(expStr, "-") {
				sign := 1
				if strings.HasPrefix(expStr, "-") {
					sign = -1
				}
				dur, err := parseDuration(expStr[1:])
				if err != nil {
					fmt.Println("Invalid exp:", err)
					return
				}
				expTime := iatTime.Add(time.Duration(sign) * dur)
				claims["exp"] = expTime.Unix()
			} else {
				expUnix, err := parseTime(expStr)
				if err != nil {
					fmt.Println("Invalid exp:", err)
					return
				}
				claims["exp"] = expUnix
			}
		}

		nbfStr, _ := cmd.Flags().GetString("nbf")
		if nbfStr != "" {
			if strings.HasPrefix(nbfStr, "+") || strings.HasPrefix(nbfStr, "-") {
				sign := 1
				if strings.HasPrefix(nbfStr, "-") {
					sign = -1
				}
				dur, err := parseDuration(nbfStr[1:])
				if err != nil {
					fmt.Println("Invalid nbf:", err)
					return
				}
				nbfTime := iatTime.Add(time.Duration(sign) * dur)
				claims["nbf"] = nbfTime.Unix()
			} else {
				nbfUnix, err := parseTime(nbfStr)
				if err != nil {
					fmt.Println("Invalid nbf:", err)
					return
				}
				claims["nbf"] = nbfUnix
			}
		}

		jtiStr, _ := cmd.Flags().GetString("jti")
		jtiAuto, _ := cmd.Flags().GetBool("jti-auto")
		if jtiAuto {
			if jtiStr != "" {
				fmt.Println("Cannot specify both --jti and --jti-auto")
				return
			}
			claims["jti"] = generateJTI()
		} else if jtiStr != "" {
			claims["jti"] = jtiStr
		}

		token := jwt.NewWithClaims(method, claims)
		tokenString, err := token.SignedString([]byte(secret))
		if err != nil {
			fmt.Println("Error signing token:", err)
			return
		}

		fmt.Println(tokenString)
	},
}

func init() {
	rootCmd.AddCommand(signCmd)

	signCmd.Flags().String("payload", "", "JSON payload to sign")
	signCmd.Flags().String("secret", "", "Secret key")
	signCmd.Flags().String("alg", "HS256", "Algorithm (HS256, HS384, HS512)")
	signCmd.Flags().String("iss", "", "Issuer")
	signCmd.Flags().String("sub", "", "Subject")
	signCmd.Flags().StringSlice("aud", []string{}, "Audience")
	signCmd.Flags().String("exp", "", "Expiration time (Unix timestamp, ISO 8601, or relative +1h +30m +7d)")
	signCmd.Flags().String("nbf", "", "Not Before time (Unix timestamp, ISO 8601, or relative +10m)")
	signCmd.Flags().String("iat", "", "Issued At time (now, Unix timestamp, or omit with --no-iat)")
	signCmd.Flags().Bool("no-iat", false, "Omit Issued At claim")
	signCmd.Flags().String("jti", "", "JWT ID")
	signCmd.Flags().Bool("jti-auto", false, "Auto generate JWT ID")
	signCmd.MarkFlagRequired("payload")
	signCmd.MarkFlagRequired("secret")
}

// parseDuration converts a human-friendly duration string to time.Duration.
// Supported formats: "7d" (days), "2h" (hours), "30m"/"30min" (minutes), "60s"/"60sec" (seconds).
// Returns an error if the format is invalid or the unit is not recognized.
func parseDuration(s string) (time.Duration, error) {
	var num int
	var unit string
	_, err := fmt.Sscanf(s, "%d%s", &num, &unit)
	if err != nil {
		return 0, fmt.Errorf("invalid format: %s", s)
	}
	var dur time.Duration
	switch unit {
	case "d":
		dur = time.Duration(num) * 24 * time.Hour
	case "h":
		dur = time.Duration(num) * time.Hour
	case "m", "min":
		dur = time.Duration(num) * time.Minute
	case "s", "sec":
		dur = time.Duration(num) * time.Second
	default:
		return 0, fmt.Errorf("unknown unit: %s", unit)
	}
	return dur, nil
}

// parseTime converts a time string to Unix timestamp (seconds since epoch).
// Supports two formats:
// - Unix timestamp: "1609459200"
// - ISO 8601 / RFC 3339: "2024-01-01T00:00:00Z" or "2024-01-01T00:00:00+02:00"
// Returns the Unix timestamp or an error if the format is not recognized.
func parseTime(s string) (int64, error) {
	// try Unix timestamp
	if unix, err := strconv.ParseInt(s, 10, 64); err == nil {
		return unix, nil
	}
	// try ISO 8601
	t, err := time.Parse(time.RFC3339, s)
	if err != nil {
		return 0, fmt.Errorf("invalid time format: %s", s)
	}
	return t.Unix(), nil
}

// generateJTI generates a UUID-style JWT ID (jti) claim value.
// Returns a string in the format: "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx" where x is a hex digit.
// Uses crypto/rand for cryptographically secure random number generation.
func generateJTI() string {
	b := make([]byte, 16)
	rand.Read(b)
	return fmt.Sprintf("%x-%x-%x-%x-%x", b[0:4], b[4:6], b[6:8], b[8:10], b[10:])
}
