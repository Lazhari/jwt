package cmd

import (
	"encoding/json"
	"fmt"
	"time"

	"github.com/charmbracelet/lipgloss"
	"github.com/charmbracelet/lipgloss/table"
	"github.com/golang-jwt/jwt/v5"
	"github.com/spf13/cobra"
)

// decodeCmd represents the decode command
var decodeCmd = &cobra.Command{
	Use:   "decode",
	Short: "Decode a JWT token",
	Long:  `Decode and verify a JWT token with the provided key.`,
	Run: func(cmd *cobra.Command, args []string) {
		if len(args) != 1 {
			fmt.Println("Usage: jwt decode <token>")
			return
		}

		tokenString := args[0]
		secret, _ := cmd.Flags().GetString("secret")

		token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
			return []byte(secret), nil
		})

		if err != nil {
			fmt.Println("Error parsing token:", err)
			return
		}

		if claims, ok := token.Claims.(jwt.MapClaims); ok {
			jsonFlag, _ := cmd.Flags().GetBool("json")
			if jsonFlag {
				// Output in JSON format
				headerJSON, _ := json.MarshalIndent(token.Header, "", "  ")
				fmt.Println("Header:")
				fmt.Println(string(headerJSON))

				payloadJSON, _ := json.MarshalIndent(claims, "", "  ")
				fmt.Println("Payload:")
				fmt.Println(string(payloadJSON))

				fmt.Println("Valid:", token.Valid)
			} else {
				// Print Header
				fmt.Println("Header:")
				headerTable := table.New().
					Border(lipgloss.NormalBorder()).
					BorderStyle(lipgloss.NewStyle().Foreground(lipgloss.Color("99"))).
					Headers("Key", "Value").
					StyleFunc(func(row, col int) lipgloss.Style {
						switch col {
						case 0:
							return lipgloss.NewStyle().Width(12)
						case 1:
							return lipgloss.NewStyle().Width(30)
						default:
							return lipgloss.NewStyle()
						}
					})
				for k, v := range token.Header {
					headerTable.Row(k, fmt.Sprintf("%v", v))
				}
				fmt.Println(headerTable.Render())

				// Print Payload
				fmt.Println("Payload:")
				payloadTable := table.New().
					Border(lipgloss.NormalBorder()).
					BorderStyle(lipgloss.NewStyle().Foreground(lipgloss.Color("99"))).
					Headers("Key", "Value").
					StyleFunc(func(row, col int) lipgloss.Style {
						switch col {
						case 0:
							return lipgloss.NewStyle().Width(12)
						case 1:
							return lipgloss.NewStyle().Width(30)
						default:
							return lipgloss.NewStyle()
						}
					})
				for k, v := range claims {
					var value string
					if k == "exp" || k == "iat" || k == "nbf" {
						if expFloat, ok := v.(float64); ok {
							expTime := time.Unix(int64(expFloat), 0)
							value = expTime.Format("2006-01-02 15:04:05 MST")
						} else {
							value = fmt.Sprintf("%v", v)
						}
					} else {
						value = fmt.Sprintf("%v", v)
					}
					payloadTable.Row(k, value)
				}
				fmt.Println(payloadTable.Render())

				fmt.Println("Valid:", token.Valid)
			}
		} else {
			fmt.Println("Invalid token")
		}
	},
}

func init() {
	rootCmd.AddCommand(decodeCmd)

	decodeCmd.Flags().String("secret", "", "Secret key for verification")
	decodeCmd.Flags().Bool("json", false, "Output in JSON format")
	decodeCmd.MarkFlagRequired("secret")
}
