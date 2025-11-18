package cmd

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/charmbracelet/lipgloss"
	"github.com/charmbracelet/lipgloss/table"
	"github.com/spf13/cobra"
)

// inspectCmd represents the inspect command
var inspectCmd = &cobra.Command{
	Use:   "inspect [token]",
	Short: "Inspect JWT token without verification",
	Long:  `Decode and display header and payload of a JWT token without verifying the signature.`,
	Run: func(cmd *cobra.Command, args []string) {
		if len(args) != 1 {
			fmt.Println("Usage: jwt inspect <token>")
			return
		}

		token := args[0]
		parts := strings.Split(token, ".")
		if len(parts) != 3 {
			fmt.Println("Invalid JWT token")
			return
		}

		// Decode header
		headerData, err := base64.RawURLEncoding.DecodeString(parts[0])
		if err != nil {
			fmt.Println("Error decoding header:", err)
			return
		}
		var header map[string]interface{}
		err = json.Unmarshal(headerData, &header)
		if err != nil {
			fmt.Println("Error parsing header:", err)
			return
		}

		// Decode payload
		payloadData, err := base64.RawURLEncoding.DecodeString(parts[1])
		if err != nil {
			fmt.Println("Error decoding payload:", err)
			return
		}
		var payload map[string]interface{}
		err = json.Unmarshal(payloadData, &payload)
		if err != nil {
			fmt.Println("Error parsing payload:", err)
			return
		}

		jsonFlag, _ := cmd.Flags().GetBool("json")
		if jsonFlag {
			// Output in JSON format
			headerJSON, _ := json.MarshalIndent(header, "", "  ")
			fmt.Println("Header:")
			fmt.Println(string(headerJSON))

			payloadJSON, _ := json.MarshalIndent(payload, "", "  ")
			fmt.Println("Payload:")
			fmt.Println(string(payloadJSON))

			fmt.Println("Signature:", parts[2])
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
			for k, v := range header {
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
			for k, v := range payload {
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

			fmt.Println("Signature:", parts[2])
		}
	},
}

func init() {
	rootCmd.AddCommand(inspectCmd)

	inspectCmd.Flags().Bool("json", false, "Output in JSON format")
}
