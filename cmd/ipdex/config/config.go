package config

import (
	"github.com/spf13/cobra"
)

func NewConfigCmd() *cobra.Command {
	var configCmd = &cobra.Command{
		Use:   "config",
		Short: "Configure",
	}

	configCmd.AddCommand(NewShowCmd(), NewSetCmd())

	return configCmd
}
