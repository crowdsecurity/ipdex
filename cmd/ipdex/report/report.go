package report

import (
	"github.com/spf13/cobra"
)

func NewReportCommand() *cobra.Command {
	var parserCmd = &cobra.Command{
		Use:     "report",
		Short:   "List/Inspect and delete reports",
		Aliases: []string{"reports"},
	}

	parserCmd.AddCommand(NewListCommand(), NewShowCommand())

	return parserCmd
}
