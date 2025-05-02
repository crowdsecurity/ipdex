package main

import (
	"github.com/crowdsecurity/ipdex/cmd/ipdex/style"
	"github.com/crowdsecurity/ipdex/pkg/version"

	"github.com/spf13/cobra"
)

func NewVersionCommand() *cobra.Command {
	cmd := &cobra.Command{
		Use:               "version",
		Short:             "Display version",
		Args:              cobra.NoArgs,
		DisableAutoGenTag: true,
		Run: func(_ *cobra.Command, _ []string) {
			style.Infof("version: %s", version.String())
		},
	}

	return cmd
}
