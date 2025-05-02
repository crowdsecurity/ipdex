package version

import (
	"fmt"
)

const (
	LatestVersion = "v0.0.5"
)

var (
	Version   string // = "v0.0.0"
	BuildDate string // = "2023-03-06_09:55:34"
	Commit    string
)

func FullString() string {
	ret := fmt.Sprintf("version: %s\n", String())
	return ret
}

func String() string {
	if Version == "" {
		Version = LatestVersion
	}
	return Version
}
