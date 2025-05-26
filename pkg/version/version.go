package version

import (
	"fmt"
)

const (
	LatestVersion = "v0.0.8"
)

var (
	Version   string
	BuildDate string
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
