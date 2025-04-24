package utils

import (
	"fmt"
	"math/rand"
	"strings"
	"time"
)

func ParseDuration(s string) (time.Duration, error) {
	// Handle "d" for days manually
	if strings.HasSuffix(s, "d") {
		num := strings.TrimSuffix(s, "d")
		days, err := time.ParseDuration(num + "h")
		if err != nil {
			return 0, err
		}
		return days * 24, nil
	}

	// Fallback to standard Go parser
	return time.ParseDuration(s)
}

var words = []string{
	"Thunder", "Mystic", "Vortex", "Cyber", "Shadow", "Nebula", "Echo", "Blaze", "Titan", "Aurora",
	"Photon", "Pioneer", "Quantum", "Sentinel", "Zenith", "Nimbus", "Atlas", "Spectra", "Pulse", "Echo",
}

func GenerateRandomName() string {
	word1 := words[rand.Intn(len(words))]
	word2 := words[rand.Intn(len(words))]
	return fmt.Sprintf("%s-%s-Report", word1, word2)
}
