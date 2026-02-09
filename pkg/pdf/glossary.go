package pdf

// TermDefinition holds a term and its explanation
type TermDefinition struct {
	Term        string
	Definition  string
	Category    string
}

// ReputationDefinitions explains each reputation level
var ReputationDefinitions = []TermDefinition{
	{
		Term:       "Malicious",
		Definition: "Clear evidence of attacks from this IP (e.g., brute-force or exploitation). Treat as hostile and block if possible.",
		Category:   "Reputation",
	},
	{
		Term:       "Suspicious",
		Definition: "Signals of harmful behavior but not confirmed. Monitor closely and consider restricting.",
		Category:   "Reputation",
	},
	{
		Term:       "Known",
		Definition: "Seen by the CrowdSec network but not clearly malicious. Treat as neutral unless other signals exist.",
		Category:   "Reputation",
	},
	{
		Term:       "Safe",
		Definition: "Verified legitimate service (e.g., search engine or security scanner). Generally safe to allow.",
		Category:   "Reputation",
	},
	{
		Term:       "Unknown",
		Definition: "Not found in CrowdSec intelligence, so no reputation is available.",
		Category:   "Reputation",
	},
}

// ConfidenceDefinitions explains confidence levels
var ConfidenceDefinitions = []TermDefinition{
	{
		Term:       "High Confidence",
		Definition: "Many independent reports; classification is very reliable.",
		Category:   "Confidence",
	},
	{
		Term:       "Medium Confidence",
		Definition: "Several reports; likely accurate but still worth monitoring.",
		Category:   "Confidence",
	},
	{
		Term:       "Low Confidence",
		Definition: "Few reports or recent activity; classification may change.",
		Category:   "Confidence",
	},
}

// BehaviorDefinitions maps behavior labels to their explanations
var BehaviorDefinitions = map[string]string{
	// HTTP-related behaviors
	"http:exploit":        "Tried to exploit web-application vulnerabilities (e.g., SQL injection, XSS).",
	"http:scan":           "Scanned web servers to find open services or weaknesses.",
	"http:bruteforce":     "Tried many password guesses against a web login.",
	"http:crawl":          "Aggressively crawled pages, often to scrape or probe.",
	"http:spam":           "Sent spam via web forms or comments.",
	"http:backdoor":       "Attempted to access or install a backdoor on a web server.",
	"http:bad_user_agent": "Used suspicious user-agent strings common in attack tools.",

	// SSH-related behaviors
	"ssh:bruteforce": "Tried many password guesses against SSH.",
	"ssh:exploit":    "Attempted to exploit vulnerabilities in SSH services.",

	// Generic behaviors
	"generic:exploit":    "Attempted to exploit known vulnerabilities in various services.",
	"generic:scan":       "Scanned ports or services to identify targets.",
	"generic:bruteforce": "Tried many password guesses against a service.",

	// SMB-related behaviors
	"smb:bruteforce": "Tried many password guesses against SMB (Windows file sharing).",
	"smb:exploit":    "Attempted to exploit SMB vulnerabilities (e.g., EternalBlue).",

	// Mail-related behaviors
	"smtp:spam":       "Sent spam emails or attempted to relay spam.",
	"smtp:bruteforce": "Tried many password guesses against email accounts.",

	// Database behaviors
	"mysql:bruteforce":      "Tried many password guesses against MySQL.",
	"postgresql:bruteforce": "Tried many password guesses against PostgreSQL.",
	"mssql:bruteforce":      "Tried many password guesses against Microsoft SQL Server.",

	// VoIP behaviors
	"sip:bruteforce": "Tried many password guesses against VoIP (SIP).",

	// Other behaviors
	"ftp:bruteforce":    "Tried many password guesses against FTP.",
	"telnet:bruteforce": "Tried many password guesses against Telnet, often targeting IoT devices.",
	"rdp:bruteforce":    "Tried many password guesses against Windows Remote Desktop.",
	"dns:exploit":       "Attempted to exploit DNS services or perform DNS-based attacks.",
}

// KeyTermDefinitions explains other important terms
var KeyTermDefinitions = []TermDefinition{
	{
		Term:       "CVE",
		Definition: "Common Vulnerabilities and Exposures. A public ID for a known security bug; IPs tied to CVEs tried to exploit those bugs.",
		Category:   "Terms",
	},
	{
		Term:       "Blocklist",
		Definition: "A list of IPs to block at the firewall or edge, used to stop known bad actors.",
		Category:   "Terms",
	},
	{
		Term:       "Autonomous System (AS)",
		Definition: "A network operator identified by an AS number. Useful for understanding who owns an IP range.",
		Category:   "Terms",
	},
	{
		Term:       "IP Range",
		Definition: "A block of IPs owned by one organization; multiple bad IPs in a range can signal a compromised network.",
		Category:   "Terms",
	},
}

// GetRelevantBehaviors returns definitions only for behaviors present in the data
func GetRelevantBehaviors(behaviors map[string]int) []TermDefinition {
	var relevant []TermDefinition
	for behavior := range behaviors {
		if def, ok := BehaviorDefinitions[behavior]; ok {
			relevant = append(relevant, TermDefinition{
				Term:       behavior,
				Definition: def,
				Category:   "Behavior",
			})
		}
	}
	return relevant
}

// ShouldIncludeCVEDefinition checks if CVE definition should be included
func ShouldIncludeCVEDefinition(cves map[string]int) bool {
	return len(cves) > 0
}

// ShouldIncludeBlocklistDefinition checks if blocklist definition should be included
func ShouldIncludeBlocklistDefinition(blocklists map[string]int) bool {
	return len(blocklists) > 0
}

// ShouldIncludeASDefinition checks if AS definition should be included
func ShouldIncludeASDefinition(as map[string]int) bool {
	return len(as) > 0
}
