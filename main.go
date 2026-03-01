package main

import (
	"crypto/tls"
	"encoding/json"
	"encoding/xml"
	"flag"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"regexp"
	"strings"
	"sync"
	"time"
)

const version = "1.0.0"

// ─── ANSI Colors ─────────────────────────────────────────────────────────────

const (
	cRed    = "\033[31m"
	cYellow = "\033[33m"
	cGreen  = "\033[32m"
	cCyan   = "\033[36m"
	cBold   = "\033[1m"
	cDim    = "\033[2m"
	cReset  = "\033[0m"
)

// ─── S3 XML Structs ───────────────────────────────────────────────────────────

type ListBucketResult struct {
	XMLName     xml.Name   `xml:"ListBucketResult"`
	Name        string     `xml:"Name"`
	IsTruncated bool       `xml:"IsTruncated"`
	Contents    []S3Object `xml:"Contents"`
}

type S3Object struct {
	Key  string `xml:"Key"  json:"key"`
	Size int64  `xml:"Size" json:"size"`
}

// ─── Finding ──────────────────────────────────────────────────────────────────

type Finding struct {
	URL      string     `json:"url"`
	Source   string     `json:"source"`
	Provider string     `json:"provider"`
	CanList  bool       `json:"can_list"`
	CanRead  bool       `json:"can_read"`
	CanWrite bool       `json:"can_write"`
	Objects  []S3Object `json:"objects"`
}

func (f Finding) Severity() string {
	switch {
	case f.CanWrite:
		return "CRITICAL"
	case f.CanRead && f.CanList:
		return "HIGH"
	case f.CanList:
		return "MEDIUM"
	default:
		return "INFO"
	}
}

func (f Finding) SeverityColored() string {
	switch f.Severity() {
	case "CRITICAL":
		return cRed + cBold + "[CRITICAL]" + cReset
	case "HIGH":
		return cRed + "[HIGH]" + cReset
	case "MEDIUM":
		return cYellow + "[MEDIUM]" + cReset
	default:
		return cDim + "[INFO]" + cReset
	}
}

// ─── HTTP Client ──────────────────────────────────────────────────────────────

var httpClient = &http.Client{
	Timeout: 8 * time.Second,
	CheckRedirect: func(req *http.Request, via []*http.Request) error {
		return http.ErrUseLastResponse
	},
	Transport: &http.Transport{
		TLSClientConfig:     &tls.Config{InsecureSkipVerify: true},
		DisableKeepAlives:   false,
		MaxIdleConnsPerHost: 20,
	},
}

// ─── Patterns ─────────────────────────────────────────────────────────────────

// s3URLPatterns match S3-compatible storage URLs found in HTML/JS
var s3URLPatterns = []*regexp.Regexp{
	// AWS virtual-hosted:  bucket.s3.amazonaws.com  |  bucket.s3.region.amazonaws.com
	regexp.MustCompile(`https?://[a-z0-9][a-z0-9._-]*\.s3(?:\.[a-z0-9-]+)?\.amazonaws\.com`),
	// AWS path-style:      s3.amazonaws.com/bucket  |  s3.region.amazonaws.com/bucket
	regexp.MustCompile(`https?://s3(?:\.[a-z0-9-]+)?\.amazonaws\.com/[a-z0-9][a-z0-9._-]*`),
	// Scaleway virtual:    bucket.s3.fr-par.scw.cloud
	regexp.MustCompile(`https?://[a-z0-9][a-z0-9._-]*\.s3\.[a-z]+-[a-z]+\.scw\.cloud`),
	// Scaleway path-style: s3.fr-par.scw.cloud/bucket
	regexp.MustCompile(`https?://s3\.[a-z]+-[a-z]+\.scw\.cloud/[a-z0-9][a-z0-9._-]*`),
	// GCS virtual:         bucket.storage.googleapis.com
	regexp.MustCompile(`https?://[a-z0-9][a-z0-9._-]*\.storage\.googleapis\.com`),
	// GCS path-style:      storage.googleapis.com/bucket
	regexp.MustCompile(`https?://storage\.googleapis\.com/[a-z0-9][a-z0-9._-]*`),
	// DigitalOcean Spaces: bucket.region.digitaloceanspaces.com
	regexp.MustCompile(`https?://[a-z0-9][a-z0-9._-]*\.[a-z0-9-]+\.digitaloceanspaces\.com`),
	// Backblaze B2:        bucket.s3.region.backblazeb2.com
	regexp.MustCompile(`https?://[a-z0-9][a-z0-9._-]*\.s3\.[a-z0-9-]+\.backblazeb2\.com`),
}

// s3CNAMEPatterns detect S3 CNAME targets in DNS responses
var s3CNAMEPatterns = []*regexp.Regexp{
	regexp.MustCompile(`\.s3(?:[.-][a-z0-9-]+)?\.amazonaws\.com\.?$`),
	regexp.MustCompile(`\.s3\.[a-z]+-[a-z]+\.scw\.cloud\.?$`),
	regexp.MustCompile(`\.storage\.googleapis\.com\.?$`),
	regexp.MustCompile(`\.[a-z0-9-]+\.digitaloceanspaces\.com\.?$`),
	regexp.MustCompile(`\.backblazeb2\.com\.?$`),
}

// providerFromURL returns a human-readable provider name
var providerFromURL = []struct {
	pattern  *regexp.Regexp
	provider string
}{
	{regexp.MustCompile(`amazonaws\.com`), "AWS S3"},
	{regexp.MustCompile(`scw\.cloud`), "Scaleway"},
	{regexp.MustCompile(`googleapis\.com`), "GCS"},
	{regexp.MustCompile(`digitaloceanspaces\.com`), "DigitalOcean Spaces"},
	{regexp.MustCompile(`backblazeb2\.com`), "Backblaze B2"},
}

// ─── Wordlists ────────────────────────────────────────────────────────────────

var commonSubdomains = []string{
	"assets", "media", "static", "cdn", "files", "uploads", "storage",
	"backup", "data", "public", "shared", "content", "images", "img",
	"docs", "downloads", "resources", "ops", "stg", "staging", "dev",
	"prod", "s3", "bucket", "archive", "store", "objects", "blobs",
	"blob", "file", "upload", "image", "video", "audio", "release",
	"releases", "artifacts", "logs", "report", "reports", "export",
}

var bucketSuffixes = []string{
	"", "-public", "-private", "-assets", "-media", "-uploads",
	"-static", "-shared", "-data", "-backup", "-prod", "-staging",
	"-dev", "-storage", "-files", "-images", "-cdn", "-content",
	"-releases", "-artifacts", "-logs", ".public", ".shared", ".assets",
}

var scwRegions = []string{"fr-par", "nl-ams", "pl-waw"}
var awsRegions = []string{"us-east-1", "us-west-2", "eu-west-1", "eu-central-1", "ap-southeast-1"}
var doRegions = []string{"nyc3", "ams3", "sgp1", "fra1", "sfo3"}

// ─── Main ─────────────────────────────────────────────────────────────────────

func main() {
	target := flag.String("target", "", "Target domain (e.g. example.com)")
	workers := flag.Int("w", 30, "Concurrent workers")
	verbose := flag.Bool("v", false, "Verbose: show all candidates being checked")
	jsonMode := flag.Bool("json", false, "Output findings as JSON (progress goes to stderr)")
	flag.Parse()

	if *target == "" {
		fmt.Fprintln(os.Stderr, "Usage: s3recon -target example.com [-w 30] [-v] [-json]")
		os.Exit(1)
	}

	domain := cleanDomain(*target)
	company := companyFromDomain(domain)

	// In JSON mode all progress goes to stderr so stdout stays clean for piping.
	progress := os.Stdout
	if *jsonMode {
		progress = os.Stderr
	}

	printBanner(domain, progress)

	// ── Phase 1: Collect candidate bucket URLs from all sources ──────────────

	candidates := make(map[string]string) // url → source
	var mu sync.Mutex

	add := func(urls []string, source string) {
		mu.Lock()
		defer mu.Unlock()
		for _, u := range urls {
			if _, exists := candidates[u]; !exists {
				candidates[u] = source
				if *verbose {
					fmt.Fprintf(progress, "  %s+%s %s → %s\n", cDim, cReset, source, u)
				}
			}
		}
	}

	fmt.Fprintf(progress, "%s[1/4]%s Scraping HTML for S3 references...\n", cCyan, cReset)
	add(scrapeHTML(domain), "html")

	fmt.Fprintf(progress, "%s[2/4]%s Inspecting TLS certificate SANs...\n", cCyan, cReset)
	add(extractFromCert(domain), "tls-cert")

	fmt.Fprintf(progress, "%s[3/4]%s Probing common subdomains via DNS/HTTP...\n", cCyan, cReset)
	add(enumSubdomains(domain), "subdomain-dns")

	fmt.Fprintf(progress, "%s[4/4]%s Generating bucket name candidates for %s%s%s...\n",
		cCyan, cReset, cBold, company, cReset)
	add(generateCandidates(company), "generated")

	total := len(candidates)
	fmt.Fprintf(progress, "\n%s[*]%s Checking %s%d%s candidates with %d workers...\n\n",
		cCyan, cReset, cBold, total, cReset, *workers)

	// ── Phase 2: Check all candidates concurrently ───────────────────────────

	type job struct {
		url    string
		source string
	}

	jobs := make(chan job, total)
	results := make(chan Finding, total)

	var wg sync.WaitGroup
	for i := 0; i < *workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := range jobs {
				f := checkBucket(j.url)
				f.Source = j.source
				if f.CanList || f.CanRead {
					results <- f
				}
			}
		}()
	}

	for url, source := range candidates {
		jobs <- job{url, source}
	}
	close(jobs)

	go func() {
		wg.Wait()
		close(results)
	}()

	var findings []Finding
	for f := range results {
		findings = append(findings, f)
	}

	if *jsonMode {
		printJSONReport(findings, domain, total)
	} else {
		printReport(findings, domain, total, progress)
	}
}

// ─── Phase 1: Extraction ──────────────────────────────────────────────────────

// scrapeHTML fetches the target page and extracts S3 bucket root URLs.
func scrapeHTML(domain string) []string {
	var body string
	for _, scheme := range []string{"https", "http"} {
		resp, err := httpClient.Get(fmt.Sprintf("%s://%s", scheme, domain))
		if err != nil {
			continue
		}
		b, err := io.ReadAll(io.LimitReader(resp.Body, 5*1024*1024))
		resp.Body.Close()
		if err != nil {
			continue
		}
		body = string(b)
		break
	}
	if body == "" {
		return nil
	}
	return normalizeBucketURLs(findS3URLs(body))
}

// extractFromCert inspects the TLS certificate's SANs and checks each for
// S3 CNAME targets or direct HTTP S3 responses.
func extractFromCert(domain string) []string {
	conn, err := tls.Dial("tcp", domain+":443", &tls.Config{InsecureSkipVerify: true})
	if err != nil {
		return nil
	}
	defer conn.Close()

	certs := conn.ConnectionState().PeerCertificates
	if len(certs) == 0 {
		return nil
	}

	var results []string
	for _, san := range certs[0].DNSNames {
		if url := checkHostForStorage(san); url != "" {
			results = append(results, url)
		}
	}
	return results
}

// enumSubdomains tries common subdomain names under the target domain.
func enumSubdomains(domain string) []string {
	var (
		results []string
		mu      sync.Mutex
		wg      sync.WaitGroup
		sem     = make(chan struct{}, 30)
	)

	for _, sub := range commonSubdomains {
		wg.Add(1)
		go func(sub string) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()

			hostname := sub + "." + domain
			if url := checkHostForStorage(hostname); url != "" {
				mu.Lock()
				results = append(results, url)
				mu.Unlock()
			}
		}(sub)
	}
	wg.Wait()
	return results
}

// checkHostForStorage checks a hostname for S3 storage via CNAME or direct HTTP probe.
func checkHostForStorage(hostname string) string {
	// 1. CNAME check
	if cname, err := net.LookupCNAME(hostname); err == nil {
		for _, pat := range s3CNAMEPatterns {
			if pat.MatchString(cname) {
				return fmt.Sprintf("http://%s/", hostname)
			}
		}
	}

	// 2. Resolve check (is it alive at all?)
	addrs, err := net.LookupHost(hostname)
	if err != nil || len(addrs) == 0 {
		return ""
	}

	// 3. HTTP probe — does it respond with an S3 listing?
	for _, scheme := range []string{"https", "http"} {
		url := fmt.Sprintf("%s://%s/", scheme, hostname)
		resp, err := httpClient.Get(url)
		if err != nil {
			continue
		}
		b, err := io.ReadAll(io.LimitReader(resp.Body, 128*1024))
		resp.Body.Close()
		if err != nil {
			continue
		}
		body := string(b)
		if looksLikeS3Listing(body) {
			return url
		}
		// Also extract any S3 URLs from the response HTML
		if urls := normalizeBucketURLs(findS3URLs(body)); len(urls) > 0 {
			return urls[0]
		}
	}
	return ""
}

// generateCandidates builds bucket name candidates and returns URLs to probe
// across Scaleway, AWS, GCS, and DigitalOcean.
func generateCandidates(company string) []string {
	buckets := make([]string, 0, len(bucketSuffixes))
	for _, suffix := range bucketSuffixes {
		buckets = append(buckets, company+suffix)
	}

	var urls []string
	for _, bucket := range buckets {
		// Scaleway
		for _, region := range scwRegions {
			urls = append(urls,
				fmt.Sprintf("https://s3.%s.scw.cloud/%s/", region, bucket),
				fmt.Sprintf("https://%s.s3.%s.scw.cloud/", bucket, region),
			)
		}
		// AWS
		urls = append(urls, fmt.Sprintf("https://%s.s3.amazonaws.com/", bucket))
		for _, region := range awsRegions {
			urls = append(urls, fmt.Sprintf("https://%s.s3.%s.amazonaws.com/", bucket, region))
		}
		// GCS
		urls = append(urls,
			fmt.Sprintf("https://storage.googleapis.com/%s/", bucket),
			fmt.Sprintf("https://%s.storage.googleapis.com/", bucket),
		)
		// DigitalOcean Spaces
		for _, region := range doRegions {
			urls = append(urls, fmt.Sprintf("https://%s.%s.digitaloceanspaces.com/", bucket, region))
		}
	}
	return urls
}

// ─── Phase 2: Bucket Checks ───────────────────────────────────────────────────

// checkBucket tests a candidate URL for list, read, and write access.
func checkBucket(url string) Finding {
	if !strings.HasSuffix(url, "/") {
		url += "/"
	}
	f := Finding{
		URL:      url,
		Provider: detectProvider(url),
	}

	objects, ok := tryList(url)
	if !ok {
		return f
	}
	f.CanList = true
	f.Objects = objects

	// Try reading the first listed object
	if len(objects) > 0 {
		fileURL := url + objects[0].Key
		f.CanRead = tryRead(fileURL)
	}

	// Try write (non-destructive: PUT a clearly-named probe, DELETE immediately)
	f.CanWrite = tryWrite(url)

	return f
}

// tryList attempts to list the bucket by parsing the S3 XML response.
func tryList(url string) ([]S3Object, bool) {
	resp, err := httpClient.Get(url)
	if err != nil || resp.StatusCode != 200 {
		if resp != nil {
			resp.Body.Close()
		}
		return nil, false
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(io.LimitReader(resp.Body, 2*1024*1024))
	if err != nil {
		return nil, false
	}

	var listing ListBucketResult
	if err := xml.Unmarshal(body, &listing); err != nil {
		return nil, false
	}
	// A valid listing has either a Name or Contents (empty bucket has Name only)
	if listing.Name == "" && len(listing.Contents) == 0 {
		return nil, false
	}
	return listing.Contents, true
}

// tryRead attempts a GET on a specific object URL.
func tryRead(url string) bool {
	resp, err := httpClient.Get(url)
	if err != nil {
		return false
	}
	io.Copy(io.Discard, resp.Body)
	resp.Body.Close()
	return resp.StatusCode == 200
}

// tryWrite sends a PUT with a clearly-named probe file and immediately DELETEs it.
// Returns true only if write succeeded (status 200 or 204).
func tryWrite(bucketURL string) bool {
	probeKey := fmt.Sprintf("s3recon-security-probe-%d.txt", time.Now().UnixNano())
	probeURL := bucketURL + probeKey

	req, err := http.NewRequest("PUT", probeURL, strings.NewReader("s3recon security probe - delete me"))
	if err != nil {
		return false
	}
	req.Header.Set("Content-Type", "text/plain")

	resp, err := httpClient.Do(req)
	if err != nil {
		return false
	}
	io.Copy(io.Discard, resp.Body)
	resp.Body.Close()

	if resp.StatusCode != 200 && resp.StatusCode != 204 {
		return false
	}

	// Immediately clean up
	del, _ := http.NewRequest("DELETE", probeURL, nil)
	if delResp, err := httpClient.Do(del); err == nil {
		io.Copy(io.Discard, delResp.Body)
		delResp.Body.Close()
	}
	return true
}

// ─── Helpers ──────────────────────────────────────────────────────────────────

// findS3URLs extracts all S3-compatible URLs from a string.
func findS3URLs(text string) []string {
	seen := make(map[string]bool)
	var results []string
	for _, pat := range s3URLPatterns {
		for _, m := range pat.FindAllString(text, -1) {
			if !seen[m] {
				seen[m] = true
				results = append(results, m)
			}
		}
	}
	return results
}

// normalizeBucketURLs strips paths to return only the bucket root URL.
func normalizeBucketURLs(urls []string) []string {
	seen := make(map[string]bool)
	var results []string
	for _, u := range urls {
		root := bucketRootURL(u)
		if root != "" && !seen[root] {
			seen[root] = true
			results = append(results, root)
		}
	}
	return results
}

// bucketRootURL returns the root URL for the bucket (strips any object path).
func bucketRootURL(u string) string {
	// Path-style providers: scheme://provider-host/bucket/object → scheme://provider-host/bucket/
	pathStyleHosts := []*regexp.Regexp{
		regexp.MustCompile(`s3(?:[.-][a-z0-9-]+)?\.amazonaws\.com`),
		regexp.MustCompile(`s3\.[a-z]+-[a-z]+\.scw\.cloud`),
		regexp.MustCompile(`storage\.googleapis\.com`),
	}
	for _, pat := range pathStyleHosts {
		loc := pat.FindStringIndex(u)
		if loc == nil {
			continue
		}
		afterHost := u[loc[1]:]
		// afterHost is like /bucket/key/subkey or /bucket/
		parts := strings.SplitN(strings.TrimPrefix(afterHost, "/"), "/", 2)
		if len(parts) > 0 && parts[0] != "" {
			return u[:loc[1]] + "/" + parts[0] + "/"
		}
	}

	// Virtual-hosted style: scheme://bucket.provider.com/key → scheme://bucket.provider.com/
	schemeEnd := strings.Index(u, "://")
	if schemeEnd < 0 {
		return ""
	}
	rest := u[schemeEnd+3:]
	hostEnd := strings.Index(rest, "/")
	if hostEnd < 0 {
		return u + "/"
	}
	return u[:schemeEnd+3] + rest[:hostEnd] + "/"
}

// looksLikeS3Listing returns true if a response body contains S3 listing XML markers.
func looksLikeS3Listing(body string) bool {
	return strings.Contains(body, "<ListBucketResult") ||
		strings.Contains(body, `xmlns="http://s3.amazonaws.com/doc/2006-03-01/"`)
}

// detectProvider returns a human-readable provider name from a URL.
func detectProvider(url string) string {
	for _, p := range providerFromURL {
		if p.pattern.MatchString(url) {
			return p.provider
		}
	}
	return "Unknown"
}

// cleanDomain strips scheme, trailing slashes, and paths from a domain string.
func cleanDomain(input string) string {
	d := strings.TrimPrefix(input, "https://")
	d = strings.TrimPrefix(d, "http://")
	d = strings.Split(d, "/")[0]
	return strings.TrimSpace(d)
}

// companyFromDomain extracts the second-to-last label from a domain.
// e.g. "api.obitrain.com" → "obitrain"
func companyFromDomain(domain string) string {
	parts := strings.Split(domain, ".")
	if len(parts) >= 2 {
		return parts[len(parts)-2]
	}
	return domain
}

// ─── Reporting ────────────────────────────────────────────────────────────────

func printBanner(domain string, w *os.File) {
	fmt.Fprintf(w, "\n%s%s", cBold, cCyan)
	fmt.Fprintln(w, "  _____ _____")
	fmt.Fprintln(w, " / ____|___ /")
	fmt.Fprintln(w, "| (___   |_ \\  recon")
	fmt.Fprintln(w, " \\___ \\ ___) |")
	fmt.Fprintln(w, " ____) / __/ ")
	fmt.Fprintf(w, "|_____/_____| v%s\n", version)
	fmt.Fprintf(w, "%s", cReset)
	fmt.Fprintf(w, "  Cloud Storage Misconfiguration Scanner\n")
	fmt.Fprintf(w, "  Target: %s%s%s\n\n", cBold, domain, cReset)
}

func printReport(findings []Finding, domain string, total int, w *os.File) {
	fmt.Fprintf(w, "\n%s%s", cBold, cCyan)
	fmt.Fprintln(w, "══════════════════════════════════════════════")
	fmt.Fprintf(w, "  RESULTS — %s\n", domain)
	fmt.Fprintln(w, "══════════════════════════════════════════════")
	fmt.Fprintf(w, "%s\n", cReset)

	if len(findings) == 0 {
		fmt.Fprintf(w, "  %s[✓] No publicly accessible buckets found.%s\n", cGreen, cReset)
		fmt.Fprintf(w, "  %sCandidates checked: %d%s\n\n", cDim, total, cReset)
		return
	}

	for i, f := range findings {
		fmt.Fprintf(w, "  %s Finding #%d\n", f.SeverityColored(), i+1)
		fmt.Fprintf(w, "  %-10s %s\n", "URL:", f.URL)
		fmt.Fprintf(w, "  %-10s %s\n", "Provider:", f.Provider)
		fmt.Fprintf(w, "  %-10s %s\n", "Source:", f.Source)
		fmt.Fprintf(w, "  %-10s %s\n", "LIST:", yesNo(f.CanList))
		fmt.Fprintf(w, "  %-10s %s\n", "READ:", yesNo(f.CanRead))
		fmt.Fprintf(w, "  %-10s %s\n", "WRITE:", yesNo(f.CanWrite))

		if f.CanList {
			fmt.Fprintf(w, "  %-10s %d objects", "Objects:", len(f.Objects))
			if len(f.Objects) > 0 {
				fmt.Fprintf(w, " (e.g. %s%s%s)", cDim, f.Objects[0].Key, cReset)
			}
			fmt.Fprintln(w)
		}

		// Print PoC curl command
		fmt.Fprintf(w, "\n  %sPoC:%s\n", cDim, cReset)
		fmt.Fprintf(w, "  %scurl -s \"%s\" | grep -oP '(?<=<Key>)[^<]+'%s\n",
			cDim, f.URL, cReset)
		fmt.Fprintln(w)
	}

	fmt.Fprintf(w, "  %sCandidates checked: %d | Findings: %d%s\n\n",
		cDim, total, len(findings), cReset)
}

// printJSONReport writes a machine-readable JSON report to stdout.
func printJSONReport(findings []Finding, domain string, total int) {
	type jsonFinding struct {
		URL         string     `json:"url"`
		Provider    string     `json:"provider"`
		Source      string     `json:"source"`
		Severity    string     `json:"severity"`
		CanList     bool       `json:"can_list"`
		CanRead     bool       `json:"can_read"`
		CanWrite    bool       `json:"can_write"`
		ObjectCount int        `json:"object_count"`
		Objects     []S3Object `json:"objects"`
	}
	type jsonReport struct {
		Target            string        `json:"target"`
		CandidatesChecked int           `json:"candidates_checked"`
		FindingCount      int           `json:"finding_count"`
		Findings          []jsonFinding `json:"findings"`
	}

	out := jsonReport{
		Target:            domain,
		CandidatesChecked: total,
		FindingCount:      len(findings),
		Findings:          make([]jsonFinding, 0, len(findings)),
	}
	for _, f := range findings {
		objects := f.Objects
		if objects == nil {
			objects = []S3Object{}
		}
		out.Findings = append(out.Findings, jsonFinding{
			URL:         f.URL,
			Provider:    f.Provider,
			Source:      f.Source,
			Severity:    f.Severity(),
			CanList:     f.CanList,
			CanRead:     f.CanRead,
			CanWrite:    f.CanWrite,
			ObjectCount: len(f.Objects),
			Objects:     objects,
		})
	}

	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	enc.Encode(out)
}

func yesNo(b bool) string {
	if b {
		return cRed + "YES ✗" + cReset
	}
	return cGreen + "NO  ✓" + cReset
}
