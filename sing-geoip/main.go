package main

import (
	"compress/gzip"
	"encoding/csv"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/netip"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"

	"github.com/maxmind/mmdbwriter"
	"github.com/maxmind/mmdbwriter/inserter"
	"github.com/maxmind/mmdbwriter/mmdbtype"

	"go4.org/netipx"

	"github.com/sagernet/sing-box/common/srs"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/option"
)

const (
	DataSourceDir = "data_source"
	OutputMMDB    = "geoip.db"
	OutputRuleSet = "rule-set"
)

func setActionOutput(name string, content string) {
	os.Stdout.WriteString("::set-output name=" + name + "::" + content + "\n")
}

func main() {
	if err := run(); err != nil {
		log.Fatalf("Error: %v", err)
		setActionOutput("skip", "true")
	}
}

func run() error {
	if err := os.MkdirAll(DataSourceDir, 0755); err != nil {
		return err
	}

	// Builders map
	builders := make(map[string]*netipx.IPSetBuilder)
	var mu sync.Mutex

	getBuilder := func(code string) *netipx.IPSetBuilder {
		mu.Lock()
		defer mu.Unlock()
		code = strings.ToLower(code)
		if _, ok := builders[code]; !ok {
			builders[code] = &netipx.IPSetBuilder{}
		}
		return builders[code]
	}

	// 1. IPInfo
	log.Println("Step 1: Processing IPInfo...")
	err := processIPInfo(getBuilder)
	if err != nil {
		return fmt.Errorf("ipinfo error: %w", err)
	}

	// 2. Anycast BGP
	log.Println("Step 2: Processing Anycast BGP...")
	anycastPrefixes, err := processAnycastBGP()
	if err != nil {
		return fmt.Errorf("anycast bgp error: %w", err)
	}
	applyOverride("anycast", anycastPrefixes, builders)

	// 3. Cloud Provider (Global -> Anycast) + Capture CF
	log.Println("Step 3: Processing Cloud Providers...")
	cloudAnycast, cfRanges, err := processCloudProviders()
	if err != nil {
		return fmt.Errorf("cloud provider error: %w", err)
	}
	applyOverride("anycast", cloudAnycast, builders)

	// 4. Cloudflare Local (Refine CF)
	log.Println("Step 4: Processing Cloudflare Local...")
	cfAnycast, err := processCloudflareLocal(cfRanges)
	if err != nil {
		return fmt.Errorf("cf local error: %w", err)
	}
	applyOverride("anycast", cfAnycast, builders)

	// 5. CN (17mon)
	log.Println("Step 5: Processing CN 17mon...")
	cn17mon, err := processCN17Mon()
	if err != nil {
		return fmt.Errorf("cn 17mon error: %w", err)
	}
	applyOverride("cn", cn17mon, builders)

	// 6. CN (Gaoyifan)
	log.Println("Step 6: Processing CN Gaoyifan...")
	cnGao, err := processCNGaoyifan()
	if err != nil {
		return fmt.Errorf("cn gaoyifan error: %w", err)
	}
	applyOverride("cn", cnGao, builders)

	// Finalize
	log.Println("Generating outputs...")
	return writeOutputs(builders)
}

// applyOverride adds prefixes to targetRegion and removes them from ALL other regions
func applyOverride(targetRegion string, prefixes []netip.Prefix, builders map[string]*netipx.IPSetBuilder) {
	targetRegion = strings.ToLower(targetRegion)
	// Add to target
	targetBuilder := builders[targetRegion]
	if targetBuilder == nil {
		targetBuilder = &netipx.IPSetBuilder{}
		builders[targetRegion] = targetBuilder
	}
	for _, p := range prefixes {
		targetBuilder.AddPrefix(p)
	}

	// Remove from others
	for code, b := range builders {
		if code == targetRegion {
			continue
		}
		for _, p := range prefixes {
			b.RemovePrefix(p)
		}
	}
}

// ---------------- Downloads ----------------

func download(url, filename string) (string, error) {
	path := filepath.Join(DataSourceDir, filename)
	if _, err := os.Stat(path); err == nil {
		log.Printf("File %s exists, skipping download.", filename)
		return path, nil
	}
	log.Printf("Downloading %s ...", url)

	resp, err := http.Get(url)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		return "", fmt.Errorf("http status %d", resp.StatusCode)
	}

	out, err := os.Create(path)
	if err != nil {
		return "", err
	}
	defer out.Close()

	_, err = io.Copy(out, resp.Body)
	return path, err
}

// ---------------- Step 1: IPInfo ----------------

func processIPInfo(getBuilder func(string) *netipx.IPSetBuilder) error {
	// Download
	token := os.Getenv("IPINFO_TOKEN")
	if token == "" {
		return fmt.Errorf("IPINFO_TOKEN not set")
	}
	url := "https://ipinfo.io/data/ipinfo_lite.csv.gz?token=" + token
	gzPath, err := download(url, "ipinfo_lite.csv.gz")
	if err != nil {
		return err
	}

	f, err := os.Open(gzPath)
	if err != nil {
		return err
	}
	defer f.Close()

	gr, err := gzip.NewReader(f)
	if err != nil {
		return err
	}
	defer gr.Close()

	reader := csv.NewReader(gr)
	// Headers: network,country,country_code,continent,continent_code,asn,as_name,as_domain
	headers, err := reader.Read()
	if err != nil {
		return err
	}
	_ = headers // skip
	log.Println("IPInfo Header:", headers)

	count := 0
	handled := 0
	skippedIPv6 := 0
	skippedInvalid := 0

	for {
		record, err := reader.Read()
		if err == io.EOF {
			break
		}
		if err != nil {
			return err
		}

		count++

		if len(record) < 5 {
			skippedInvalid++
			continue
		}

		// Row content logging (first 5)
		if count <= 5 {
			log.Println("Row:", record)
		}

		networkStr := record[0]
		countryCode := record[2]
		continentCode := record[4]

		// Parse CIDR or IP
		var prefix netip.Prefix
		if strings.Contains(networkStr, "/") {
			prefix, err = netip.ParsePrefix(networkStr)
		} else {
			// If no slash, verify if it's a single IP.
			// netip.ParsePrefix fails if no slash.
			var addr netip.Addr
			addr, err = netip.ParseAddr(networkStr)
			if err == nil {
				prefix = netip.PrefixFrom(addr, addr.BitLen())
			}
		}

		if err != nil {
			skippedInvalid++
			continue
		}
		if !prefix.Addr().Is4() {
			skippedIPv6++
			continue
		}

		// Determine Region
		targetRegion := countryCode
		if continentCode == "AS" {
			if countryCode == "CN" {
				continue // Drop CN from IPInfo (not counted as skippedIPv6/Invalid, just dropped per logic)
			}
			// Map others
			switch countryCode {
			case "HK", "SG", "JP":
				targetRegion = countryCode
			default:
				// Map to HK/SG/JP based on proximity
				targetRegion = mapAsiaToProxy(countryCode)
			}
		} else {
			targetRegion = continentCode
		}

		// Add to builder
		if targetRegion != "" {
			getBuilder(targetRegion).AddPrefix(prefix)
			handled++
		}
	}
	log.Printf("IPInfo summary: total=%d, handled=%d, skippedIPv6=%d, skippedInvalid=%d", count, handled, skippedIPv6, skippedInvalid)
	return nil
}

func mapAsiaToProxy(cc string) string {
	// Simple mapping
	switch cc {
	case "KR", "TW", "MN":
		return "JP"
	case "MO":
		return "HK"
	default:
		// SE Asia / South Asia / West Asia -> SG
		return "SG"
	}
}

// ---------------- Step 2: Anycast BGP ----------------

func processAnycastBGP() ([]netip.Prefix, error) {
	url := "https://raw.githubusercontent.com/bgptools/anycast-prefixes/master/anycatch-v4-prefixes.txt"
	path, err := download(url, "anycast-prefixes.txt")
	if err != nil {
		return nil, err
	}
	return parseCIDRList(path, "Anycast BGP")
}

func parseCIDRList(path string, listName string) ([]netip.Prefix, error) {
	content, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	lines := strings.Split(string(content), "\n")
	var prefixes []netip.Prefix

	total := 0
	handled := 0
	skippedIPv6 := 0
	skippedInvalid := 0

	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		total++

		p, err := netip.ParsePrefix(line)
		if err != nil {
			skippedInvalid++
			continue
		}
		if !p.Addr().Is4() {
			skippedIPv6++
			continue
		}

		prefixes = append(prefixes, p)
		handled++
	}
	log.Printf("%s summary: total_lines=%d, handled=%d, skippedIPv6=%d, skippedInvalid=%d", listName, total, handled, skippedIPv6, skippedInvalid)
	return prefixes, nil
}

// ---------------- Step 3: Cloud Providers ----------------

func processCloudProviders() (anycast []netip.Prefix, cfParams []netip.Prefix, err error) {
	url := "https://raw.githubusercontent.com/tobilg/public-cloud-provider-ip-ranges/refs/heads/main/data/providers/all.csv"
	path, err := download(url, "cloud_providers.csv")
	if err != nil {
		return nil, nil, err
	}

	f, err := os.Open(path)
	if err != nil {
		return nil, nil, err
	}
	defer f.Close()

	reader := csv.NewReader(f)
	// cloud_provider,cidr_block,ip_address,ip_address_mask,ip_address_cnt,region
	_, err = reader.Read() // header
	if err != nil {
		return nil, nil, err
	}

	total := 0
	handled := 0
	skippedIPv6 := 0
	skippedInvalid := 0

	for {
		rec, err := reader.Read()
		if err == io.EOF {
			break
		}
		if err != nil || len(rec) < 6 {
			if len(rec) > 0 {
				skippedInvalid++
			} // Only count as invalid if it's a partial record vs hard error
			continue
		}

		total++

		provider := rec[0]
		cidr := rec[1]
		region := rec[5]

		if provider == "AWS" {
			continue
		}

		p, err := netip.ParsePrefix(cidr)
		if err != nil {
			skippedInvalid++
			continue
		}
		if !p.Addr().Is4() {
			skippedIPv6++
			continue
		}

		handled++ // Found valid IPv4 CIDR

		if strings.EqualFold(region, "global") {
			anycast = append(anycast, p)
		}
		if provider == "CloudFlare" {
			cfParams = append(cfParams, p)
		}
	}
	log.Printf("CloudProviders summary: total=%d, valid_ipv4=%d, skippedIPv6=%d, skippedInvalid=%d", total, handled, skippedIPv6, skippedInvalid)
	return
}

// ---------------- Step 4: Cloudflare Local ----------------

func processCloudflareLocal(cfFromStep3 []netip.Prefix) ([]netip.Prefix, error) {
	url := "https://api.cloudflare.com/local-ip-ranges.csv"
	path, err := download(url, "local-ip-ranges.csv")
	if err != nil {
		return nil, err
	}

	// Read local IPs to exclude
	content, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}

	// Format: cidr,country,region,city...
	// We only need the CIDR to exclude.

	toExcludeBuilder := &netipx.IPSetBuilder{}
	lines := strings.Split(string(content), "\n")

	total := 0
	handled := 0
	skippedIPv6 := 0
	skippedInvalid := 0

	for _, line := range lines {
		parts := strings.Split(line, ",")
		if len(parts) > 0 && parts[0] != "" {
			total++
			p, err := netip.ParsePrefix(parts[0])
			if err != nil {
				skippedInvalid++
				continue
			}
			if !p.Addr().Is4() {
				skippedIPv6++
				continue
			}

			toExcludeBuilder.AddPrefix(p)
			handled++
		}
	}
	log.Printf("CloudflareLocal summary: total_lines=%d, handled=%d, skippedIPv6=%d, skippedInvalid=%d", total, handled, skippedIPv6, skippedInvalid)
	excludeSet, _ := toExcludeBuilder.IPSet()

	// Build the final CF Anycast list
	// Capture Step 3 IPs, Minus Local IPs

	// We use a builder for the CF set
	cfBuilder := &netipx.IPSetBuilder{}
	for _, p := range cfFromStep3 {
		cfBuilder.AddPrefix(p)
	}
	// Subtract locals

	// IPSetBuilder logic: Add CF ranges. Remove Exclude ranges.
	// Wait, to remove "Exclude" ranges from "CF" ranges:
	// We can iterate the Exclude SET and RemovePrefix on the CF Builder.

	// However, `excludeSet` is an IPSet. We can get prefixes.
	for _, p := range excludeSet.Prefixes() {
		cfBuilder.RemovePrefix(p)
	}

	finalSet, _ := cfBuilder.IPSet()
	return finalSet.Prefixes(), nil
}

// ---------------- Step 5 & 6: CN Lists ----------------

func processCN17Mon() ([]netip.Prefix, error) {
	url := "https://raw.githubusercontent.com/17mon/china_ip_list/master/china_ip_list.txt"
	path, err := download(url, "china_ip_list.txt")
	if err != nil {
		return nil, err
	}
	return parseCIDRList(path, "CN 17mon")
}

func processCNGaoyifan() ([]netip.Prefix, error) {
	url := "https://raw.githubusercontent.com/gaoyifan/china-operator-ip/ip-lists/china.txt"
	path, err := download(url, "cn_gaoyifan.txt")
	if err != nil {
		return nil, err
	}
	return parseCIDRList(path, "CN Gaoyifan")
}

// ---------------- Writers ----------------

func writeOutputs(builders map[string]*netipx.IPSetBuilder) error {
	// Convert builders to map[string][]*net.IPNet for MMDB
	// and use it for RuleSet.

	// We need `*net.IPNet` because mmdbwriter uses it.

	regionData := make(map[string][]*net.IPNet)
	// Also separate CN for geoip-cn.db

	sortedRegions := make([]string, 0, len(builders))
	for r := range builders {
		sortedRegions = append(sortedRegions, r)
	}
	sort.Strings(sortedRegions)

	for _, region := range sortedRegions {
		set, err := builders[region].IPSet()
		if err != nil {
			return err
		}
		prefixes := set.Prefixes()
		for _, p := range prefixes {
			ipNet := prefixToIPNet(p)
			regionData[region] = append(regionData[region], ipNet)
		}
	}

	// 1. geoip.db
	log.Printf("Writing %s...", OutputMMDB)
	if err := writeMMDB(regionData, OutputMMDB, nil); err != nil {
		return err
	}

	// 2. geoip-cn.db (Only CN)
	if cnData, ok := regionData["cn"]; ok {
		log.Printf("Writing geoip-cn.db...")
		cnMap := map[string][]*net.IPNet{"cn": cnData}
		if err := writeMMDB(cnMap, "geoip-cn.db", []string{"cn"}); err != nil {
			return err
		}
	}

	// 3. rule-set
	log.Printf("Writing rule-sets to %s/...", OutputRuleSet)
	if err := os.RemoveAll(OutputRuleSet); err != nil {
		return err
	}
	if err := os.MkdirAll(OutputRuleSet, 0755); err != nil {
		return err
	}

	for region, ipNets := range regionData {
		// SRS and JSON
		if len(ipNets) == 0 {
			continue
		}

		headlessRule := option.DefaultHeadlessRule{
			IPCIDR: make([]string, 0, len(ipNets)),
		}
		for _, ipNet := range ipNets {
			headlessRule.IPCIDR = append(headlessRule.IPCIDR, ipNet.String())
		}

		plainRuleSet := option.PlainRuleSet{
			Rules: []option.HeadlessRule{
				{
					Type:           C.RuleTypeDefault,
					DefaultOptions: headlessRule,
				},
			},
		}

		baseName := "geoip-" + region

		// Write SRS
		srsPath := filepath.Join(OutputRuleSet, baseName+".srs")
		f, err := os.Create(srsPath)
		if err != nil {
			return err
		}
		if err := srs.Write(f, plainRuleSet); err != nil {
			f.Close()
			return err
		}
		f.Close()

		// Write JSON
		jsonPath := filepath.Join(OutputRuleSet, baseName+".json")
		jf, err := os.Create(jsonPath)
		if err != nil {
			return err
		}
		encoder := json.NewEncoder(jf) // Need to import encoding/json
		encoder.SetIndent("", "    ")
		if err := encoder.Encode(plainRuleSet); err != nil {
			jf.Close()
			return err
		}
		jf.Close()

		// Write raw txt data ip prefix
		txtPath := filepath.Join(OutputRuleSet, baseName+".txt")
		tf, err := os.Create(txtPath)
		if err != nil {
			return err
		}
		for _, ipNet := range ipNets {
			tf.WriteString(ipNet.String() + "\n")
		}
		tf.Close()
	}

	return nil
}

func writeMMDB(data map[string][]*net.IPNet, output string, codes []string) error {
	// metadata simulation
	// We need to create a writer.
	// existing code used newWriter logic.

	if codes == nil {
		for r := range data {
			codes = append(codes, r)
		}
	}

	writer, err := mmdbwriter.New(mmdbwriter.Options{
		DatabaseType:            "sing-geoip",
		Languages:               codes,
		IPVersion:               4, // We only process IPv4
		RecordSize:              24,
		Inserter:                inserter.ReplaceWith,
		DisableIPv4Aliasing:     true,
		IncludeReservedNetworks: true,
	})
	if err != nil {
		return err
	}

	for code, list := range data {
		// Filter if codes is strict? existing `write` did filter.
		// We just insert everything in data since we built it clean.

		// If codes is restricted (e.g. geoip-cn), we only insert if code is in list?
		// But in our call, we passed map with only CN for geoip-cn.
		// So just iterate map.

		for _, ipNet := range list {
			if err := writer.Insert(ipNet, mmdbtype.String(code)); err != nil {
				return err
			}
		}
	}

	out, err := os.Create(output)
	if err != nil {
		return err
	}
	defer out.Close()
	_, err = writer.WriteTo(out)
	return err
}

func prefixToIPNet(p netip.Prefix) *net.IPNet {
	// netip.Prefix to net.IPNet
	// p.Masked() ensures canonical
	p = p.Masked()
	addr := p.Addr()
	ip := net.IP(addr.AsSlice())
	mask := net.CIDRMask(p.Bits(), addr.BitLen())
	return &net.IPNet{IP: ip, Mask: mask}
}
