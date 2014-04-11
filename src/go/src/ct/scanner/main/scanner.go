package main

import (
	"crypto/x509"
	"ct/client"
	"ct/scanner"
	"flag"
	"log"
	"regexp"
)

var logUri = flag.String("log_uri", "http://ct.googleapis.com/aviator", "CT log base URI")
var matchSubjectRegex = flag.String("match_subject_regex", ".*", "Regex to match CN/SAN")
var blockSize = flag.Int("block_size", 1000, "Max number of entries to request at per call to get-entries")
var numWorkers = flag.Int("num_workers", 2, "Number of concurrent matchers")
var parallelFetch = flag.Int("parallel_fetch", 2, "Number of concurrent GetEntries fetches")
var startIndex = flag.Int64("start_index", 0, "Log index to start scanning at")

// Prints out a short bit of info about |cert|, found at |index| in the
// specified log
func logCertInfo(index int64, cert *x509.Certificate) {
	log.Printf("Interesting cert at index %d: CN: '%s'", index, cert.Subject.CommonName)
}

// Prints out a short bit of info about |precert|, found at |index| in the
// specified log
func logPrecertInfo(index int64, precert string) {
	log.Printf("Interesting precert at index %d: CN: '%s'", index, precert)
}

func main() {
	flag.Parse()
	logClient := client.New(*logUri)
	opts := scanner.ScannerOptions{
		Matcher:       scanner.MatchSubjectRegex{regexp.MustCompile(*matchSubjectRegex)},
		BlockSize:     *blockSize,
		NumWorkers:    *numWorkers,
		ParallelFetch: *parallelFetch,
		StartIndex:    *startIndex,
	}
	scanner := scanner.NewScanner(logClient, opts)
	scanner.Scan(logCertInfo, logPrecertInfo)
}
