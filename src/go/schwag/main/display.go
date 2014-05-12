package main

import (
	"flag"

	"code.google.com/p/certificate-transparency/src/go/client"
	"code.google.com/p/certificate-transparency/src/go/schwag"
)

var logUri = flag.String("log_uri", "http://ct.googleapis.com/pilot", "CT Log base URI")
var logName = flag.String("log_name", "Pilot", "Name to display on LCD")
var fetchSecs = flag.Int("fetch_secs", 60, "Fetch a new STH every n seconds")
var serialDevice = flag.String("serial_device", "/dev/ttyACM0", "Which serial device has the LCD connected")
var serialBaud = flag.Int("serial_baud", 115200, "Speed at which to communicate with LCD device")
var freshAge = flag.Int("fresh_age", 30*60, "STH age in seconds below which the display is completely green")
var staleAge = flag.Int("stale_age", 90*60, "STH age in seconds after which the display is completely red")

func main() {
	flag.Parse()
	logClient := client.New(*logUri)
	displayConfig := schwag.DisplayConfig{
		Client:    logClient,
		Name:      *logName,
		Port:      *serialDevice,
		Baud:      *serialBaud,
		FreshAge:  *freshAge,
		StaleAge:  *staleAge,
		FetchSecs: *fetchSecs,
	}
	display, err := schwag.NewLCDDisplay(displayConfig)
	if err != nil {
		panic(err.Error())
	}
	display.Run()
}
