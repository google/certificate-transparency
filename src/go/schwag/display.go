// This package contains a driver for an LCD display which shows info about a
// CT log.
//
// This package can be used to drive any serially connected LCD which is
// compatible with the Matrix Orbital command set, although currently
// the code assumes an 16x2 LCD.
package schwag

import (
	"flag"
	"fmt"
	"io"
	"log"
	"time"

	"code.google.com/p/certificate-transparency/src/go/client"
	"github.com/tarm/goserial"
)

// These represent some of the MatrixOrbital command codes we use
const (
	cmdSetColour     = "\xfe\xd0"
	cmdClear         = "\xfe\x58"
	cmdHome          = "\xfe\x48"
	cmdAutoscrollOff = "\xfe\x52"
	cmdSetSplash     = "\xfe\x40Certificate         Transparency"
)

const (
	// Arbitrary value used to roll the displayed TreeSize digits a bit
	// when counting up to a new TreeSize
	counterRattleStep = 947
)

var updateHz = flag.Int("update_hz", 10, "LCD updates per second")

// LCDDisplay is a driver for Matrix Orbital compatible serially connected LCD
// panels.
type LCDDisplay struct {
	logClient *client.LogClient
	serial    io.ReadWriteCloser
	config    DisplayConfig
	sth       *client.SignedTreeHead
	// numCerts keeps track of the number of certs to be displayed on the
	// LCD.  This is kept apart from sth.TreeSize in order to perform an
	// aesthetic 'rattle count' of digits when a new STH with a larger
	// TreeSize is encountered.
	numCerts uint64
}

type DisplayConfig struct {
	// Info to be displayed is fetched using |Client|
	Client *client.LogClient
	// Log name to be displayed on the LCD
	Name string
	// Path to the serial port connected to the LCD
	Port string
	// Baud rate to use to talk to the LCD device
	Baud int
	// When the current STH is less than |FreshAge| seconds old, the display is
	// green, above this age it starts fading towards red.
	FreshAge int
	// When the current STH is older than |StaleAge| the display colour is set
	// to red.
	StaleAge int
	// Fetch a new STH from the log once every |FetchSecs| seconds
	FetchSecs int
}

// NewLCDDisplay creates a new LCD Display driver instance.
// The LCDDisplay is configured with the data in |conf|.
// Returns a new LCDDisplay instance or an error.
func NewLCDDisplay(conf DisplayConfig) (*LCDDisplay, error) {
	serialConfig := &serial.Config{Name: conf.Port, Baud: conf.Baud}
	s, err := serial.OpenPort(serialConfig)
	if err != nil {
		return nil, err
	}
	s.Write([]byte(cmdAutoscrollOff + cmdClear))
	return &LCDDisplay{
		logClient: conf.Client,
		serial:    s,
		config:    conf}, nil
}

// Goroutine to fetch STHs from the configured log server.
func (l *LCDDisplay) sthFetcher(newSTHs chan<- *client.SignedTreeHead) {
	for {
		sth, err := l.logClient.GetSTH()
		if err != nil {
			log.Printf(err.Error())
		} else {
			newSTHs <- sth
		}
		time.Sleep(time.Duration(l.config.FetchSecs) * time.Second)
	}
}

// Colour returns a string containing Matrix Orbital compatible control codes
// to set the color of the LCD backlight.
func Colour(r uint8, g uint8, b uint8) string {
	rgb := []uint8{r, g, b}
	return fmt.Sprintf("%s%s", cmdSetColour, string(rgb))
}

// Goroutine to update the LCD device.
func (l *LCDDisplay) displayUpdater(newSTHs <-chan *client.SignedTreeHead) {
	for {
		time.Sleep(time.Duration(1 / *updateHz) * time.Second)
		// check if there's a new STH waiting for us, and grab it if
		// so.
		select {
		case l.sth = <-newSTHs:
			if l.numCerts == 0 {
				// This is the first STH we see, so don't try
				// to count to the number of certs all the way
				// up from zero
				l.numCerts = l.sth.TreeSize
			}
		default:
			if l.sth == nil {
				// We're still waiting for the first STH so put something to that effect on the LCD
				l.serial.Write([]byte(fmt.Sprintf("%s%sFetching STH...", cmdHome, Colour(0xff, 0x80, 0xff))))
				continue
			}
		}
		if l.numCerts < l.sth.TreeSize-counterRattleStep {
			l.numCerts += counterRattleStep
		} else {
			l.numCerts = l.sth.TreeSize
		}
		ageSecs := int(time.Now().Sub(time.Unix(int64(l.sth.Timestamp)/1000, 0)).Seconds())
		var red, green uint8
		switch {
		case ageSecs < l.config.FreshAge:
			green = 0xff
			red = 0x00
		case ageSecs >= l.config.StaleAge:
			red = 0xff
			green = 0x00
		default:
			red = uint8(0xff * (ageSecs - l.config.FreshAge) / (l.config.StaleAge - l.config.FreshAge))
			green = 0xff - red
		}
		l.serial.Write([]byte(fmt.Sprintf("%s%s%5s %4dm old", cmdHome, Colour(red, green, 0), l.config.Name[:6], ageSecs/60)))
		l.serial.Write([]byte(fmt.Sprintf("Certs: %9d", l.numCerts)))
	}
}

// Run will start periodically fetching STHs from the configured log in the
// background, and block while it continues to refresh the LCD contents.
// There's currently no way to cause Run() to exit (other than killing the
// program.)
func (l *LCDDisplay) Run() {
	newSTHs := make(chan *client.SignedTreeHead, 1)
	go l.sthFetcher(newSTHs)
	l.displayUpdater(newSTHs)
}
