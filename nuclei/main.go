// Command nuclei is the projectdiscovery/nuclei vulnerability scanner as a
// standalone go-plugin gRPC plugin, launched as a subprocess by the scanner
// host. It implements both Execute (scan) and Prepare (pre-scan template
// sync). All nuclei dependency weight — the heaviest of the tools — lives in
// this module's go.mod, keeping it out of the scanner host binary.
package main

import "github.com/trganda/vpt-scanner-plugins/sdk"

func main() {
	sdk.Serve(newScanner())
}
