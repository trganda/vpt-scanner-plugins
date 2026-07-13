// Command portscan is the naabu-backed port-scan tool as a standalone
// go-plugin gRPC plugin. It is launched as a subprocess by the scanner host
// (internal/adapter/scan/plugin) and never run directly — doing so prints the
// go-plugin handshake guard message.
//
// All projectdiscovery/naabu dependency weight lives in this module's go.mod,
// keeping it out of the scanner host binary.
package main

import "github.com/trganda/vpt-scanner-plugins/sdk"

func main() {
	sdk.Serve(newScanner())
}
