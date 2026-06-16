// Command httpprobe is the projectdiscovery/httpx HTTP probing tool as a
// standalone go-plugin gRPC plugin, launched as a subprocess by the scanner
// host. All httpx/tlsx dependency weight lives in this module's go.mod, keeping
// it out of the scanner host binary.
package main

import "github.com/trganda/vpt-backend/plugins/sdk"

func main() {
	sdk.Serve(newScanner())
}
