MODULES := sdk portscan subfinder httpprobe nuclei

.PHONY: test build generate

test:
	@for module in $(MODULES); do \
		(cd $$module && GOWORK=off go test -race ./...) || exit 1; \
	done

build:
	@mkdir -p bin
	@for pair in portscan:portscan subfinder:subdomain httpprobe:httpprobe nuclei:vuln; do \
		module=$${pair%%:*}; capability=$${pair##*:}; \
		(cd $$module && GOWORK=off CGO_ENABLED=0 go build -trimpath -o ../bin/$$capability .) || exit 1; \
	done

generate:
	cd sdk && buf generate
