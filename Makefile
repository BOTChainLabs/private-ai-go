.PHONY: help check fmt vet test cover live crosscheck

.DEFAULT_GOAL := help

GO ?= go

help: ## Show available targets.
	@grep -E '^[a-zA-Z_-]+:.*?## ' $(MAKEFILE_LIST) | awk 'BEGIN {FS = ":.*?## "}; {printf "  %-12s %s\n", $$1, $$2}'

check: fmt vet test ## Everything CI runs.

fmt: ## Fail if any file is not gofmt-formatted.
	@out=$$(gofmt -l .); if [ -n "$$out" ]; then echo "not formatted:"; echo "$$out"; exit 1; fi

vet: ## Run go vet.
	$(GO) vet ./...

test: ## Run all unit tests with the race detector.
	$(GO) test -race ./...

cover: ## Show test coverage per package.
	$(GO) test -cover ./...

live: ## Live checks: Phala preflight (no key), Phala calls (PHALA_API_KEY), NEAR calls (NEARAI_API_KEY).
	PRIVATEAI_LIVE=1 $(GO) test -count=1 -run Live -v ./provider/phala
	$(GO) test -count=1 -run Live -v ./provider/near

crosscheck: ## Compare with Phala's official verifier (see tools/crosscheck/README.md; needs W=<workdir>).
	@test -n "$(W)" || (echo "usage: make crosscheck W=<workdir>" && exit 1)
	PRIVATEAI_CROSSCHECK_DIR=$(W) $(GO) test -count=1 -run CrossCheck -v ./provider/phala
