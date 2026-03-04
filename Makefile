SHELL := /bin/bash
MURK := $(CURDIR)/target/release/murk
MUSL_TARGET := x86_64-unknown-linux-musl

.PHONY: build test test-demos test-hero test-team test-offboard test-eve test-recovery test-vhs

build:
	cargo build --release

test:
	cargo nextest run

test-demos: build test-hero test-team test-offboard test-eve test-recovery
	@echo "\nall demo tests passed"

test-hero: build
	@printf "  %-12s" "hero" && \
	set -e && \
	dir=$$(mktemp -d) && \
	trap "rm -rf $$dir" EXIT && \
	cd $$dir && \
	echo "alice" | $(MURK) init >/dev/null 2>&1 && \
	eval $$(cat .env) && \
	echo "secret1" | $(MURK) add DATABASE_URL --desc "Production database" >/dev/null 2>&1 && \
	echo "secret2" | $(MURK) add API_KEY --desc "OpenAI API key" >/dev/null 2>&1 && \
	echo "secret3" | $(MURK) add STRIPE_SECRET --desc "Stripe secret key" >/dev/null 2>&1 && \
	$(MURK) info >/dev/null 2>&1 && \
	$(MURK) export >/dev/null 2>&1 && \
	echo "ok"

test-team: build
	@printf "  %-12s" "team" && \
	set -e && \
	export PATH="$(CURDIR)/target/release:$$PATH" && \
	source demo/setup.sh && \
	demo_init_dirs alice bob && \
	trap "demo_cleanup" EXIT && \
	demo_alice_vault && \
	echo "localhost:5432/dev" | murk add DATABASE_URL --scoped >/dev/null 2>&1 && \
	murk export 2>/dev/null | grep -q "localhost" && \
	demo_onboard bob && \
	demo_alice_authorize bob && \
	demo_alice_push "add bob" && \
	demo_pull bob && \
	murk info 2>/dev/null | grep -q "recipients" && \
	murk get DATABASE_URL 2>/dev/null | grep -q "db.example.com" && \
	echo "ok"

test-offboard: build
	@printf "  %-12s" "offboard" && \
	set -e && \
	export PATH="$(CURDIR)/target/release:$$PATH" && \
	source demo/setup.sh && \
	demo_init_dirs alice bob carol && \
	trap "demo_cleanup" EXIT && \
	demo_alice_vault && \
	demo_onboard bob && \
	demo_onboard carol && \
	demo_alice_authorize bob && \
	demo_alice_authorize carol && \
	demo_alice_push "add team" && \
	demo_pull bob && \
	demo_pull carol && \
	cd $$BOB_DIR && export MURK_KEY=$$BOB_KEY && \
	murk circle 2>/dev/null | grep -q "carol" && \
	murk circle revoke carol >/dev/null 2>&1 && \
	echo "rotated1" | murk add DATABASE_URL >/dev/null 2>&1 && \
	echo "rotated2" | murk add API_KEY >/dev/null 2>&1 && \
	echo "rotated3" | murk add STRIPE_SECRET >/dev/null 2>&1 && \
	! murk circle 2>/dev/null | grep -q "carol" && \
	git add .murk && git commit -m "revoke carol" >/dev/null 2>&1 && \
	git push >/dev/null 2>&1 && \
	cd $$CAROL_DIR && export MURK_KEY=$$CAROL_KEY && \
	murk export >/dev/null 2>&1 && \
	git pull >/dev/null 2>&1 && \
	! murk export >/dev/null 2>&1 && \
	echo "ok"

test-eve: build
	@printf "  %-12s" "eve" && \
	set -e && \
	base=$$(mktemp -d) && \
	trap "rm -rf $$base" EXIT && \
	alice=$$base/alice && eve=$$base/eve && \
	mkdir -p $$alice $$eve && \
	cd $$alice && \
	echo "alice" | $(MURK) init >/dev/null 2>&1 && \
	eval $$(cat .env) && \
	echo "secret1" | $(MURK) add DATABASE_URL --desc "Production database" >/dev/null 2>&1 && \
	echo "secret2" | $(MURK) add API_KEY >/dev/null 2>&1 && \
	cp .murk $$eve/ && \
	cd $$eve && unset MURK_KEY && \
	$(MURK) ls 2>/dev/null | grep -q "DATABASE_URL" && \
	$(MURK) info 2>/dev/null | grep -q "DATABASE_URL" && \
	! $(MURK) get DATABASE_URL >/dev/null 2>&1 && \
	! $(MURK) export >/dev/null 2>&1 && \
	echo "ok"

test-recovery: build
	@printf "  %-12s" "recovery" && \
	set -e && \
	dir=$$(mktemp -d) && \
	trap "rm -rf $$dir" EXIT && \
	cd $$dir && \
	echo "alice" | $(MURK) init >/dev/null 2>&1 && \
	eval $$(cat .env) && \
	ORIGINAL=$$MURK_KEY && \
	PHRASE=$$($(MURK) recover 2>/dev/null) && \
	RESTORED=$$($(MURK) restore "$$PHRASE" 2>/dev/null) && \
	test "$$ORIGINAL" = "$$RESTORED" && \
	echo "ok"

test-vhs:
	@command -v cross >/dev/null 2>&1 || { echo "error: cross not found — install with: cargo install cross --locked"; exit 1; }
	cross build --release --target $(MUSL_TARGET)
	@printf 'FROM ghcr.io/charmbracelet/vhs\nRUN apt-get update --allow-releaseinfo-change && apt-get install -y --no-install-recommends git && rm -rf /var/lib/apt/lists/*\n' | docker build -t vhs-git -
	@for tape in hero team offboard eve recovery; do \
		printf "  %-12s" "$$tape" && \
		docker run --rm -v $(CURDIR):/vhs -e PATH="/vhs/target/$(MUSL_TARGET)/release:$$PATH" vhs-git demo/$$tape.tape && \
		echo "ok"; \
	done
	@echo "\nall VHS tapes rendered"
