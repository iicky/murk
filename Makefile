SHELL := /bin/bash
MURK := $(CURDIR)/target/release/murk
GIT_ENV := GIT_AUTHOR_NAME=test GIT_AUTHOR_EMAIL=test@murk GIT_COMMITTER_NAME=test GIT_COMMITTER_EMAIL=test@murk

.PHONY: build test test-demos test-hero test-team test-offboard test-eve test-recovery

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
	export $(GIT_ENV) && \
	set -e && \
	base=$$(mktemp -d) && \
	trap "rm -rf $$base" EXIT && \
	alice=$$base/alice && bob=$$base/bob && remote=$$base/remote && \
	mkdir -p $$alice $$bob && \
	git init --bare $$remote >/dev/null && \
	cd $$alice && \
	echo "alice" | $(MURK) init >/dev/null && \
	eval $$(cat .env) && \
	ALICE_KEY=$$MURK_KEY && \
	echo "secret1" | $(MURK) add DATABASE_URL --desc "Production database" >/dev/null && \
	echo "secret2" | $(MURK) add API_KEY >/dev/null && \
	echo "secret3" | $(MURK) add STRIPE_SECRET >/dev/null && \
	git init >/dev/null && git checkout -b main >/dev/null && \
	git add .murk && git commit -m "init" >/dev/null && \
	git remote add origin $$remote && \
	git push -u origin main >/dev/null && \
	echo "localhost:5432/dev" | $(MURK) add DATABASE_URL --scoped >/dev/null && \
	$(MURK) export 2>/dev/null | grep -q "localhost" && \
	cd $$bob && unset MURK_KEY && \
	git clone $$remote . >/dev/null && \
	$(MURK) init >/dev/null && \
	eval $$(cat .env) && \
	BOB_KEY=$$MURK_KEY && \
	BOB_PUBKEY=$$($(MURK) init 2>&1 | grep "^age1") && \
	cd $$alice && export MURK_KEY=$$ALICE_KEY && \
	$(MURK) authorize $$BOB_PUBKEY bob >/dev/null && \
	git add .murk && git commit -m "add bob" >/dev/null && \
	git push >/dev/null && \
	cd $$bob && export MURK_KEY=$$BOB_KEY && \
	git pull >/dev/null && \
	$(MURK) info 2>/dev/null | grep -q "2 recipients" && \
	$(MURK) get DATABASE_URL 2>/dev/null | grep -q "secret1" && \
	echo "ok"

test-offboard: build
	@printf "  %-12s" "offboard" && \
	export $(GIT_ENV) && \
	set -e && \
	base=$$(mktemp -d) && \
	trap "rm -rf $$base" EXIT && \
	alice=$$base/alice && bob=$$base/bob && carol=$$base/carol && remote=$$base/remote && \
	mkdir -p $$alice $$bob $$carol && \
	git init --bare $$remote >/dev/null 2>&1 && \
	cd $$alice && \
	echo "alice" | $(MURK) init >/dev/null 2>&1 && \
	eval $$(cat .env) && \
	ALICE_KEY=$$MURK_KEY && \
	echo "secret1" | $(MURK) add DATABASE_URL >/dev/null 2>&1 && \
	echo "secret2" | $(MURK) add API_KEY >/dev/null 2>&1 && \
	echo "secret3" | $(MURK) add STRIPE_SECRET >/dev/null 2>&1 && \
	git init >/dev/null 2>&1 && git checkout -b main >/dev/null 2>&1 && \
	git add .murk && git commit -m "init" >/dev/null 2>&1 && \
	git remote add origin $$remote && \
	git push -u origin main >/dev/null 2>&1 && \
	cd $$bob && unset MURK_KEY && \
	git clone $$remote . >/dev/null 2>&1 && \
	$(MURK) init >/dev/null 2>&1 && \
	eval $$(cat .env) && \
	BOB_KEY=$$MURK_KEY && \
	BOB_PUBKEY=$$($(MURK) init 2>&1 | grep "^age1") && \
	cd $$carol && unset MURK_KEY && \
	git clone $$remote . >/dev/null 2>&1 && \
	$(MURK) init >/dev/null 2>&1 && \
	eval $$(cat .env) && \
	CAROL_KEY=$$MURK_KEY && \
	CAROL_PUBKEY=$$($(MURK) init 2>&1 | grep "^age1") && \
	cd $$alice && export MURK_KEY=$$ALICE_KEY && \
	$(MURK) authorize $$BOB_PUBKEY bob >/dev/null 2>&1 && \
	$(MURK) authorize $$CAROL_PUBKEY carol >/dev/null 2>&1 && \
	git add .murk && git commit -m "add team" >/dev/null 2>&1 && \
	git push >/dev/null 2>&1 && \
	cd $$bob && export MURK_KEY=$$BOB_KEY && git pull >/dev/null 2>&1 && \
	cd $$carol && export MURK_KEY=$$CAROL_KEY && git pull >/dev/null 2>&1 && \
	cd $$bob && export MURK_KEY=$$BOB_KEY && \
	$(MURK) recipients 2>/dev/null | grep -q "carol" && \
	$(MURK) revoke carol >/dev/null 2>&1 && \
	echo "rotated1" | $(MURK) add DATABASE_URL >/dev/null 2>&1 && \
	echo "rotated2" | $(MURK) add API_KEY >/dev/null 2>&1 && \
	echo "rotated3" | $(MURK) add STRIPE_SECRET >/dev/null 2>&1 && \
	! $(MURK) recipients 2>/dev/null | grep -q "carol" && \
	git add .murk && git commit -m "revoke carol" >/dev/null 2>&1 && \
	git push >/dev/null 2>&1 && \
	cd $$carol && export MURK_KEY=$$CAROL_KEY && \
	$(MURK) export >/dev/null 2>&1 && \
	git pull >/dev/null 2>&1 && \
	! $(MURK) export >/dev/null 2>&1 && \
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
