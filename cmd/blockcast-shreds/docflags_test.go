package main

import (
	"os"
	"regexp"
	"sort"
	"strings"
	"testing"
)

// The operator install document shipped a `--retain` and a `--health-max-age`
// row for flags that were never registered, and told operators to tune the
// first one. Because the flag set is built with flag.ContinueOnError, following
// that advice exits the process non-zero, which under the systemd unit's
// Restart=on-failure is a restart loop caused by the documentation. These two
// tests make that class of drift a build failure in both directions.

const installDoc = "../../docs/operations/install.md"

// docTableFlags returns the flag names in the install document's config table.
// Rows look like: | `--listen` | `0.0.0.0:20000` | Unicast UDP ingress address. |
func docTableFlags(t *testing.T) []string {
	t.Helper()
	body, err := os.ReadFile(installDoc)
	if err != nil {
		t.Fatalf("read %s: %v", installDoc, err)
	}
	// Only the leading token of the cell, so `--feed NAME=IP:PORT` yields "feed".
	row := regexp.MustCompile("(?m)^\\|\\s*`--([a-z0-9-]+)[^`]*`\\s*\\|")
	var names []string
	for _, m := range row.FindAllStringSubmatch(string(body), -1) {
		names = append(names, m[1])
	}
	if len(names) == 0 {
		t.Fatalf("no flag rows found in %s — the table format changed and this "+
			"test is no longer checking anything", installDoc)
	}
	sort.Strings(names)
	return names
}

// registeredFlags returns the flag names main.go registers on the main flag set.
// The selftest sub-command builds its own FlagSet with its own --json and a
// --fixture that the config table deliberately does not cover, so the scan is
// scoped to run()'s body: from its NewFlagSet to the start of func selftest.
//
// run() is no longer the only place registration happens. BLO-28993 moved the
// three scoring flags into scoringFlags, a helper that sits AFTER func selftest
// and so falls outside the window above. That made this scan report --mode,
// --source-label and --rights-basis as documented-but-unregistered while
// TestDocumentedFlagsAreAccepted simultaneously proved the parser accepts all
// three ("flag needs an argument", not "not defined") -- a false failure in the
// doc-drift direction and, worse, a blind spot in the other: a flag registered
// only in the helper could go undocumented without this test noticing. So every
// registrar run() delegates to is scanned as well, and a registrar this list
// cannot find is a hard failure rather than a silent under-count.
func registeredFlags(t *testing.T) []string {
	t.Helper()
	source, err := os.ReadFile("main.go")
	if err != nil {
		t.Fatalf("read main.go: %v", err)
	}
	full := string(source)
	start := strings.Index(full, `flag.NewFlagSet("blockcast-shreds"`)
	end := strings.Index(full, "func selftest(")
	if start < 0 || end < 0 || end <= start {
		t.Fatalf("could not isolate run()'s flag set in main.go (start=%d end=%d); "+
			"the file was restructured and this scan is no longer reliable", start, end)
	}
	body := full[start:end]

	// Helpers run() hands the flag set to. Scanned in full, because the names
	// they register are indistinguishable from run()'s own to an operator.
	for _, registrar := range []string{"func scoringFlags("} {
		at := strings.Index(full, registrar)
		if at < 0 {
			t.Fatalf("main.go no longer contains %q, which registeredFlags scans for "+
				"delegated flag registrations. If it was renamed or inlined, update "+
				"this list: dropping it silently hides every flag it registers from "+
				"both directions of TestHelpDocumentsEveryFlag.", registrar)
		}
		rest := full[at+len(registrar):]
		stop := strings.Index(rest, "\nfunc ")
		if stop < 0 {
			stop = len(rest)
		}
		body += rest[:stop]
	}

	// flags.StringVar(&x, "name", ...) / flags.Bool("name", ...) / flags.Var(&x, "name", ...)
	//
	// The leading-argument group is deliberately "any run of non-comma,
	// non-quote characters" rather than "&something". BLO-28993 registers the
	// scoring flags as flags.Var(stringFlag[T]{&field}, "name", ...), whose
	// first argument is a composite literal and not an address-of expression, so
	// an &-anchored pattern silently skipped all three: they matched nothing and
	// were reported as documented-but-unregistered. Verified across all ten
	// registration forms in this file -- the seven &-style and Bool/Int/Duration
	// ones still yield the same names.
	call := regexp.MustCompile(`flags\.(?:[A-Za-z0-9]*Var|Bool|String|Int|Int64|Uint|Uint64|Float64|Duration)\(\s*(?:[^,"]+,\s*)?"([a-z0-9-]+)"`)
	var names []string
	for _, m := range call.FindAllStringSubmatch(body, -1) {
		names = append(names, m[1])
	}
	if len(names) < 5 {
		t.Fatalf("found only %d flag registrations in run() (%v); the "+
			"registration form changed and this scan is no longer reliable",
			len(names), names)
	}
	sort.Strings(names)
	return names
}

// TestHelpDocumentsEveryFlag fails if the install document's config table and
// the registered flag set disagree in either direction.
func TestHelpDocumentsEveryFlag(t *testing.T) {
	documented := docTableFlags(t)
	registered := registeredFlags(t)

	inDoc := map[string]bool{}
	for _, n := range documented {
		inDoc[n] = true
	}
	inCode := map[string]bool{}
	for _, n := range registered {
		inCode[n] = true
	}

	for _, n := range documented {
		if !inCode[n] {
			t.Errorf("%s documents --%s, which the binary does not register. "+
				"An operator who puts it in BLOCKCAST_SHREDS_ARGS gets a parse "+
				"error and, under Restart=on-failure, a restart loop.",
				installDoc, n)
		}
	}
	for _, n := range registered {
		if !inDoc[n] {
			t.Errorf("main.go registers --%s but %s does not document it", n, installDoc)
		}
	}
	t.Logf("documented=%v registered=%v", documented, registered)
}

// TestDocumentedFlagsAreAccepted proves definedness behaviourally rather than by
// reading the source a second time: every documented flag is probed with a form
// that must fail at parse time, and the failure must not be "not defined".
func TestDocumentedFlagsAreAccepted(t *testing.T) {
	// A probe whose parse must fail, so no receiver is ever started. Value-taking
	// flags are probed with no value; the bool flag is probed with a bad value.
	probes := map[string][]string{
		"feed":           {"--feed"},
		"listen":         {"--listen"},
		"dest-ip-ports":  {"--dest-ip-ports"},
		"http-addr":      {"--http-addr"},
		"json":           {"--json=not-a-bool"},
		"mode":           {"--mode"},
		"source-label":   {"--source-label"},
		"rights-basis":   {"--rights-basis"},
		"health-max-age": {"--health-max-age"},
		"retain":         {"--retain"},
		// Probed with no value, like the other value-taking flags. A probe that
		// supplied a real path would parse, fall through to listenAndScore and
		// hang the package on the test timeout -- the trap TestUndefinedFlagIsRejected
		// documents below.
		"delivery-wal":     {"--delivery-wal"},
		"delivery-records": {"--delivery-records"},
		"erasure-grace-ms": {"--erasure-grace-ms"},
		"report-interval":  {"--report-interval"},
		// Probed with no value for the same reason as --delivery-wal above: the
		// pair is validated together at startup, so a probe supplying both real
		// values would parse, fall through to listenAndScore and hang the
		// package. Probing one of the pair with no value fails in the parser,
		// before heartbeatOptions ever runs.
		"broker-url": {"--broker-url"},
		"gw-uuid":    {"--gw-uuid"},
	}

	for _, name := range docTableFlags(t) {
		args, ok := probes[name]
		if !ok {
			t.Errorf("%s documents --%s but this test has no probe for it; add "+
				"one so the flag's existence stays verified", installDoc, name)
			continue
		}
		err := run(args)
		if err == nil {
			t.Errorf("--%s: probe %v was expected to fail at parse time", name, args)
			continue
		}
		if strings.Contains(err.Error(), "not defined") {
			t.Errorf("--%s is documented but not registered: %v", name, err)
		}
	}
}

// TestUndefinedFlagIsRejected pins the premise the tests above rely on: an
// unknown flag is a hard error, not a warning.
//
// The probe must be a name that can never become a real flag. It used to be
// `--retain`, chosen because the document once advertised a `--retain` that did
// not exist — but BLO-28422 made `--retain` real, and the failure mode was not a
// clean assertion failure. A defined flag parses, `run` falls through to
// listenAndScore, the receiver binds its sockets and blocks on its signal
// channel, and the package dies on the 10-minute test timeout with this test
// named as the one still running. So picking a plausible-but-currently-absent
// flag here converts a future feature into a CI hang, which is why the probe is
// now a name nobody would ship.
func TestUndefinedFlagIsRejected(t *testing.T) {
	err := run([]string{"--not-a-real-flag-and-never-will-be", "4s"})
	if err == nil {
		t.Fatal("expected an unknown flag to be rejected")
	}
	if !strings.Contains(err.Error(), "not defined") {
		t.Fatalf("expected a 'not defined' parse error, got: %v", err)
	}
}

// TestNoUndefinedFlagMentionedAnywhereInDoc is the wider net. Scoping the check
// to the config table is not enough: the first pass at this fix removed the
// phantom `--retain` and `--health-max-age` rows but left two prose references
// that described the same nonexistent knobs, including one that stated the
// scoring deadline in terms of a `--retain` window that does not exist. Any
// `--flag` token anywhere in the document must be a real flag.
func TestNoUndefinedFlagMentionedAnywhereInDoc(t *testing.T) {
	body, err := os.ReadFile(installDoc)
	if err != nil {
		t.Fatalf("read %s: %v", installDoc, err)
	}

	registered := map[string]bool{}
	for _, n := range registeredFlags(t) {
		registered[n] = true
	}
	// Flags of other commands the document legitimately mentions. Each entry is
	// a deliberate exemption, so a genuinely phantom blockcast-shreds flag still
	// fails rather than being waved through.
	allowed := map[string]bool{
		"fixture":        true, // blockcast-shreds selftest sub-command
		"snapshot":       true, // goreleaser build
		"clean":          true, // goreleaser build
		"push":           true, // docker build
		"check":          true, // sha256sum
		"ignore-missing": true, // sha256sum
		"build-arg":      true, // docker build
		"now":            true, // systemctl enable --now
		"version":        true, // systemctl --version
		"since":          true, // journalctl --since
	}

	token := regexp.MustCompile(`--([a-z][a-z0-9-]{2,})`)
	seen := map[string]bool{}
	for _, m := range token.FindAllStringSubmatch(string(body), -1) {
		name := m[1]
		if seen[name] || registered[name] || allowed[name] {
			continue
		}
		seen[name] = true
		t.Errorf("%s mentions --%s, which is not a registered flag of "+
			"blockcast-shreds and is not in this test's allow-list of "+
			"other-command flags. Either the doc is describing a knob that "+
			"does not exist, or the allow-list needs the new entry.", installDoc, name)
	}
}
