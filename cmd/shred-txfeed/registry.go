//go:build linux

package main

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"slices"
	"time"

	"github.com/blockcast/go-amt/txfeed"
)

// registry polls the W9 channel registry (BLO-46422), a Solana program, for
// the publisher's active channels: the filter channels it sends besides the
// static -channel6 ones.
type registry struct {
	url       string // Solana JSON-RPC endpoint
	program   txfeed.Pubkey
	publisher txfeed.Pubkey
	port      uint16
}

// registryPoll is the result of one poll.
type registryPoll struct {
	chans   []txfeed.Channel
	skipped int
	err     error
}

// newRegistry returns the registry the flags name, or nil when url is empty.
func newRegistry(url, program, publisher string, port int, poll time.Duration, add int, stale time.Duration) (*registry, error) {
	if url == "" {
		if program != "" || publisher != "" {
			return nil, errors.New("-registry-program and -registry-publisher need -registry-rpc")
		}
		return nil, nil
	}
	if poll <= 0 || add < 1 || stale < poll {
		return nil, fmt.Errorf("-registry-poll %v, -registry-add %d, -registry-stale %v: want a positive poll, at least 1 add, and stale at least the poll", poll, add, stale)
	}
	r := &registry{url: url, port: uint16(port)}
	var err error
	if r.program, err = txfeed.ParsePubkey(program); err != nil {
		return nil, fmt.Errorf("-registry-program: %w", err)
	}
	if r.publisher, err = txfeed.ParsePubkey(publisher); err != nil {
		return nil, fmt.Errorf("-registry-publisher: %w", err)
	}
	return r, nil
}

// run polls now and then every interval, sending each result to out.
func (r *registry) run(every time.Duration, out chan<- registryPoll) {
	for {
		ctx, cancel := context.WithTimeout(context.Background(), every)
		chans, skipped, err := r.poll(ctx)
		cancel()
		out <- registryPoll{chans, skipped, err}
		time.Sleep(every)
	}
}

// memcmp is a getProgramAccounts filter: the account has b at offset.
func memcmp(offset int, b []byte) map[string]any {
	return map[string]any{"memcmp": map[string]any{"offset": offset, "bytes": txfeed.Base58Encode(b)}}
}

// poll returns the publisher's active registry channels, sorted, and how many
// accounts it skipped. The RPC filters on the discriminator, the status and
// the publisher, and returns only each account's first
// txfeed.RegistryChannelPrefix bytes; poll checks all of it again, so a
// channel on a txfeed.RefusedKeys key, on another port, in an unknown layout
// or with a wrong stored group is skipped, not sent.
func (r *registry) poll(ctx context.Context) (chans []txfeed.Channel, skipped int, err error) {
	body, err := json.Marshal(map[string]any{
		"jsonrpc": "2.0", "id": 1, "method": "getProgramAccounts",
		"params": []any{r.program.String(), map[string]any{
			"encoding":   "base64",
			"commitment": "confirmed",
			"dataSlice":  map[string]int{"offset": 0, "length": txfeed.RegistryChannelPrefix},
			"filters": []any{
				memcmp(0, []byte{txfeed.RegistryChannelDiscriminator}),
				memcmp(txfeed.RegistryStatusOffset, []byte{byte(txfeed.RegistryActive)}),
				memcmp(txfeed.RegistryPublisherOffset, r.publisher[:]),
			},
		}},
	})
	if err != nil {
		return nil, 0, err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, r.url, bytes.NewReader(body))
	if err != nil {
		return nil, 0, err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, 0, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, 0, fmt.Errorf("getProgramAccounts: HTTP %s", resp.Status)
	}
	var out struct {
		Result []struct {
			Pubkey  string
			Account struct{ Data []string } // [base64, "base64"]
		}
		Error *struct {
			Code    int
			Message string
		}
	}
	// One reply holds the whole set. Its size is bounded: the program caps a
	// publisher's active channels at its config's max_active (256 by default).
	if err := json.NewDecoder(io.LimitReader(resp.Body, 8<<20)).Decode(&out); err != nil {
		return nil, 0, fmt.Errorf("getProgramAccounts: %w", err)
	}
	if out.Error != nil {
		return nil, 0, fmt.Errorf("getProgramAccounts: RPC error %d: %s", out.Error.Code, out.Error.Message)
	}
	for _, a := range out.Result {
		c, ok := r.check(a.Account.Data)
		if !ok {
			skipped++
			continue
		}
		if !slices.Contains(chans, c) {
			chans = append(chans, c)
		}
	}
	slices.SortFunc(chans, func(a, b txfeed.Channel) int {
		if a.Kind != b.Kind {
			return int(a.Kind) - int(b.Kind)
		}
		return bytes.Compare(a.Key[:], b.Key[:])
	})
	return chans, skipped, nil
}

// check decodes one getProgramAccounts data value and reports whether it is
// a channel this publisher may send.
func (r *registry) check(data []string) (txfeed.Channel, bool) {
	if len(data) != 2 || data[1] != "base64" {
		return txfeed.Channel{}, false
	}
	b, err := base64.StdEncoding.DecodeString(data[0])
	if err != nil {
		return txfeed.Channel{}, false
	}
	c, err := txfeed.ParseRegistryChannel(b)
	if err != nil || c.Status != txfeed.RegistryActive || c.Publisher != r.publisher || c.Port != r.port ||
		slices.ContainsFunc(txfeed.RefusedKeys, func(n txfeed.Named) bool { return n.ID == c.Key }) {
		return txfeed.Channel{}, false
	}
	return c.Channel, true
}

// nextChannels returns the channels to send after a registry poll: every
// static one, then each polled channel already being sent, then at most
// addMax new polled ones in poll order, limit in all, so that new (S,G)
// state reaches the MX at a bounded rate. A channel the poll no longer
// returns stops at once.
func nextChannels(static, current, polled []txfeed.Channel, addMax, limit int) (next, added, dropped []txfeed.Channel) {
	next = slices.Clone(static)
	for _, c := range polled {
		if len(next) < limit && slices.Contains(current, c) && !slices.Contains(next, c) {
			next = append(next, c)
		}
	}
	for _, c := range polled {
		if len(added) == addMax || len(next) == limit {
			break
		}
		if !slices.Contains(next, c) {
			next = append(next, c)
			added = append(added, c)
		}
	}
	for _, c := range current {
		if !slices.Contains(next, c) {
			dropped = append(dropped, c)
		}
	}
	return next, added, dropped
}
