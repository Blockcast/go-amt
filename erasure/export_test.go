package erasure

// Test-only views of the guard tuning constants.
//
// The black-box tests in erasure_test drive the resync and self-heal thresholds
// directly. Re-declaring the values there would let the tests keep passing
// against a changed constant while asserting the old contract, so they are
// exported through the package itself instead.
const (
	MaxSlotJumpForTest               = maxSlotJump
	SlotResyncThresholdForTest       = slotResyncThreshold
	FrontierDistrustThresholdForTest = frontierDistrustThreshold
	MinRetainedCapacityForTest       = minRetainedCapacity
)

// ScoresCapForTest reports the capacity of the score-event backing array.
//
// Resident memory after a burst is a property of capacity, not length: the
// drain filters in place, so a test asserting only len() would pass against a
// buffer still pinning its high-water mark.
//
// This used to read the arrival backing array as well. BLO-28451 replaced that
// slice with the fixed-size deliveryWindow fold, so there is no arrival
// capacity left to observe -- the retention it measured is gone rather than
// merely bounded. t.scores is the last in-place-filtered slice and the only
// remaining caller of releaseUnused, so the burst-retention contract is pinned
// here instead of being dropped with the field.
func (t *Tracker) ScoresCapForTest() int {
	t.mu.Lock()
	defer t.mu.Unlock()
	return cap(t.scores)
}
