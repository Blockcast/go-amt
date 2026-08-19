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

// ArrivalsCapForTest reports the capacity of the arrival backing array.
//
// Resident memory after a burst is a property of capacity, not length: the
// drain filters in place, so a test asserting only len() would pass against a
// buffer still pinning its high-water mark.
func (t *Tracker) ArrivalsCapForTest() int {
	t.mu.Lock()
	defer t.mu.Unlock()
	return cap(t.arrivals)
}
