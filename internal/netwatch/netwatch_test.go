package netwatch

import (
	"reflect"
	"testing"
)

func TestParseProcNetTCP(t *testing.T) {
	// Columns: sl local_address rem_address st ...
	// 0A = LISTEN, 01 = ESTABLISHED. Ports are hex: 1F90=8080, 0016=22, 0050=80.
	data := `  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt
   0: 0100007F:1F90 00000000:0000 0A 00000000:00000000 00:00000000 00000000
   1: 00000000:0016 00000000:0000 0A 00000000:00000000 00:00000000 00000000
   2: 0100007F:0050 0300007F:9AF2 01 00000000:00000000 00:00000000 00000000
   3: 00000000:0050 00000000:0000 0A 00000000:00000000 00:00000000 00000000
`
	got := parseProcNetTCP(data)
	want := []int{22, 80, 8080} // 8080 dedup across two rows would be one; 80 listens
	if !reflect.DeepEqual(got, want) {
		t.Errorf("got %v, want %v", got, want)
	}
}

func TestParseProcNetTCPEmpty(t *testing.T) {
	if got := parseProcNetTCP("header only\n"); len(got) != 0 {
		t.Errorf("expected no ports, got %v", got)
	}
}
