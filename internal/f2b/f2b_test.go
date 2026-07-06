package f2b

import (
	"bytes"
	"context"
	"encoding/binary"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"reflect"
	"testing"
	"time"
)

// --- pickle encoder ---

func TestPickleCommand(t *testing.T) {
	got := pickleCommand([]string{"ping"})
	want := []byte("(Vping\nl.")
	if !bytes.Equal(got, want) {
		t.Errorf("pickleCommand: got %q want %q", got, want)
	}

	got = pickleCommand([]string{"set", "sshd", "maxretry", "5"})
	want = []byte("(Vset\nVsshd\nVmaxretry\nV5\nl.")
	if !bytes.Equal(got, want) {
		t.Errorf("pickleCommand: got %q want %q", got, want)
	}
}

func TestEscapeRawUnicode(t *testing.T) {
	// Backslash and newline must be escaped so the V-opcode line stays intact,
	// and the escaped form must round-trip through the decoder.
	in := `a\b` + "\n"
	got := escapeRawUnicode(in)
	if want := "a\\u005cb\\u000a"; got != want {
		t.Errorf("escape: got %q want %q", got, want)
	}
	if back := unescapeRawUnicode(got); back != in {
		t.Errorf("round-trip: got %q want %q", back, in)
	}
	if got := escapeRawUnicode("plain-ascii_1.2.3.4"); got != "plain-ascii_1.2.3.4" {
		t.Errorf("escape ascii must be identity, got %q", got)
	}
}

// --- unpickler fixtures (hand-assembled pickle streams) ---

func p2str(s string) []byte {
	b := []byte{'X'}
	b = binary.LittleEndian.AppendUint32(b, uint32(len(s)))
	return append(b, s...)
}

func TestUnpickle_Protocol2Tuple(t *testing.T) {
	// pickle.dumps((0, 1), 2) → PROTO 2, BININT1 0, BININT1 1, TUPLE2, STOP
	data := []byte{0x80, 0x02, 'K', 0x00, 'K', 0x01, 0x86, '.'}
	v, err := unpickle(data)
	if err != nil {
		t.Fatalf("unpickle: %v", err)
	}
	if !reflect.DeepEqual(v, []any{int64(0), int64(1)}) {
		t.Errorf("got %#v", v)
	}
}

func TestUnpickle_Protocol4Frame(t *testing.T) {
	// PROTO 4, FRAME, BININT1 0, SHORT_BINUNICODE "pong", MEMOIZE, TUPLE2, MEMOIZE, STOP
	body := []byte{'K', 0x00, 0x8c, 4, 'p', 'o', 'n', 'g', 0x94, 0x86, 0x94, '.'}
	data := []byte{0x80, 0x04, 0x95}
	data = binary.LittleEndian.AppendUint64(data, uint64(len(body)))
	data = append(data, body...)
	v, err := unpickle(data)
	if err != nil {
		t.Fatalf("unpickle: %v", err)
	}
	if !reflect.DeepEqual(v, []any{int64(0), "pong"}) {
		t.Errorf("got %#v", v)
	}
}

func TestUnpickle_Protocol0(t *testing.T) {
	// pickle.dumps((0, 'pong'), 0) — MARK INT STRING TUPLE PUT STOP
	data := []byte("(I0\nS'pong'\ntp0\n.")
	v, err := unpickle(data)
	if err != nil {
		t.Fatalf("unpickle: %v", err)
	}
	if !reflect.DeepEqual(v, []any{int64(0), "pong"}) {
		t.Errorf("got %#v", v)
	}
}

func TestUnpickle_ExceptionResponse(t *testing.T) {
	// (1, CommandException('Invalid command')) in protocol 2:
	// PROTO2, BININT1 1, GLOBAL, BINUNICODE, TUPLE1, REDUCE, TUPLE2, STOP
	var data []byte
	data = append(data, 0x80, 0x02, 'K', 0x01)
	data = append(data, 'c')
	data = append(data, "fail2ban.exceptions\nCommandException\n"...)
	data = append(data, p2str("Invalid command")...)
	data = append(data, 0x85, 'R', 0x86, '.')

	v, err := unpickle(data)
	if err != nil {
		t.Fatalf("unpickle: %v", err)
	}
	_, err = interpretResponse(v)
	if err == nil {
		t.Fatal("want error for code=1 response")
	}
	if want := "CommandException(Invalid command)"; !bytes.Contains([]byte(err.Error()), []byte(want)) {
		t.Errorf("error must contain %q, got: %v", want, err)
	}
}

func TestUnpickle_NestedStatus(t *testing.T) {
	// (0, [["Actions", [["Banned IP list", ["1.2.3.4", "5.6.7.8"]]]]])
	var data []byte
	data = append(data, 0x80, 0x02, 'K', 0x00)
	data = append(data, ']', '(') // outer list, mark
	data = append(data, ']', '(') // ["Actions", …]
	data = append(data, p2str("Actions")...)
	data = append(data, ']', '(') // actions list
	data = append(data, ']', '(') // ["Banned IP list", …]
	data = append(data, p2str("Banned IP list")...)
	data = append(data, ']', '(') // ip list
	data = append(data, p2str("1.2.3.4")...)
	data = append(data, p2str("5.6.7.8")...)
	data = append(data, 'e') // close ip list
	data = append(data, 'e') // close ["Banned IP list", ips]
	data = append(data, 'e') // close actions list
	data = append(data, 'e') // close ["Actions", …]
	data = append(data, 'e') // close outer list
	data = append(data, 0x86, '.')

	v, err := unpickle(data)
	if err != nil {
		t.Fatalf("unpickle: %v", err)
	}
	payload, err := interpretResponse(v)
	if err != nil {
		t.Fatalf("interpret: %v", err)
	}
	ips := findStatusList(payload, "Banned IP list")
	if !reflect.DeepEqual(ips, []any{"1.2.3.4", "5.6.7.8"}) {
		t.Errorf("banned list: got %#v", ips)
	}
}

func TestUnpickle_Scalars(t *testing.T) {
	cases := []struct {
		name string
		data []byte
		want any
	}{
		{"none", []byte{'N', '.'}, nil},
		{"true", []byte{0x88, '.'}, true},
		{"binint", []byte{'J', 0x2e, 0xfb, 0xff, 0xff, '.'}, int64(-1234)},
		{"long1", []byte{0x8a, 0x02, 0x10, 0x0e, '.'}, int64(3600)},
		{"long1-neg", []byte{0x8a, 0x01, 0xff, '.'}, int64(-1)},
		{"float", append(append([]byte{'G'}, binary.BigEndian.AppendUint64(nil, 0x3ff0000000000000)...), '.'), float64(1.0)},
		{"unicode-v", []byte("Vcaf\\u00e9\n."), "café"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			v, err := unpickle(c.data)
			if err != nil {
				t.Fatalf("unpickle: %v", err)
			}
			if !reflect.DeepEqual(v, c.want) {
				t.Errorf("got %#v want %#v", v, c.want)
			}
		})
	}
}

func TestUnpickle_Memo(t *testing.T) {
	// [x, x] where x is memoized: PROTO2, EMPTY_LIST, MARK, str BINPUT 0, BINGET 0, APPENDS, STOP
	var data []byte
	data = append(data, 0x80, 0x02, ']', '(')
	data = append(data, p2str("dup")...)
	data = append(data, 'q', 0x00, 'h', 0x00, 'e', '.')
	v, err := unpickle(data)
	if err != nil {
		t.Fatalf("unpickle: %v", err)
	}
	if !reflect.DeepEqual(v, []any{"dup", "dup"}) {
		t.Errorf("got %#v", v)
	}
}

// --- socket round-trip against a fake fail2ban server ---

// fakeServer answers every command with the given raw pickle payload.
func fakeServer(t *testing.T, respond func(cmd []string) []byte) string {
	t.Helper()
	sock := filepath.Join(os.TempDir(), fmt.Sprintf("f2b-test-%d.sock", time.Now().UnixNano()))
	ln, err := net.Listen("unix", sock)
	if err != nil {
		t.Skipf("unix sockets unavailable: %v", err)
	}
	t.Cleanup(func() { ln.Close(); os.Remove(sock) })

	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				var buf bytes.Buffer
				tmp := make([]byte, 1024)
				for {
					n, err := c.Read(tmp)
					if n > 0 {
						buf.Write(tmp[:n])
						if bytes.HasSuffix(buf.Bytes(), []byte(endMarker)) {
							break
						}
					}
					if err != nil {
						return
					}
				}
				payload := bytes.TrimSuffix(buf.Bytes(), []byte(endMarker))
				req, err := unpickle(payload)
				if err != nil {
					return
				}
				var cmd []string
				if lst, ok := req.([]any); ok {
					for _, e := range lst {
						if s, ok := e.(string); ok {
							cmd = append(cmd, s)
						}
					}
				}
				resp := respond(cmd)
				_, _ = c.Write(append(resp, []byte(endMarker)...))
			}(conn)
		}
	}()
	return sock
}

// resp2 encodes (0, payloadOpcodes) in protocol 2 for the fake server.
func respOK(payload []byte) []byte {
	out := []byte{0x80, 0x02, 'K', 0x00}
	out = append(out, payload...)
	return append(out, 0x86, '.')
}

func TestClient_ExecPing(t *testing.T) {
	sock := fakeServer(t, func(cmd []string) []byte {
		if len(cmd) == 1 && cmd[0] == "ping" {
			return respOK(p2str("pong"))
		}
		return respOK([]byte{'N'})
	})
	c := NewClient(sock)
	v, err := c.Exec(context.Background(), "ping")
	if err != nil {
		t.Fatalf("Exec: %v", err)
	}
	if v != "pong" {
		t.Errorf("got %#v", v)
	}
}

func TestManager_SetAndGetJail(t *testing.T) {
	state := map[string]int64{"maxretry": 5, "bantime": 600, "findtime": 600}
	sock := fakeServer(t, func(cmd []string) []byte {
		switch {
		case len(cmd) == 3 && cmd[0] == "get":
			return respOK([]byte{0x8a, 0x04,
				byte(state[cmd[2]]), byte(state[cmd[2]] >> 8), byte(state[cmd[2]] >> 16), byte(state[cmd[2]] >> 24)})
		case len(cmd) == 4 && cmd[0] == "set":
			var n int64
			fmt.Sscanf(cmd[3], "%d", &n)
			state[cmd[2]] = n
			return respOK([]byte{0x8a, 0x04, byte(n), byte(n >> 8), byte(n >> 16), byte(n >> 24)})
		}
		return respOK([]byte{'N'})
	})

	m := NewManager(sock, "sshd")
	ctx := context.Background()
	if err := m.SetJail(ctx, JailSettings{MaxRetry: 3, BanTimeSecs: 7200, FindTimeSecs: 600}); err != nil {
		t.Fatalf("SetJail: %v", err)
	}
	got, err := m.GetJail(ctx)
	if err != nil {
		t.Fatalf("GetJail: %v", err)
	}
	want := JailSettings{MaxRetry: 3, BanTimeSecs: 7200, FindTimeSecs: 600}
	if got != want {
		t.Errorf("GetJail: got %+v want %+v", got, want)
	}
}

func TestManager_UnbanNotBannedIsNoError(t *testing.T) {
	sock := fakeServer(t, func(cmd []string) []byte {
		// (1, CommandException('1.2.3.4 is not banned'))
		var data []byte
		data = append(data, 'K', 0x01, 'c')
		data = append(data, "fail2ban.exceptions\nCommandException\n"...)
		data = append(data, p2str("1.2.3.4 is not banned")...)
		data = append(data, 0x85, 'R', 0x86, '.')
		return append([]byte{0x80, 0x02}, data...)
	})
	m := NewManager(sock, "sshd")
	if err := m.UnbanIP(context.Background(), "1.2.3.4"); err != nil {
		t.Errorf("UnbanIP of not-banned IP must be nil, got: %v", err)
	}
}
