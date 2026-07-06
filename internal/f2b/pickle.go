// Package f2b talks to the fail2ban server over its local command socket.
//
// fail2ban's socket protocol is: a Python-pickled list of command strings,
// terminated by "<F2B_END_COMMAND>"; the response is a pickled (code, payload)
// tuple with the same terminator. Requests are encoded here with protocol-0
// opcodes (accepted by every Python 3 pickle.loads); responses are decoded by
// a small stack-machine unpickler covering the value shapes fail2ban emits:
// tuples, lists, dicts, ints, floats, strings, bytes, bools, None and pickled
// exception objects.
package f2b

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"math"
	"strconv"
	"strings"
)

// pickleCommand encodes a fail2ban command (a list of strings) as a
// protocol-0 pickle: MARK, one UNICODE line per argument, LIST, STOP.
func pickleCommand(args []string) []byte {
	var b bytes.Buffer
	b.WriteByte('(')
	for _, a := range args {
		b.WriteByte('V')
		b.WriteString(escapeRawUnicode(a))
		b.WriteByte('\n')
	}
	b.WriteByte('l')
	b.WriteByte('.')
	return b.Bytes()
}

// escapeRawUnicode encodes s for the pickle UNICODE ('V') opcode, which uses
// Python's raw-unicode-escape codec. Backslashes, newlines and non-ASCII
// runes are escaped as \uXXXX so the line stays unambiguous.
func escapeRawUnicode(s string) string {
	var b strings.Builder
	for _, r := range s {
		switch {
		case r == '\\' || r == '\n' || r == '\r' || r > 0x7e || r < 0x20:
			if r > 0xffff {
				r1, r2 := utf16Pair(r)
				fmt.Fprintf(&b, `\u%04x\u%04x`, r1, r2)
			} else {
				fmt.Fprintf(&b, `\u%04x`, r)
			}
		default:
			b.WriteRune(r)
		}
	}
	return b.String()
}

func utf16Pair(r rune) (rune, rune) {
	r -= 0x10000
	return 0xd800 + (r >> 10), 0xdc00 + (r & 0x3ff)
}

// PyClass is a reference to a Python class encountered while unpickling
// (GLOBAL / STACK_GLOBAL opcodes), e.g. a fail2ban exception class.
type PyClass struct {
	Module string
	Name   string
}

func (c *PyClass) String() string { return c.Module + "." + c.Name }

// PyObject is an instantiated Python object (REDUCE / NEWOBJ): typically an
// exception carried in an error response.
type PyObject struct {
	Class *PyClass
	Args  []any
	State any
}

func (o *PyObject) String() string {
	parts := make([]string, 0, len(o.Args))
	for _, a := range o.Args {
		parts = append(parts, Stringify(a))
	}
	return fmt.Sprintf("%s(%s)", o.Class, strings.Join(parts, ", "))
}

// Stringify renders an unpickled value for error messages.
func Stringify(v any) string {
	switch t := v.(type) {
	case nil:
		return "None"
	case string:
		return t
	case []byte:
		return string(t)
	case fmt.Stringer:
		return t.String()
	case []any:
		parts := make([]string, 0, len(t))
		for _, e := range t {
			parts = append(parts, Stringify(e))
		}
		return "[" + strings.Join(parts, ", ") + "]"
	default:
		return fmt.Sprintf("%v", t)
	}
}

type markType struct{}

var errStop = errors.New("pickle stop")

type unpickler struct {
	data  []byte
	pos   int
	stack []any
	memo  map[int]any
}

// unpickle decodes a pickle stream into Go values: int64, float64, string,
// []byte, bool, nil, []any (lists and tuples), map[any]any, *PyClass,
// *PyObject.
func unpickle(data []byte) (any, error) {
	u := &unpickler{data: data, memo: map[int]any{}}
	for {
		if u.pos >= len(u.data) {
			return nil, errors.New("pickle: unexpected end of stream")
		}
		op := u.data[u.pos]
		u.pos++
		err := u.step(op)
		if errors.Is(err, errStop) {
			if len(u.stack) == 0 {
				return nil, errors.New("pickle: empty stack at STOP")
			}
			return u.stack[len(u.stack)-1], nil
		}
		if err != nil {
			return nil, err
		}
	}
}

func (u *unpickler) push(v any) { u.stack = append(u.stack, v) }

func (u *unpickler) pop() (any, error) {
	if len(u.stack) == 0 {
		return nil, errors.New("pickle: pop from empty stack")
	}
	v := u.stack[len(u.stack)-1]
	u.stack = u.stack[:len(u.stack)-1]
	return v, nil
}

// popMark pops all values above the topmost MARK sentinel and removes it.
func (u *unpickler) popMark() ([]any, error) {
	for i := len(u.stack) - 1; i >= 0; i-- {
		if _, ok := u.stack[i].(markType); ok {
			items := make([]any, len(u.stack)-i-1)
			copy(items, u.stack[i+1:])
			u.stack = u.stack[:i]
			return items, nil
		}
	}
	return nil, errors.New("pickle: MARK not found")
}

func (u *unpickler) read(n int) ([]byte, error) {
	if n < 0 || u.pos+n > len(u.data) {
		return nil, errors.New("pickle: unexpected end of stream")
	}
	b := u.data[u.pos : u.pos+n]
	u.pos += n
	return b, nil
}

func (u *unpickler) readLine() (string, error) {
	idx := bytes.IndexByte(u.data[u.pos:], '\n')
	if idx < 0 {
		return "", errors.New("pickle: unterminated line")
	}
	s := string(u.data[u.pos : u.pos+idx])
	u.pos += idx + 1
	return s, nil
}

func (u *unpickler) memoize(v any) { u.memo[len(u.memo)] = v }

//nolint:gocyclo // a pickle VM is inherently one big opcode switch
func (u *unpickler) step(op byte) error {
	switch op {
	case 0x80: // PROTO
		_, err := u.read(1)
		return err
	case 0x95: // FRAME
		_, err := u.read(8)
		return err
	case '.': // STOP
		return errStop
	case '(': // MARK
		u.push(markType{})
	case ')': // EMPTY_TUPLE
		u.push([]any{})
	case 't': // TUPLE
		items, err := u.popMark()
		if err != nil {
			return err
		}
		u.push(items)
	case 0x85, 0x86, 0x87: // TUPLE1, TUPLE2, TUPLE3
		n := int(op) - 0x84
		if len(u.stack) < n {
			return errors.New("pickle: short stack for TUPLE")
		}
		items := make([]any, n)
		copy(items, u.stack[len(u.stack)-n:])
		u.stack = u.stack[:len(u.stack)-n]
		u.push(items)
	case ']': // EMPTY_LIST
		u.push([]any{})
	case 'l': // LIST
		items, err := u.popMark()
		if err != nil {
			return err
		}
		u.push(items)
	case 'a': // APPEND
		v, err := u.pop()
		if err != nil {
			return err
		}
		return u.appendTo(v)
	case 'e': // APPENDS
		items, err := u.popMark()
		if err != nil {
			return err
		}
		return u.appendTo(items...)
	case '}': // EMPTY_DICT
		u.push(map[any]any{})
	case 'd': // DICT
		items, err := u.popMark()
		if err != nil {
			return err
		}
		m := map[any]any{}
		for i := 0; i+1 < len(items); i += 2 {
			m[mapKey(items[i])] = items[i+1]
		}
		u.push(m)
	case 's': // SETITEM
		v, err := u.pop()
		if err != nil {
			return err
		}
		k, err := u.pop()
		if err != nil {
			return err
		}
		return u.setItems(k, v)
	case 'u': // SETITEMS
		items, err := u.popMark()
		if err != nil {
			return err
		}
		return u.setItems(items...)
	case 'N': // NONE
		u.push(nil)
	case 0x88: // NEWTRUE
		u.push(true)
	case 0x89: // NEWFALSE
		u.push(false)
	case 'K': // BININT1
		b, err := u.read(1)
		if err != nil {
			return err
		}
		u.push(int64(b[0]))
	case 'M': // BININT2
		b, err := u.read(2)
		if err != nil {
			return err
		}
		u.push(int64(binary.LittleEndian.Uint16(b)))
	case 'J': // BININT (signed 32-bit LE)
		b, err := u.read(4)
		if err != nil {
			return err
		}
		u.push(int64(int32(binary.LittleEndian.Uint32(b))))
	case 0x8a: // LONG1
		nb, err := u.read(1)
		if err != nil {
			return err
		}
		b, err := u.read(int(nb[0]))
		if err != nil {
			return err
		}
		u.push(decodeLongLE(b))
	case 'I': // INT (line; also 00/01 for bool)
		line, err := u.readLine()
		if err != nil {
			return err
		}
		switch line {
		case "00":
			u.push(false)
		case "01":
			u.push(true)
		default:
			n, err := strconv.ParseInt(line, 10, 64)
			if err != nil {
				return fmt.Errorf("pickle: bad INT %q", line)
			}
			u.push(n)
		}
	case 'L': // LONG (line with trailing L)
		line, err := u.readLine()
		if err != nil {
			return err
		}
		n, err := strconv.ParseInt(strings.TrimSuffix(line, "L"), 10, 64)
		if err != nil {
			return fmt.Errorf("pickle: bad LONG %q", line)
		}
		u.push(n)
	case 'G': // BINFLOAT (8-byte big-endian)
		b, err := u.read(8)
		if err != nil {
			return err
		}
		u.push(math.Float64frombits(binary.BigEndian.Uint64(b)))
	case 'F': // FLOAT (line)
		line, err := u.readLine()
		if err != nil {
			return err
		}
		f, err := strconv.ParseFloat(line, 64)
		if err != nil {
			return fmt.Errorf("pickle: bad FLOAT %q", line)
		}
		u.push(f)
	case 0x8c: // SHORT_BINUNICODE
		nb, err := u.read(1)
		if err != nil {
			return err
		}
		b, err := u.read(int(nb[0]))
		if err != nil {
			return err
		}
		u.push(string(b))
	case 'X': // BINUNICODE
		nb, err := u.read(4)
		if err != nil {
			return err
		}
		b, err := u.read(int(binary.LittleEndian.Uint32(nb)))
		if err != nil {
			return err
		}
		u.push(string(b))
	case 0x8d: // BINUNICODE8
		nb, err := u.read(8)
		if err != nil {
			return err
		}
		b, err := u.read(int(binary.LittleEndian.Uint64(nb))) //nolint:gosec // bounded by read()
		if err != nil {
			return err
		}
		u.push(string(b))
	case 'V': // UNICODE (raw-unicode-escape line)
		line, err := u.readLine()
		if err != nil {
			return err
		}
		u.push(unescapeRawUnicode(line))
	case 'S': // STRING (repr-quoted line)
		line, err := u.readLine()
		if err != nil {
			return err
		}
		u.push(unquotePyString(line))
	case 'U': // SHORT_BINSTRING
		nb, err := u.read(1)
		if err != nil {
			return err
		}
		b, err := u.read(int(nb[0]))
		if err != nil {
			return err
		}
		u.push(string(b))
	case 'T': // BINSTRING
		nb, err := u.read(4)
		if err != nil {
			return err
		}
		b, err := u.read(int(binary.LittleEndian.Uint32(nb)))
		if err != nil {
			return err
		}
		u.push(string(b))
	case 'C': // SHORT_BINBYTES
		nb, err := u.read(1)
		if err != nil {
			return err
		}
		b, err := u.read(int(nb[0]))
		if err != nil {
			return err
		}
		u.push(append([]byte(nil), b...))
	case 'B': // BINBYTES
		nb, err := u.read(4)
		if err != nil {
			return err
		}
		b, err := u.read(int(binary.LittleEndian.Uint32(nb)))
		if err != nil {
			return err
		}
		u.push(append([]byte(nil), b...))
	case 0x94: // MEMOIZE
		if len(u.stack) == 0 {
			return errors.New("pickle: MEMOIZE on empty stack")
		}
		u.memoize(u.stack[len(u.stack)-1])
	case 'q': // BINPUT
		b, err := u.read(1)
		if err != nil {
			return err
		}
		if len(u.stack) == 0 {
			return errors.New("pickle: BINPUT on empty stack")
		}
		u.memo[int(b[0])] = u.stack[len(u.stack)-1]
	case 'r': // LONG_BINPUT
		b, err := u.read(4)
		if err != nil {
			return err
		}
		if len(u.stack) == 0 {
			return errors.New("pickle: LONG_BINPUT on empty stack")
		}
		u.memo[int(binary.LittleEndian.Uint32(b))] = u.stack[len(u.stack)-1]
	case 'p': // PUT
		line, err := u.readLine()
		if err != nil {
			return err
		}
		idx, err := strconv.Atoi(line)
		if err != nil {
			return fmt.Errorf("pickle: bad PUT index %q", line)
		}
		if len(u.stack) == 0 {
			return errors.New("pickle: PUT on empty stack")
		}
		u.memo[idx] = u.stack[len(u.stack)-1]
	case 'h': // BINGET
		b, err := u.read(1)
		if err != nil {
			return err
		}
		u.push(u.memo[int(b[0])])
	case 'j': // LONG_BINGET
		b, err := u.read(4)
		if err != nil {
			return err
		}
		u.push(u.memo[int(binary.LittleEndian.Uint32(b))])
	case 'g': // GET
		line, err := u.readLine()
		if err != nil {
			return err
		}
		idx, err := strconv.Atoi(line)
		if err != nil {
			return fmt.Errorf("pickle: bad GET index %q", line)
		}
		u.push(u.memo[idx])
	case 'c': // GLOBAL
		module, err := u.readLine()
		if err != nil {
			return err
		}
		name, err := u.readLine()
		if err != nil {
			return err
		}
		u.push(&PyClass{Module: module, Name: name})
	case 0x93: // STACK_GLOBAL
		name, err := u.pop()
		if err != nil {
			return err
		}
		module, err := u.pop()
		if err != nil {
			return err
		}
		u.push(&PyClass{Module: Stringify(module), Name: Stringify(name)})
	case 'R', 0x81: // REDUCE, NEWOBJ
		args, err := u.pop()
		if err != nil {
			return err
		}
		callable, err := u.pop()
		if err != nil {
			return err
		}
		cls, _ := callable.(*PyClass)
		if cls == nil {
			cls = &PyClass{Module: "?", Name: Stringify(callable)}
		}
		argList, _ := args.([]any)
		u.push(&PyObject{Class: cls, Args: argList})
	case 'b': // BUILD
		state, err := u.pop()
		if err != nil {
			return err
		}
		if len(u.stack) > 0 {
			if obj, ok := u.stack[len(u.stack)-1].(*PyObject); ok {
				obj.State = state
			}
		}
	case 0x8f: // EMPTY_SET
		u.push([]any{})
	case 0x90: // ADDITEMS
		items, err := u.popMark()
		if err != nil {
			return err
		}
		return u.appendTo(items...)
	default:
		return fmt.Errorf("pickle: unsupported opcode 0x%02x at offset %d", op, u.pos-1)
	}
	return nil
}

// appendTo appends items to the list at the top of the stack in place.
func (u *unpickler) appendTo(items ...any) error {
	if len(u.stack) == 0 {
		return errors.New("pickle: APPEND to empty stack")
	}
	lst, ok := u.stack[len(u.stack)-1].([]any)
	if !ok {
		return errors.New("pickle: APPEND target is not a list")
	}
	u.stack[len(u.stack)-1] = append(lst, items...)
	return nil
}

// setItems applies key/value pairs to the dict at the top of the stack.
func (u *unpickler) setItems(kv ...any) error {
	if len(u.stack) == 0 {
		return errors.New("pickle: SETITEM on empty stack")
	}
	m, ok := u.stack[len(u.stack)-1].(map[any]any)
	if !ok {
		return errors.New("pickle: SETITEM target is not a dict")
	}
	for i := 0; i+1 < len(kv); i += 2 {
		m[mapKey(kv[i])] = kv[i+1]
	}
	return nil
}

// mapKey converts a value into something usable as a Go map key.
func mapKey(v any) any {
	switch v.(type) {
	case string, int64, float64, bool, nil:
		return v
	default:
		return Stringify(v)
	}
}

// decodeLongLE decodes a little-endian two's-complement integer (LONG1).
func decodeLongLE(b []byte) int64 {
	if len(b) == 0 {
		return 0
	}
	var n int64
	for i := len(b) - 1; i >= 0; i-- {
		n = n<<8 | int64(b[i])
	}
	// Sign-extend when the high bit of the most significant byte is set.
	if b[len(b)-1]&0x80 != 0 && len(b) < 8 {
		n -= 1 << (8 * uint(len(b)))
	}
	return n
}

// unescapeRawUnicode decodes the raw-unicode-escape encoding used by the
// UNICODE ('V') opcode: only \uXXXX sequences are special.
func unescapeRawUnicode(s string) string {
	if !strings.Contains(s, `\u`) {
		return s
	}
	var b strings.Builder
	for i := 0; i < len(s); {
		if s[i] == '\\' && i+5 < len(s) && s[i+1] == 'u' {
			if n, err := strconv.ParseUint(s[i+2:i+6], 16, 32); err == nil {
				b.WriteRune(rune(n))
				i += 6
				continue
			}
		}
		b.WriteByte(s[i])
		i++
	}
	return b.String()
}

// unquotePyString strips the repr quoting of a protocol-0 STRING line and
// resolves common backslash escapes.
func unquotePyString(s string) string {
	if len(s) >= 2 && (s[0] == '\'' || s[0] == '"') && s[len(s)-1] == s[0] {
		s = s[1 : len(s)-1]
	}
	if !strings.Contains(s, `\`) {
		return s
	}
	var b strings.Builder
	for i := 0; i < len(s); {
		if s[i] == '\\' && i+1 < len(s) {
			switch s[i+1] {
			case 'n':
				b.WriteByte('\n')
			case 't':
				b.WriteByte('\t')
			case 'r':
				b.WriteByte('\r')
			case '\\', '\'', '"':
				b.WriteByte(s[i+1])
			case 'x':
				if i+3 < len(s) {
					if n, err := strconv.ParseUint(s[i+2:i+4], 16, 8); err == nil {
						b.WriteByte(byte(n))
						i += 4
						continue
					}
				}
				b.WriteByte(s[i+1])
			default:
				b.WriteByte(s[i+1])
			}
			i += 2
			continue
		}
		b.WriteByte(s[i])
		i++
	}
	return b.String()
}
