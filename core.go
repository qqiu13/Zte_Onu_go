package main

import (
	"bytes"
	"crypto/aes"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"math"
	"math/rand"
	"regexp"
	"strconv"
	"strings"
)

var poolsHex = map[string]string{
	"init": "7b56b0f7da0e6852c819f32b849079e562f8ead2649387df73d7fbccaafe7543" +
		"1c29df4c522c6e7b453d1ff1debc27858a4591be3813de673208541175f4d3b4" +
		"a4b312866723994c617fb1d230df47f17693a38c95d359bf878ef3b3e4764988",
	"ksB": "8c2365d1fc324537112871630720691473e7d453132436c2b5e1fccf8a9a4189" +
		"3c49cf5c728c9eeb750d3fd1fecc57657a35213e68537e970248747195345384" +
		"b4c3e2d6273de65d729cbc3d03fd76c19c25a89247e4180f243f4f67ec97f499",
	"kgA": "9c3375d11c424537184891731745794443d7d573335476d2c5f12c4f7aba61d9" +
		"5c69df8cd21cde3b352d2fe1de4c77f51a65d1fe18438ea742080478d5e4f334" +
		"a4d3f236476d869d42651342dc429948dc679f9edc46375f849f6f76ce794f49",
	"kgB": "b25e207bb8834c67df90e3a658bcd2bcad4000470d5b3c29e59a74e9b0562757" +
		"0f7e1c6f1c975580fb003f8eb37b2bf43ce9014dda553395a934f18c78eb9c5b" +
		"da927c7a7bf8b5d1b1e7771e53a97696ceca9acf7520f7dd1909ffbcdaf4f6ee",
}

func mustHex(s string) []byte {
	b, err := hex.DecodeString(s)
	if err != nil {
		panic(fmt.Sprintf("invalid built-in key pool hex: %v", err))
	}
	return b
}

var pools = map[string][]byte{
	"init": mustHex(poolsHex["init"]),
	"ksB":  mustHex(poolsHex["ksB"]),
	"kgA":  mustHex(poolsHex["kgA"]),
	"kgB":  mustHex(poolsHex["kgB"]),
}

var rsaByCore = map[string][2]int{
	"C": {30049, 103},
	"B": {2537, 23},
	"M": {2537, 23},
	"A": {30049, 103},
}

var keyPoolByCore = map[string]string{
	"C": "kgA",
	"B": "ksB",
	"M": "kgB",
	"A": "init",
}

type branchSpec struct {
	Tag  string
	Off  int
	Core string
}

var branchKey = map[string]branchSpec{
	"C": {"re_rand=", 8, "C"},
	"B": {"newrand=", 8, "B"},
	"M": {"mipsrand=", 9, "M"},
}

func latin1Bytes(s string) []byte {
	out := make([]byte, 0, len(s))
	for _, r := range s {
		if r > 0xFF {
			r = '?'
		}
		out = append(out, byte(r))
	}
	return out
}

func latin1String(b []byte) string {
	rs := make([]rune, 0, len(b))
	for _, c := range b {
		rs = append(rs, rune(c))
	}
	return string(rs)
}

func trunc(b []byte, n int) []byte {
	if len(b) > n {
		return b[:n]
	}
	return b
}

func powMod(a, e, m int) int {
	if m <= 1 {
		return 0
	}
	r := 1 % m
	a %= m
	if a < 0 {
		a += m
	}
	for e > 0 {
		if e&1 == 1 {
			r = (r * a) % m
		}
		a = (a * a) % m
		e >>= 1
	}
	return r
}

func gcd(a, b int) int {
	for b != 0 {
		a, b = b, a%b
	}
	if a < 0 {
		a = -a
	}
	return a
}

func modInverse(a, m int) int {
	oldR, r := a%m, m
	oldS, s := 1, 0
	for r != 0 {
		q := oldR / r
		oldR, r = r, oldR-q*r
		oldS, s = s, oldS-q*s
	}
	d := oldS % m
	if d < 0 {
		d += m
	}
	return d
}

func printableRatio(b []byte) float64 {
	if len(b) == 0 {
		return 0.0
	}
	n := 0
	for _, c := range b {
		if (c >= 0x20 && c < 0x7F) || c == 9 || c == 10 || c == 13 {
			n++
		}
	}
	return float64(n) / float64(len(b))
}

func isAllDigits(s string) bool {
	if s == "" {
		return false
	}
	for i := 0; i < len(s); i++ {
		if s[i] < '0' || s[i] > '9' {
			return false
		}
	}
	return true
}

func isLatin1(s string) bool {
	for _, r := range s {
		if r > 0xFF {
			return false
		}
	}
	return true
}

func macStr(b []byte) string {
	parts := make([]string, len(b))
	for i, c := range b {
		parts[i] = fmt.Sprintf("%02X", c)
	}
	return strings.Join(parts, ":")
}

func pad(data []byte, blockSize int) []byte {
	n := blockSize - len(data)%blockSize
	out := make([]byte, len(data)+n)
	copy(out, data)
	return out
}

func unpad(data []byte) []byte { return bytes.TrimRight(data, "\x00") }

func aesEncrypt(key, data []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	d := pad(data, aes.BlockSize)
	out := make([]byte, len(d))
	for i := 0; i < len(d); i += aes.BlockSize {
		block.Encrypt(out[i:i+aes.BlockSize], d[i:i+aes.BlockSize])
	}
	return out, nil
}

func aesDecrypt(key, data []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	if len(data)%aes.BlockSize != 0 {
		return nil, fmt.Errorf("ciphertext length %d is not a multiple of 16", len(data))
	}
	out := make([]byte, len(data))
	for i := 0; i < len(data); i += aes.BlockSize {
		block.Decrypt(out[i:i+aes.BlockSize], data[i:i+aes.BlockSize])
	}
	return unpad(out), nil
}

func deriveKey(poolName string, seed, n int) ([]byte, error) {
	if seed < 0 {
		return nil, fmt.Errorf("%s: seed=%d is negative", poolName, seed)
	}
	if seed > 71 {
		return nil, fmt.Errorf("%s: seed=%d exceeds the maximum of 71", poolName, seed)
	}
	pool := pools[poolName]
	if seed+n > len(pool) {
		return nil, fmt.Errorf("%s: seed+n=%d exceeds pool length %d", poolName, seed+n, len(pool))
	}
	out := make([]byte, n)
	for i := 0; i < n; i++ {
		out[i] = pool[seed+i] ^ 0xA5
	}
	return out, nil
}

func magicTable() []int {
	t := make([]int, 256)
	for i := range t {
		t[i] = -1
	}
	for v := 0; v < 2537; v++ {
		d := powMod(v, 1271, 2537) & 0xFF
		if t[d] == -1 {
			t[d] = v
		}
	}
	return t
}

var magicTbl = magicTable()

func buildMagic(mac6 []byte, tail []int) ([]byte, []int, error) {
	m := make([]byte, 6)
	copy(m, mac6)
	if len(mac6) < 6 {
		for i := len(mac6); i < 6; i++ {
			m[i] = 0
		}
	}
	tl := make([]int, 6)
	copy(tl, tail)

	words := make([]int, 0, 12)
	for _, b := range m {
		w := magicTbl[b]
		if w < 0 {
			return nil, nil, fmt.Errorf("byte 0x%02X has no preimage in the magic table", b)
		}
		words = append(words, w)
	}
	words = append(words, tl...)

	var buf bytes.Buffer
	for i := 0; i < 11 && i < len(words); i++ {
		var b [4]byte
		binary.LittleEndian.PutUint32(b[:], uint32(words[i]))
		buf.Write(b[:])
	}
	var h [2]byte
	binary.LittleEndian.PutUint16(h[:], uint16(words[11]))
	buf.Write(h[:])
	return buf.Bytes(), words, nil
}

func isPrime(n int) bool {
	if n < 2 {
		return false
	}
	for i := 2; i*i <= n; i++ {
		if n%i == 0 {
			return false
		}
	}
	return true
}

type rsaKey struct {
	P, Q, N, Phi, E, D int
}

func rsaGen(rnd *rand.Rand, siMod int) rsaKey {
	capVal := siMod - 1
	lo, hi := 60, 159
	if lo*lo > capVal {
		lo = 17
		hi = int(math.Sqrt(float64(capVal)))
	}
	for hi > lo && hi*hi > capVal {
		hi--
	}
	span := hi - lo + 1

	var p, q int
	for {
		p = lo + rnd.Intn(hi-lo+1)
		for !isPrime(p) {
			p++
		}
		if p > hi {
			p = lo
		}
		q = lo + rnd.Intn(hi-lo+1)
		guard := 0
		for (p == q || !isPrime(q)) && guard <= span {
			q--
			if q < lo {
				q = hi
			}
			guard++
		}
		if p == q || !isPrime(q) {
			continue
		}
		nTry := p * q
		if 255 < nTry && nTry <= capVal && gcd(nTry, siMod) == 1 {
			break
		}
	}

	n := p * q
	phi := (p - 1) * (q - 1)
	cand := make([]int, 0, 100)
	for e := phi - 1; e > 1 && len(cand) < 100; e-- {
		if gcd(e, phi) == 1 {
			cand = append(cand, e)
		}
	}
	ev := cand[rnd.Intn(len(cand))]
	return rsaKey{P: p, Q: q, N: n, Phi: phi, E: ev, D: modInverse(ev, phi)}
}

func buildSendInfo(serverMAC []byte, seq [][]byte, rsa rsaKey, siExp, siMod int) []byte {
	xs := []int{0, rsa.D, 0, rsa.N}
	arr := make([]int, 0, 4+6+len(seq)*6)
	for _, x := range xs {
		arr = append(arr, powMod(x, siExp, siMod))
	}
	data := make([]byte, 0, 6+6*len(seq))
	data = append(data, serverMAC...)
	for _, m := range seq {
		data = append(data, m...)
	}
	for _, b := range data {
		arr = append(arr, powMod(int(b), rsa.E, rsa.N))
	}

	var body bytes.Buffer
	for _, v := range arr {
		var b [4]byte
		binary.LittleEndian.PutUint32(b[:], uint32(v))
		body.Write(b[:])
	}
	out := []byte(fmt.Sprintf("SendInfo.gch?info=%d|", len(arr)))
	return append(out, body.Bytes()...)
}

func buildSeq(clientMAC []byte, pattern string) [][]byte {
	out := make([][]byte, 0, len(pattern))
	for i := 0; i < len(pattern); i++ {
		if pattern[i] == 'a' {
			out = append(out, clientMAC)
		} else {
			out = append(out, []byte{0x00, 0xFF, 0x72, 0x46, 0x34, 0x11})
		}
	}
	return out
}

func detectCore(txt []byte) string {
	if bytes.Contains(txt, []byte("re_rand=")) {
		return "C"
	}
	if bytes.Contains(txt, []byte("newrand=")) {
		return "B"
	}
	if bytes.Contains(txt, []byte("mipsrand=")) {
		return "M"
	}
	return "A"
}

var reAtoi = regexp.MustCompile(`\s*(-?\d+)`)

func atoiDec(s []byte) int {
	m := reAtoi.FindSubmatch(s)
	if m == nil {
		return 0
	}
	v, err := strconv.Atoi(string(m[1]))
	if err != nil {
		return 0
	}
	return v
}

func smodArm(x, m int) int {
	r := x % m
	if r < 0 {
		r = -r
	}
	if x < 0 {
		return -r
	}
	return r
}

func calcSeed(rand60 int, field []byte) int {
	t := (rand60 * 0x1000193) % 64
	v := smodArm(t^atoiDec(field), 60)
	if v < 0 {
		v %= 60
		if v < 0 {
			v += 60
		}
	}
	return v
}

func plainStep4(verS, user, pw, core, fmtName string) []byte {
	body := ""
	if fmtName == "login" || (fmtName == "" && core == "A") {
		body = fmt.Sprintf("CheckLoginAuth.gch?LoginUser=%s&LoginUserPassword=%s", user, pw)
	} else {
		body = fmt.Sprintf("CheckLoginAuth.gch?version%s&user=%s&pass=%s", verS, user, pw)
	}
	return latin1Bytes(body)
}

func plainStep5(mode int, fmuser, tail, core string) []byte {
	if core == "A" {
		return latin1Bytes(fmt.Sprintf("FactoryMode.gch?FacMode=%d&FacUser=%s%s", mode, fmuser, tail))
	}
	return latin1Bytes(fmt.Sprintf("FactoryMode.gch?mode=%d&user=%s%s", mode, fmuser, tail))
}

func normVersion(v string) (string, string) {
	s := strings.TrimSpace(v)
	if !isAllDigits(s) {
		return "", "must be digits only (version<digits>, no equals sign)"
	}
	if n, _ := strconv.Atoi(s); n <= 49 {
		return "", fmt.Sprintf("must be greater than 49, got %s", s)
	}
	return s, "ok"
}

func normSlaveIP(v string) (string, string) {
	s := strings.TrimSpace(v)
	if len(s) <= 6 {
		return "", fmt.Sprintf("length must exceed 6, got %d", len(s))
	}
	if len(s) >= 7 && s[:7] == "0.0.0.0" {
		return "", "must not be 0.0.0.0"
	}
	return s, "ok"
}

func normMACStr(v string) []byte {
	t := strings.Split(strings.ReplaceAll(v, "-", ":"), ":")
	if len(t) != 6 {
		return nil
	}
	out := make([]byte, 6)
	for i, x := range t {
		if len(x) != 2 {
			return nil
		}
		n, err := strconv.ParseUint(x, 16, 8)
		if err != nil {
			return nil
		}
		out[i] = byte(n)
	}
	return out
}
