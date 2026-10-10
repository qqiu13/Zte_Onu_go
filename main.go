package main

import (
	"flag"
	"fmt"
	"math/rand"
	"os"
	"strings"
	"time"
)

type strList []string

func (s *strList) String() string {
	if s == nil {
		return ""
	}
	return strings.Join(*s, " ")
}

func (s *strList) Set(v string) error {
	for _, f := range strings.Fields(v) {
		*s = append(*s, f)
	}
	return nil
}

func repeatTo(s []string, n int) []string {
	if len(s) == 0 {
		return nil
	}
	out := make([]string, 0, n)
	for i := 0; i < n; i++ {
		out = append(out, s[i%len(s)])
	}
	return out
}

func runMain() int {
	fs := flag.NewFlagSet("zte_onu", flag.ContinueOnError)
	fs.SetOutput(os.Stdout)

	ipOpt := fs.String("ip", "", "device IP (either this flag or a positional argument)")
	port := fs.Int("port", 8080, "port")
	var users, pws strList
	fs.Var(&users, "u", "username(s); multiple values allowed (defaults to 4 built-in accounts)")
	fs.Var(&users, "user", "same as -u")
	fs.Var(&pws, "p", "password(s); multiple values allowed (defaults to 4 built-in passwords)")
	fs.Var(&pws, "pass", "same as -p")
	macFlag := fs.String("m", "", "[required] local NIC MAC, XX:XX:XX:XX:XX:XX")
	slaveIP := fs.String("slaveip", "", "append &slaveip=<ip> to step 5 (slave ONU)")
	closeMode := fs.Bool("close", false, "step 5 sends the close payload instead of enable")
	all := fs.Bool("all", false, "try every credential pair, do not stop at first hit")
	verbose := fs.Bool("v", false, "print per-step detail")

	fs.Usage = func() { fs.PrintDefaults() }
	if err := fs.Parse(os.Args[1:]); err != nil {
		return 2
	}

	ip := *ipOpt
	if args := fs.Args(); len(args) > 0 && ip == "" {
		ip = args[0]
	}
	if ip == "" {
		fmt.Println("an IP is required (positional argument or -ip)")
		fs.Usage()
		return 2
	}
	if *macFlag == "" {
		fmt.Println("-m local NIC MAC is required")
		fs.Usage()
		return 2
	}
	if normMACStr(*macFlag) == nil {
		fmt.Printf("invalid MAC, expected six octets XX:XX:XX:XX:XX:XX: %s\n", *macFlag)
		return 2
	}

	userList := []string(users)
	pwList := []string(pws)
	if len(userList) == 0 {
		userList = append([]string(nil), []string{"factorymode", "CMCCAdmin", "CUAdmin", "telecomadmin"}...)
	}
	if len(pwList) == 0 {
		pwList = append([]string(nil), []string{"nE%jA@5b", "aDm8H%MdA", "CUAdmin", "nE7jA%5m"}...)
	}
	switch {
	case len(userList) == 1 && len(pwList) > 1:
		userList = repeatTo(userList, len(pwList))
	case len(pwList) == 1 && len(userList) > 1:
		pwList = repeatTo(pwList, len(userList))
	case len(userList) != len(pwList):
		fmt.Printf("-u has %d value(s) and -p has %d: they pair up 1:1, so counts must match (or one side may have exactly 1)\n",
			len(userList), len(pwList))
		return 2
	}
	for name, vals := range map[string][]string{"-u": userList, "-p": pwList} {
		for _, v := range vals {
			if !isLatin1(v) {
				fmt.Printf("%s contains a non-latin-1 character: %q\n", name, v)
				return 2
			}
		}
	}

	combos := make([][2]string, 0, len(userList))
	for i := range userList {
		combos = append(combos, [2]string{userList[i], pwList[i]})
	}
	if len(combos) > 4 {
		combos = combos[:4]
	}
	total := len(combos)

	hits := make([][4]string, 0)
	seedBase := rand.New(rand.NewSource(time.Now().UnixNano()))

	for idx, c := range combos {
		u, p := c[0], c[1]
		var marks [][2]interface{}
		progress := func(n int, ok bool, note string) {
			marks = append(marks, [2]interface{}{n, ok})
			if *verbose {
				suffix := ""
				if note != "" {
					suffix = "  " + note
				}
				st := "OK!"
				if !ok {
					st = "FAIL!"
				}
				fmt.Printf("  facStep %d: %s%s\n", n, st, suffix)
			}
		}
		if *verbose {
			fmt.Printf("[%d/%d] user=%s pass=%s\n", idx+1, total, u, p)
		}

		res := run(runConfig{
			Host:     ip,
			Port:     *port,
			MAC:      *macFlag,
			User:     u,
			PW:       p,
			Mode:     2,
			FMUser:   "notused",
			MagicMAC: "client",
			SlaveIP:  *slaveIP,
			Close:    *closeMode,
			Timeout:  5.0,
			Verbose:  *verbose,
			Rnd:      rand.New(rand.NewSource(seedBase.Int63())),
			Progress: progress,
		})

		tagParts := make([]string, 0, len(marks))
		for _, mk := range marks {
			st := "OK"
			if ok, _ := mk[1].(bool); !ok {
				st = "X"
			}
			tagParts = append(tagParts, fmt.Sprintf("%d:%s", mk[0], st))
		}
		tag := strings.Join(tagParts, " ")

		done := res.OK
		if *closeMode {
			done = len(res.Failed) == 0
		}
		switch {
		case res.Error != "":
			fmt.Printf("[%d/%d] user=%s pass=%s -> aborted (%s)\n", idx+1, total, u, p, res.Error)
		case done:
			fmt.Printf("[%d/%d] user=%s pass=%s -> OK  %s  core=%s seed=%d\n",
				idx+1, total, u, p, tag, res.Core, res.Seed)
			hits = append(hits, [4]string{u, p, res.CredUser, res.CredPass})
			if !*all {
				return finishAndPrint(hits, total, *closeMode)
			}
		default:
			fmt.Printf("[%d/%d] user=%s pass=%s -> FAIL %s  core=%s step4=%s\n",
				idx+1, total, u, p, tag, res.Core, res.step4String())
		}
		if idx+1 < total {
			time.Sleep(dur(0.3))
		}
	}
	return finishAndPrint(hits, total, *closeMode)
}

func finishAndPrint(hits [][4]string, total int, closeMode bool) int {
	if closeMode {
		if len(hits) > 0 {
			fmt.Printf("close mode: all five steps completed, close payload sent (%d pair(s) succeeded)\n", len(hits))
			return 0
		}
		fmt.Println("close mode failed")
		return 1
	}
	if len(hits) > 0 {
		for _, h := range hits {
			fmt.Printf("Hit: user=%s pass=%s -> user=%s  pass=%s\n", h[0], h[1], h[2], h[3])
		}
		return 0
	}
	fmt.Printf("all %d credential pair(s) failed to yield credentials\n", total)
	return 1
}

func main() { os.Exit(runMain()) }
