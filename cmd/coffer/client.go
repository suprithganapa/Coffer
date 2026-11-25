package main

import (
	"bufio"
	"bytes"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"mime"
	"net/http"
	"net/url"
	"os"
	"path"
	"path/filepath"
	"sort"
	"strings"
	"syscall"
	"text/tabwriter"
	"time"

	"coffer/internal/server"
)

type client struct {
	addr  string
	token string
	http  *http.Client
}

func tokenFile() string {
	h, _ := os.UserHomeDir()
	return filepath.Join(h, ".coffer-token")
}

func newClient() *client {
	addr := os.Getenv("COFFER_ADDR")
	if addr == "" {
		addr = "http://127.0.0.1:8200"
	}
	tok := os.Getenv("COFFER_TOKEN")
	if tok == "" {
		if b, err := os.ReadFile(tokenFile()); err == nil {
			tok = strings.TrimSpace(string(b))
		}
	}
	return &client{addr: strings.TrimRight(addr, "/"), token: tok, http: &http.Client{Timeout: 10 * time.Minute}}
}

type apiError struct {
	Status int
	Errors []string
}

func (e *apiError) Error() string {
	if len(e.Errors) == 0 {
		return fmt.Sprintf("request failed with status %d", e.Status)
	}
	return fmt.Sprintf("%s (status %d)", strings.Join(e.Errors, "; "), e.Status)
}

func (c *client) do(method, p string, body any, out any) error {
	var rd io.Reader
	if body != nil {
		b, _ := json.Marshal(body)
		rd = bytes.NewReader(b)
	}
	req, err := http.NewRequest(method, c.addr+"/v1/"+strings.TrimPrefix(p, "/"), rd)
	if err != nil {
		return err
	}
	if c.token != "" {
		req.Header.Set("X-Coffer-Token", c.token)
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := c.http.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	data, _ := io.ReadAll(resp.Body)
	if resp.StatusCode >= 400 {
		var e struct {
			Errors []string `json:"errors"`
		}
		json.Unmarshal(data, &e)
		return &apiError{resp.StatusCode, e.Errors}
	}
	if out != nil && len(data) > 0 {
		return json.Unmarshal(data, out)
	}
	return nil
}

type envelope struct {
	Data     map[string]any `json:"data"`
	Auth     map[string]any `json:"auth"`
	WrapInfo map[string]any `json:"wrap_info"`
	Warnings []string       `json:"warnings"`
}

func printJSON(v any) {
	b, _ := json.MarshalIndent(v, "", "  ")
	fmt.Println(string(b))
}

func printKV(m map[string]any) {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	tw := tabwriter.NewWriter(os.Stdout, 0, 4, 2, ' ', 0)
	fmt.Fprintln(tw, "Key\tValue")
	fmt.Fprintln(tw, "---\t-----")
	for _, k := range keys {
		v := m[k]
		switch vv := v.(type) {
		case map[string]any, []any:
			b, _ := json.Marshal(vv)
			fmt.Fprintf(tw, "%s\t%s\n", k, b)
		case nil:
			fmt.Fprintf(tw, "%s\tn/a\n", k)
		default:
			fmt.Fprintf(tw, "%s\t%v\n", k, vv)
		}
	}
	tw.Flush()
}

// parseKV turns k=v args into a map; v starting with @ reads a file, "-" reads stdin.
func parseKV(args []string) (map[string]any, error) {
	out := map[string]any{}
	for _, a := range args {
		i := strings.IndexByte(a, '=')
		if i <= 0 {
			return nil, fmt.Errorf("expected key=value, got %q", a)
		}
		k, v := a[:i], a[i+1:]
		if strings.HasPrefix(v, "@") {
			b, err := os.ReadFile(v[1:])
			if err != nil {
				return nil, err
			}
			v = string(b)
		} else if v == "-" {
			b, _ := io.ReadAll(os.Stdin)
			v = string(b)
		}
		out[k] = v
	}
	return out, nil
}

func readSecretLine(prompt string) string {
	fmt.Fprint(os.Stderr, prompt)
	// best effort: disable echo via stty when available
	_ = syscall.Getpid
	r := bufio.NewReader(os.Stdin)
	s, _ := r.ReadString('\n')
	return strings.TrimSpace(s)
}

func runClient(cmd string, args []string) error {
	c := newClient()
	switch cmd {
	case "status":
		return opStatus(c)
	case "operator":
		return runOperator(c, args)
	case "login":
		return runLogin(c, args)
	case "read", "write", "list", "delete":
		return runGeneric(c, cmd, args)
	case "kv":
		return runKV(c, args)
	case "token":
		return runToken(c, args)
	case "policy":
		return runPolicy(c, args)
	case "secrets", "auth":
		return runMounts(c, cmd, args)
	case "fs":
		return runFS(c, args)
	case "s3":
		return runS3(c, args)
	case "cluster":
		return runCluster(c, args)
	}
	fmt.Print(usage)
	return fmt.Errorf("unknown command %q", cmd)
}

func need(args []string, n int, use string) error {
	if len(args) < n {
		return errors.New("usage: coffer " + use)
	}
	return nil
}

func opStatus(c *client) error {
	var st map[string]any
	if err := c.do("GET", "sys/seal-status", nil, &st); err != nil {
		return err
	}
	printKV(st)
	return nil
}

func runOperator(c *client, args []string) error {
	if err := need(args, 1, "operator <init|unseal|seal|status|rotate|rekey|generate-root>"); err != nil {
		return err
	}
	switch args[0] {
	case "status":
		return opStatus(c)
	case "init":
		fs := flag.NewFlagSet("init", flag.ExitOnError)
		shares := fs.Int("key-shares", 5, "number of unseal key shares")
		thr := fs.Int("key-threshold", 3, "shares required to unseal")
		fs.Parse(args[1:])
		var res struct {
			Keys      []string `json:"keys"`
			KeysB64   []string `json:"keys_base64"`
			RootToken string   `json:"root_token"`
		}
		if err := c.do("PUT", "sys/init", map[string]any{"secret_shares": *shares, "secret_threshold": *thr}, &res); err != nil {
			return err
		}
		for i, k := range res.Keys {
			fmt.Printf("Unseal Key %d: %s\n", i+1, k)
		}
		fmt.Printf("\nInitial Root Token: %s\n\n", res.RootToken)
		fmt.Printf("Coffer initialized with %d key shares and a key threshold of %d.\n", *shares, *thr)
		fmt.Println("Store the unseal keys in separate, safe places. Coffer starts SEALED: run `coffer operator unseal` with", *thr, "different keys.")
		return nil
	case "unseal":
		key := ""
		if len(args) > 1 {
			key = args[1]
		} else {
			key = readSecretLine("Unseal Key (will be hidden if your terminal supports it): ")
		}
		var st map[string]any
		if err := c.do("PUT", "sys/unseal", map[string]any{"key": key}, &st); err != nil {
			return err
		}
		printKV(st)
		return nil
	case "seal":
		if err := c.do("PUT", "sys/seal", nil, nil); err != nil {
			return err
		}
		fmt.Println("Success! Coffer is sealed.")
		return nil
	case "rotate":
		var e envelope
		if err := c.do("PUT", "sys/rotate", nil, &e); err != nil {
			return err
		}
		fmt.Printf("Success! Rotated encryption key; new term %v\n", e.Data["term"])
		return nil
	case "snapshot":
		return runSnapshot(c, args[1:])
	case "rekey", "generate-root":
		fs := flag.NewFlagSet(args[0], flag.ExitOnError)
		keys := fs.String("keys", "", "comma separated current unseal keys (threshold count)")
		shares := fs.Int("key-shares", 5, "new number of shares (rekey)")
		thr := fs.Int("key-threshold", 3, "new threshold (rekey)")
		fs.Parse(args[1:])
		if *keys == "" {
			return errors.New("-keys is required")
		}
		body := map[string]any{"keys": strings.Split(*keys, ","), "secret_shares": *shares, "secret_threshold": *thr}
		if args[0] == "generate-root" {
			var res map[string]any
			if err := c.do("PUT", "sys/generate-root", body, &res); err != nil {
				return err
			}
			fmt.Println("New root token:", res["token"])
			return nil
		}
		var e envelope
		if err := c.do("PUT", "sys/rekey", body, &e); err != nil {
			return err
		}
		for i, k := range e.Data["keys"].([]any) {
			fmt.Printf("New Unseal Key %d: %v\n", i+1, k)
		}
		return nil
	}
	return fmt.Errorf("unknown operator command %q", args[0])
}

func saveToken(tok string) error {
	return os.WriteFile(tokenFile(), []byte(tok+"\n"), 0o600)
}

func runLogin(c *client, args []string) error {
	fs := flag.NewFlagSet("login", flag.ExitOnError)
	method := fs.String("method", "token", "token, userpass or approle")
	mount := fs.String("path", "", "auth mount path (defaults to the method name)")
	fs.Parse(args)
	rest := fs.Args()
	if *mount == "" {
		*mount = *method
	}
	var tok string
	switch *method {
	case "token":
		if len(rest) > 0 {
			tok = rest[0]
		} else {
			tok = readSecretLine("Token: ")
		}
		c.token = tok
		var e envelope
		if err := c.do("GET", "auth/token/lookup-self", nil, &e); err != nil {
			return fmt.Errorf("token is not valid: %w", err)
		}
	case "userpass":
		kv, err := parseKV(rest)
		if err != nil {
			return err
		}
		user, _ := kv["username"].(string)
		if user == "" {
			return errors.New("usage: coffer login -method=userpass username=<name> [password=<pw>]")
		}
		pw, _ := kv["password"].(string)
		if pw == "" {
			pw = readSecretLine("Password: ")
		}
		var e envelope
		if err := c.do("POST", "auth/"+*mount+"/login/"+user, map[string]any{"password": pw}, &e); err != nil {
			return err
		}
		tok, _ = e.Auth["client_token"].(string)
	case "approle":
		kv, err := parseKV(rest)
		if err != nil {
			return err
		}
		var e envelope
		if err := c.do("POST", "auth/"+*mount+"/login", kv, &e); err != nil {
			return err
		}
		tok, _ = e.Auth["client_token"].(string)
	default:
		return fmt.Errorf("unsupported method %q", *method)
	}
	if err := saveToken(tok); err != nil {
		return err
	}
	fmt.Printf("Success! You are now authenticated. Token saved to %s\n", tokenFile())
	if *method != "token" {
		fmt.Println("token:", tok)
	}
	return nil
}

func runGeneric(c *client, cmd string, args []string) error {
	if err := need(args, 1, cmd+" <path> [key=value ...]"); err != nil {
		return err
	}
	p := args[0]
	var e envelope
	switch cmd {
	case "read":
		if err := c.do("GET", p, nil, &e); err != nil {
			return err
		}
		printJSON(e.Data)
	case "list":
		if err := c.do("LIST", p, nil, &e); err != nil {
			return err
		}
		for _, k := range e.Data["keys"].([]any) {
			fmt.Println(k)
		}
	case "write":
		kv, err := parseKV(args[1:])
		if err != nil {
			return err
		}
		if err := c.do("PUT", p, kv, &e); err != nil {
			return err
		}
		if e.Data != nil || e.Auth != nil {
			printJSON(map[string]any{"data": e.Data, "auth": e.Auth})
		} else {
			fmt.Println("Success! Data written to:", p)
		}
	case "delete":
		if err := c.do("DELETE", p, nil, nil); err != nil {
			return err
		}
		fmt.Println("Success! Data deleted (if it existed) at:", p)
	}
	return nil
}

// splitKV splits "secret/app/db" into mount "secret" and path "app/db".
func splitKV(p string) (string, string) {
	p = strings.Trim(p, "/")
	i := strings.IndexByte(p, '/')
	if i < 0 {
		return p, ""
	}
	return p[:i], p[i+1:]
}

func runKV(c *client, args []string) error {
	if err := need(args, 2, "kv <get|put|patch|list|delete|undelete|destroy|metadata> <mount/path> [key=value ...]"); err != nil {
		return err
	}
	sub := args[0]
	fs := flag.NewFlagSet("kv", flag.ExitOnError)
	version := fs.Int("version", 0, "version to read")
	versions := fs.String("versions", "", "comma separated versions (undelete/destroy/delete)")
	cas := fs.Int("cas", -1, "check-and-set version for put")
	fs.Parse(args[1:])
	rest := fs.Args()
	if len(rest) < 1 {
		return errors.New("missing path")
	}
	mount, p := splitKV(rest[0])
	var e envelope
	switch sub {
	case "get":
		q := ""
		if *version > 0 {
			q = fmt.Sprintf("?version=%d", *version)
		}
		if err := c.do("GET", mount+"/data/"+p+q, nil, &e); err != nil {
			return err
		}
		if md, ok := e.Data["metadata"].(map[string]any); ok {
			fmt.Println("====== Metadata ======")
			printKV(md)
			fmt.Println("\n====== Data ======")
		}
		d, _ := e.Data["data"].(map[string]any)
		printKV(d)
	case "put", "patch":
		kv, err := parseKV(rest[1:])
		if err != nil {
			return err
		}
		body := map[string]any{"data": kv}
		if *cas >= 0 {
			body["options"] = map[string]any{"cas": *cas}
		}
		method := "PUT"
		if sub == "patch" {
			method = "PATCH"
		}
		if err := c.do(method, mount+"/data/"+p, body, &e); err != nil {
			return err
		}
		printKV(e.Data)
	case "list":
		if err := c.do("LIST", mount+"/metadata/"+p, nil, &e); err != nil {
			return err
		}
		for _, k := range e.Data["keys"].([]any) {
			fmt.Println(k)
		}
	case "delete":
		if *versions != "" {
			return c.do("POST", mount+"/delete/"+p, map[string]any{"versions": strings.Split(*versions, ",")}, nil)
		}
		if err := c.do("DELETE", mount+"/data/"+p, nil, nil); err != nil {
			return err
		}
		fmt.Println("Success! Latest version soft-deleted (restore with `coffer kv undelete`).")
	case "undelete", "destroy":
		if *versions == "" {
			return errors.New("-versions is required")
		}
		if err := c.do("POST", mount+"/"+sub+"/"+p, map[string]any{"versions": strings.Split(*versions, ",")}, nil); err != nil {
			return err
		}
		fmt.Println("Success!")
	case "metadata":
		if err := c.do("GET", mount+"/metadata/"+p, nil, &e); err != nil {
			return err
		}
		printJSON(e.Data)
	default:
		return fmt.Errorf("unknown kv command %q", sub)
	}
	return nil
}

func runToken(c *client, args []string) error {
	if err := need(args, 1, "token <create|lookup|renew|revoke>"); err != nil {
		return err
	}
	fs := flag.NewFlagSet("token", flag.ExitOnError)
	pols := fs.String("policy", "", "comma separated policies")
	ttl := fs.String("ttl", "", "token TTL, e.g. 1h")
	uses := fs.Int("use-limit", 0, "number of uses")
	orphan := fs.Bool("orphan", false, "create an orphan token")
	fs.Parse(args[1:])
	var e envelope
	switch args[0] {
	case "create":
		body := map[string]any{"ttl": *ttl, "num_uses": *uses, "no_parent": *orphan}
		if *pols != "" {
			body["policies"] = strings.Split(*pols, ",")
		}
		if err := c.do("POST", "auth/token/create", body, &e); err != nil {
			return err
		}
		printKV(e.Auth)
	case "lookup":
		if t := fs.Arg(0); t != "" {
			if err := c.do("POST", "auth/token/lookup", map[string]any{"token": t}, &e); err != nil {
				return err
			}
		} else if err := c.do("GET", "auth/token/lookup-self", nil, &e); err != nil {
			return err
		}
		printKV(e.Data)
	case "renew":
		if err := c.do("POST", "auth/token/renew-self", map[string]any{"increment": *ttl}, &e); err != nil {
			return err
		}
		printKV(e.Auth)
	case "revoke":
		t := fs.Arg(0)
		if t == "" {
			return c.do("POST", "auth/token/revoke-self", nil, nil)
		}
		if err := c.do("POST", "auth/token/revoke", map[string]any{"token": t}, nil); err != nil {
			return err
		}
		fmt.Println("Success! Revoked token (if it existed)")
	}
	return nil
}

func runPolicy(c *client, args []string) error {
	if err := need(args, 1, "policy <list|read|write|delete> [name] [file]"); err != nil {
		return err
	}
	var e envelope
	switch args[0] {
	case "list":
		if err := c.do("LIST", "sys/policies/acl", nil, &e); err != nil {
			return err
		}
		for _, k := range e.Data["keys"].([]any) {
			fmt.Println(k)
		}
	case "read":
		if err := need(args, 2, "policy read <name>"); err != nil {
			return err
		}
		if err := c.do("GET", "sys/policies/acl/"+args[1], nil, &e); err != nil {
			return err
		}
		fmt.Println(e.Data["policy"])
	case "write":
		if err := need(args, 3, "policy write <name> <file|->"); err != nil {
			return err
		}
		var b []byte
		var err error
		if args[2] == "-" {
			b, err = io.ReadAll(os.Stdin)
		} else {
			b, err = os.ReadFile(args[2])
		}
		if err != nil {
			return err
		}
		if err := c.do("PUT", "sys/policies/acl/"+args[1], map[string]any{"policy": string(b)}, nil); err != nil {
			return err
		}
		fmt.Printf("Success! Uploaded policy: %s\n", args[1])
	case "delete":
		if err := need(args, 2, "policy delete <name>"); err != nil {
			return err
		}
		return c.do("DELETE", "sys/policies/acl/"+args[1], nil, nil)
	}
	return nil
}

func runMounts(c *client, kind string, args []string) error {
	if err := need(args, 1, kind+" <list|enable|disable>"); err != nil {
		return err
	}
	base := "sys/mounts"
	if kind == "auth" {
		base = "sys/auth"
	}
	fs := flag.NewFlagSet(kind, flag.ExitOnError)
	p := fs.String("path", "", "mount path (defaults to the type)")
	desc := fs.String("description", "", "description")
	fs.Parse(args[1:])
	switch args[0] {
	case "list":
		var e envelope
		if err := c.do("GET", base, nil, &e); err != nil {
			return err
		}
		tw := tabwriter.NewWriter(os.Stdout, 0, 4, 2, ' ', 0)
		fmt.Fprintln(tw, "Path\tType\tDescription")
		keys := make([]string, 0, len(e.Data))
		for k := range e.Data {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		for _, k := range keys {
			m := e.Data[k].(map[string]any)
			fmt.Fprintf(tw, "%s\t%v\t%v\n", k, m["type"], m["description"])
		}
		tw.Flush()
	case "enable":
		typ := fs.Arg(0)
		if typ == "" {
			return fmt.Errorf("usage: coffer %s enable [-path=p] <type>", kind)
		}
		if *p == "" {
			*p = typ
		}
		if err := c.do("POST", base+"/"+*p, map[string]any{"type": typ, "description": *desc}, nil); err != nil {
			return err
		}
		fmt.Printf("Success! Enabled %s at: %s/\n", typ, strings.Trim(*p, "/"))
	case "disable":
		target := fs.Arg(0)
		if target == "" {
			return fmt.Errorf("usage: coffer %s disable <path>", kind)
		}
		if err := c.do("DELETE", base+"/"+target, nil, nil); err != nil {
			return err
		}
		fmt.Println("Success! Disabled", target)
	}
	return nil
}

// ---------------- fs ----------------

func (c *client) fsReq(method, p string, query url.Values, body io.Reader, ctype string) (*http.Response, error) {
	u := c.addr + "/v1/fs" + path.Clean("/"+p)
	if len(query) > 0 {
		u += "?" + query.Encode()
	}
	req, err := http.NewRequest(method, u, body)
	if err != nil {
		return nil, err
	}
	req.Header.Set("X-Coffer-Token", c.token)
	if ctype != "" {
		req.Header.Set("Content-Type", ctype)
	}
	resp, err := c.http.Do(req)
	if err != nil {
		return nil, err
	}
	if resp.StatusCode >= 400 {
		defer resp.Body.Close()
		var e struct {
			Errors []string `json:"errors"`
		}
		json.NewDecoder(resp.Body).Decode(&e)
		return nil, &apiError{resp.StatusCode, e.Errors}
	}
	return resp, nil
}

func human(n float64) string {
	units := []string{"B", "KB", "MB", "GB", "TB"}
	i := 0
	for n >= 1024 && i < len(units)-1 {
		n /= 1024
		i++
	}
	if i == 0 {
		return fmt.Sprintf("%.0f %s", n, units[i])
	}
	return fmt.Sprintf("%.1f %s", n, units[i])
}

func runFS(c *client, args []string) error {
	if err := need(args, 1, "fs <ls|put|get|cat|rm|mkdir|mv|cp|share|encrypt|stat> ..."); err != nil {
		return err
	}
	sub, rest := args[0], args[1:]
	switch sub {
	case "ls":
		p := "/"
		if len(rest) > 0 {
			p = rest[0]
		}
		resp, err := c.fsReq("GET", p, nil, nil, "")
		if err != nil {
			return err
		}
		defer resp.Body.Close()
		var out struct {
			Entries []struct {
				Name      string    `json:"name"`
				IsDir     bool      `json:"is_dir"`
				Size      float64   `json:"size"`
				Mtime     time.Time `json:"mtime"`
				Encrypted bool      `json:"encrypted"`
			} `json:"entries"`
		}
		if strings.HasPrefix(resp.Header.Get("Content-Type"), "application/json") {
			json.NewDecoder(resp.Body).Decode(&out)
		}
		tw := tabwriter.NewWriter(os.Stdout, 0, 4, 2, ' ', 0)
		for _, e := range out.Entries {
			name, size, lock := e.Name, human(e.Size), ""
			if e.IsDir {
				name += "/"
				size = "-"
			}
			if e.Encrypted {
				lock = "encrypted"
			}
			fmt.Fprintf(tw, "%s\t%s\t%s\t%s\n", e.Mtime.Local().Format("2006-01-02 15:04"), size, name, lock)
		}
		tw.Flush()
	case "put":
		if err := need(rest, 2, "fs put <local-file> <remote-path>"); err != nil {
			return err
		}
		f, err := os.Open(rest[0])
		if err != nil {
			return err
		}
		defer f.Close()
		dst := rest[1]
		if strings.HasSuffix(dst, "/") {
			dst += filepath.Base(rest[0])
		}
		ct := mime.TypeByExtension(filepath.Ext(rest[0]))
		resp, err := c.fsReq("PUT", dst, nil, f, ct)
		if err != nil {
			return err
		}
		resp.Body.Close()
		fmt.Println("Uploaded", rest[0], "->", dst)
	case "get", "cat":
		if err := need(rest, 1, "fs get <remote-path> [local-file]"); err != nil {
			return err
		}
		resp, err := c.fsReq("GET", rest[0], nil, nil, "")
		if err != nil {
			return err
		}
		defer resp.Body.Close()
		var w io.Writer = os.Stdout
		if sub == "get" {
			local := path.Base(rest[0])
			if len(rest) > 1 {
				local = rest[1]
			}
			f, err := os.Create(local)
			if err != nil {
				return err
			}
			defer f.Close()
			w = f
			defer fmt.Println("Downloaded", rest[0], "->", local)
		}
		_, err = io.Copy(w, resp.Body)
		return err
	case "rm":
		fs := flag.NewFlagSet("rm", flag.ExitOnError)
		rec := fs.Bool("r", false, "recursive")
		fs.Parse(rest)
		if fs.NArg() < 1 {
			return errors.New("usage: coffer fs rm [-r] <path>")
		}
		q := url.Values{}
		if *rec {
			q.Set("recursive", "true")
		}
		resp, err := c.fsReq("DELETE", fs.Arg(0), q, nil, "")
		if err != nil {
			return err
		}
		resp.Body.Close()
	case "mkdir":
		if err := need(rest, 1, "fs mkdir <path>"); err != nil {
			return err
		}
		resp, err := c.fsReq("POST", rest[0], url.Values{"op": {"mkdir"}}, nil, "")
		if err != nil {
			return err
		}
		resp.Body.Close()
	case "mv", "cp":
		if err := need(rest, 2, "fs "+sub+" <from> <to>"); err != nil {
			return err
		}
		op := map[string]string{"mv": "rename", "cp": "copy"}[sub]
		resp, err := c.fsReq("POST", rest[0], url.Values{"op": {op}, "to": {rest[1]}}, nil, "")
		if err != nil {
			return err
		}
		resp.Body.Close()
	case "stat":
		if err := need(rest, 1, "fs stat <path>"); err != nil {
			return err
		}
		resp, err := c.fsReq("GET", rest[0], url.Values{"meta": {"true"}}, nil, "")
		if err != nil {
			return err
		}
		defer resp.Body.Close()
		var out map[string]any
		json.NewDecoder(resp.Body).Decode(&out)
		printJSON(out)
	case "share":
		fs := flag.NewFlagSet("share", flag.ExitOnError)
		ttl := fs.String("ttl", "24h", "link lifetime")
		max := fs.Int("max-downloads", 0, "download limit (0 = unlimited)")
		fs.Parse(rest)
		if fs.NArg() < 1 {
			return errors.New("usage: coffer fs share [-ttl=24h] [-max-downloads=N] <path>")
		}
		b, _ := json.Marshal(map[string]any{"ttl": *ttl, "max_downloads": *max})
		resp, err := c.fsReq("POST", fs.Arg(0), url.Values{"op": {"share"}}, bytes.NewReader(b), "application/json")
		if err != nil {
			return err
		}
		defer resp.Body.Close()
		var out struct {
			Share map[string]any `json:"share"`
		}
		json.NewDecoder(resp.Body).Decode(&out)
		fmt.Println(out.Share["url"])
	case "encrypt":
		fs := flag.NewFlagSet("encrypt", flag.ExitOnError)
		key := fs.String("key", "", "transit key name (empty to stop encrypting new files)")
		repl := fs.String("replication", "", "replication for new files (e.g. 001)")
		ttl := fs.String("ttl", "", "TTL for new files (e.g. 7d)")
		fs.Parse(rest)
		if fs.NArg() < 1 {
			return errors.New("usage: coffer fs encrypt -key=<transit-key> <folder>")
		}
		b, _ := json.Marshal(map[string]any{"encryption_key": *key, "replication": *repl, "ttl": *ttl})
		resp, err := c.fsReq("POST", fs.Arg(0), url.Values{"op": {"config"}}, bytes.NewReader(b), "application/json")
		if err != nil {
			return err
		}
		resp.Body.Close()
		fmt.Println("Folder settings updated for", fs.Arg(0))
	default:
		return fmt.Errorf("unknown fs command %q", sub)
	}
	return nil
}

func runS3(c *client, args []string) error {
	if err := need(args, 1, "s3 <keys-create|keys-list|keys-delete>"); err != nil {
		return err
	}
	var e envelope
	switch args[0] {
	case "keys-create":
		fs := flag.NewFlagSet("keys-create", flag.ExitOnError)
		pols := fs.String("policy", "", "comma separated policies")
		desc := fs.String("description", "", "description")
		fs.Parse(args[1:])
		if err := c.do("POST", "sys/s3/keys", map[string]any{"policies": *pols, "description": *desc}, &e); err != nil {
			return err
		}
		printKV(e.Data)
		fmt.Println("\nThe secret key is shown only once. Use it with any S3 client (path-style, SigV4).")
	case "keys-list":
		if err := c.do("GET", "sys/s3/keys", nil, &e); err != nil {
			return err
		}
		printJSON(e.Data["key_info"])
	case "keys-delete":
		if err := need(args, 2, "s3 keys-delete <access-key>"); err != nil {
			return err
		}
		return c.do("DELETE", "sys/s3/keys/"+args[1], nil, nil)
	}
	return nil
}

func runCluster(c *client, args []string) error {
	if err := need(args, 1, "cluster <status|grow|vacuum>"); err != nil {
		return err
	}
	var e envelope
	switch args[0] {
	case "status":
		if err := c.do("GET", "sys/storage/status", nil, &e); err != nil {
			return err
		}
		printJSON(e.Data)
	case "grow":
		fs := flag.NewFlagSet("grow", flag.ExitOnError)
		n := fs.Int("count", 1, "volumes to add")
		coll := fs.String("collection", "", "collection")
		repl := fs.String("replication", "", "replication")
		fs.Parse(args[1:])
		if err := c.do("POST", "sys/storage/grow", map[string]any{"count": *n, "collection": *coll, "replication": *repl}, &e); err != nil {
			return err
		}
		printJSON(e.Data)
	case "vacuum":
		fs := flag.NewFlagSet("vacuum", flag.ExitOnError)
		th := fs.Float64("garbageThreshold", 0.3, "minimum garbage ratio")
		fs.Parse(args[1:])
		if err := c.do("POST", "sys/storage/vacuum", map[string]any{"garbage_threshold": *th}, &e); err != nil {
			return err
		}
		printJSON(e.Data)
	}
	return nil
}

func runSnapshot(c *client, args []string) error {
	if len(args) < 1 {
		return errors.New("usage: coffer operator snapshot save <file>  |  coffer operator snapshot restore -dir=<data-dir> <file>")
	}
	switch args[0] {
	case "save":
		if len(args) < 2 {
			return errors.New("usage: coffer operator snapshot save <file>")
		}
		req, _ := http.NewRequest("GET", c.addr+"/v1/sys/storage/snapshot", nil)
		req.Header.Set("X-Coffer-Token", c.token)
		resp, err := c.http.Do(req)
		if err != nil {
			return err
		}
		defer resp.Body.Close()
		if resp.StatusCode != 200 {
			var e struct {
				Errors []string `json:"errors"`
			}
			json.NewDecoder(resp.Body).Decode(&e)
			return &apiError{resp.StatusCode, e.Errors}
		}
		f, err := os.Create(args[1])
		if err != nil {
			return err
		}
		n, err := io.Copy(f, resp.Body)
		f.Close()
		if err != nil {
			return err
		}
		fmt.Printf("Snapshot saved to %s (%s). Keep it with your backups; it is useless without the unseal keys.\n", args[1], human(float64(n)))
		return nil
	case "restore":
		fs := flag.NewFlagSet("restore", flag.ExitOnError)
		dir := fs.String("dir", "./coffer-data", "data directory of the STOPPED server")
		fs.Parse(args[1:])
		if fs.NArg() < 1 {
			return errors.New("usage: coffer operator snapshot restore -dir=<data-dir> <file>")
		}
		file := fs.Arg(0)
		// PowerShell may split "-dir=.\\x" at the dot, leaving the folder as the first argument
		if st, err := os.Stat(file); err == nil && st.IsDir() {
			if fs.NArg() < 2 {
				return fmt.Errorf("%s is a folder, not a snapshot file; usage: coffer operator snapshot restore -dir=<data-dir> <file>", file)
			}
			*dir, file = file, fs.Arg(1)
		}
		f, err := os.Open(file)
		if err != nil {
			return err
		}
		defer f.Close()
		done, err := server.RestoreSnapshot(*dir, f)
		if err != nil {
			return err
		}
		fmt.Printf("Restored %s into %s. Previous data was moved to *.bak-* folders.\nStart the server and unseal it with the unseal keys that were valid when the snapshot was taken.\n", strings.Join(done, ", "), *dir)
		return nil
	}
	return fmt.Errorf("unknown snapshot command %q", args[0])
}
