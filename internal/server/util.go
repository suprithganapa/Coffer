package server

import (
	"fmt"
	"net/url"

	"coffer/internal/filer"
	"strconv"
)

func itoa(n int) string                     { return strconv.Itoa(n) }
func ftoa(f float64) string                 { return strconv.FormatFloat(f, 'f', -1, 64) }
func qesc(s string) string                  { return url.QueryEscape(s) }
func fmtSscan(s string, v any) (int, error) { return fmt.Sscan(s, v) }

func filerWriteOpts() filer.WriteOptions { return filer.WriteOptions{Owner: "test"} }
