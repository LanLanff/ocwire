//go:build !windows

package main

import "errors"

func setAutostart(on bool) error {
	return errors.New("开机自启目前仅支持 Windows")
}

func getAutostart() bool { return false }
