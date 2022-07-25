package iptables

import (
	"io"
	"os/exec"
	"regexp"
	"strings"
)

// LockIP 封禁IP
func LockIP(ip string) error {
	command := "iptables -A INPUT -s " + ip + " -j DROP"
	cmd := exec.Command("/bin/bash", "-c", command)
	_, err := cmd.Output()
	return err
}

// UnlockIP 解封IP
func UnlockIP(ip string) error {
	command := "iptables -D INPUT -s " + ip + " -j DROP"
	cmd := exec.Command("/bin/bash", "-c", command)
	_, err := cmd.Output()
	return err
}

var regexpRule = regexp.MustCompile(`\d+\s+DROP\s+all\s+--\s+([0-9./]+)\s+0\.0\.0\.0/0`)

// Clean 清除所有规则
func Clean() (int, error) {
	command := "iptables -L -n --line-numbers"
	cmd := exec.Command("/bin/bash", "-c", command)
	ret, err := cmd.Output()
	if err != nil {
		return 0, err
	}
	result := regexpRule.FindAllSubmatch(ret, -1)
	if len(result) > 0 {
		for _, r := range result {
			_ = UnlockIP(string(r[1]))
		}
	}
	return len(result), err
}

// Get 获取所有规则
func Get(w io.Writer) error {
	command := "iptables -L -n --line-numbers"
	cmd := exec.Command("/bin/bash", "-c", command)
	ret, err := cmd.Output()
	if err != nil {
		return err
	}
	var line string
	result := regexpRule.FindAllSubmatch(ret, -1)
	if len(result) > 0 {
		for _, r := range result {
			if strings.Contains(string(r[1]), "0.0.0.0") {
				continue
			}
			line = string(r[1]) + "\n"
			if _, err = w.Write([]byte(line)); err != nil {
				return err
			}
		}
	}
	return err
}

func GetOrigin(w io.Writer) error {
	command := "iptables -L -n --line-numbers"
	cmd := exec.Command("/bin/bash", "-c", command)
	ret, err := cmd.Output()
	if err != nil {
		return err
	}
	_, err = w.Write(ret)
	return err
}
