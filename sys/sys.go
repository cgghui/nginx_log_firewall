package sys

import (
	"bytes"
	"github.com/cgghui/nginx_log_firewall/iptables"
	"log"
	"strings"
	"time"
)

var LogHandleList = make([]*LogHandle, 0)

func Run(conf *Config) {

	ret := &bytes.Buffer{}
	_ = iptables.Get(ret)
	for _, ip := range strings.Split(ret.String(), "\n") {
		LockIP(ip)
	}
	for _, ip := range conf.Black.IP {
		LockIP(ip)
	}
	for _, ip := range conf.Pass.IP {
		UnlockIP(ip)
	}

	for i := range conf.LogFileList {
		lh, err := NewLogHandle(conf.LogFileList[i])
		if err != nil {
			log.Printf("Error: %v", err)
			continue
		}
		LogHandleList = append(LogHandleList, lh)
		go logHandleThread(lh, conf)
	}

	go ExpireUnlock()
}

func logHandleThread(lh *LogHandle, conf *Config) {
	t := time.NewTimer(0)
	for range t.C {
		lh.load()
		for _, s := range lh.store {
			if conf.Pass.InIP(s.IP) || conf.Pass.InPath(s.Path) || conf.Pass.InUserAgent(s.UserAgent) {
				UnlockIP(s.IP)
			} else {
				LockIP(s.IP)
			}
		}
		lh.store = lh.store[:0]
		t.Reset(time.Second)
	}
}
