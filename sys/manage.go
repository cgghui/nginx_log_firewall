package sys

import (
	"github.com/cgghui/nginx_log_firewall/iptables"
	"strings"
	"sync"
	"time"
)

var LockListMx = &sync.Mutex{}
var LockListIP = make(map[string][]*LockInfo, 0)

var unlockTime = 86400 * time.Second // 1日 IP段锁后，解锁时间

type LockInfo struct {
	IP         string
	ExpireTime time.Time
}

// ipPrefix IP前段如：127.0.0.1 取出为：127.0.0
func ipPrefix(ip string) string {
	arr := strings.SplitN(ip, ".", 4)
	if len(arr) != 4 {
		return ""
	}
	return arr[0] + "." + arr[1] + "." + arr[2]
}

// Clear 从内存中清除所有被封IP，iptables中不被清除
func Clear() {
	LockListMx.Lock()
	defer LockListMx.Unlock()
	LockListIP = make(map[string][]*LockInfo, 0)
}

// LockIP 封锁IP
// 如果IP已被封锁，则不重复封锁
// 如果IP为段，则封锁段，段内具体的IP则清除
func LockIP(ip string) {
	LockListMx.Lock()
	defer LockListMx.Unlock()
	prefix := ipPrefix(ip)
	if prefix == "" {
		return
	}
	//
	if _, ok := LockListIP[prefix]; !ok {
		LockListIP[prefix] = make([]*LockInfo, 0)
	}
	//
	if strings.HasSuffix(ip, ".0/24") {
		if len(LockListIP[prefix]) == 1 && LockListIP[prefix][0].IP == "*" {
			return
		}
		for _, info := range LockListIP[prefix] {
			if info.IP != "*" {
				_ = iptables.UnlockIP(info.IP)
			}
		}
		LockListIP[prefix] = []*LockInfo{
			{
				IP:         "*",
				ExpireTime: time.Now().Add(unlockTime),
			},
		}
		_ = iptables.LockIP(ip)
		return
	}
	//
	if len(LockListIP[prefix]) == 1 && LockListIP[prefix][0].IP == "*" {
		return
	}
	for _, info := range LockListIP[prefix] {
		if info.IP == ip {
			return
		}
	}
	LockListIP[prefix] = append(LockListIP[prefix], &LockInfo{
		IP:         ip,
		ExpireTime: time.Now().Add(time.Hour),
	})
	_ = iptables.LockIP(ip)
}

// UnlockIP 解锁IP
func UnlockIP(ip string) {
	LockListMx.Lock()
	defer LockListMx.Unlock()
	prefix := ipPrefix(ip)
	if prefix == "" {
		return
	}
	if _, ok := LockListIP[prefix]; !ok {
		return
	}
	if len(LockListIP[prefix]) == 1 && LockListIP[prefix][0].IP == "*" {
		_ = iptables.UnlockIP(prefix + ".0/24")
		LockListIP[prefix] = LockListIP[prefix][:0]
		return
	}
	list := make([]*LockInfo, 0)
	for _, info := range LockListIP[prefix] {
		if info.IP == ip {
			_ = iptables.UnlockIP(ip)
			continue
		}
		list = append(list, info)
	}
	LockListIP[prefix] = list
}

func ExpireUnlock() {
	t := time.NewTimer(0)
	for range t.C {
		LockListMx.Lock()
		for prefix, data := range LockListIP {
			if len(data) > 10 {
				for _, info := range data {
					_ = iptables.UnlockIP(info.IP)
				}
				_ = iptables.LockIP(prefix + ".0/24")
				LockListIP[prefix] = []*LockInfo{
					{
						IP:         "*",
						ExpireTime: time.Now().Add(unlockTime),
					},
				}
			} else {
				if len(LockListIP[prefix]) == 1 && LockListIP[prefix][0].IP == "*" {
					if time.Now().After(LockListIP[prefix][0].ExpireTime) {
						_ = iptables.UnlockIP(prefix + ".0/24")
						LockListIP[prefix] = LockListIP[prefix][:0]
					}
					continue
				}
				list := make([]*LockInfo, 0)
				for _, info := range data {
					if time.Now().After(info.ExpireTime) {
						_ = iptables.UnlockIP(info.IP)
						continue
					}
					list = append(list, info)
				}
				LockListIP[prefix] = list
			}
		}
		LockListMx.Unlock()
		t.Reset(time.Second)
	}
}
