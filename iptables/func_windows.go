package iptables

import (
	"io"
	"regexp"
	"strings"
)

// LockIP 封禁IP
func LockIP(ip string) error {
	return nil
}

// UnlockIP 解封IP
func UnlockIP(ip string) error {
	return nil
}

// Clean 清除所有规则
func Clean() (int, error) {
	return 0, nil
}

var demoGetData = []byte(`Chain INPUT (policy ACCEPT)
num  target     prot opt source               destination         
1    DROP       all  --  185.191.171.33       0.0.0.0/0           
2    DROP       all  --  185.191.171.0/24     0.0.0.0/0           
3    DROP       all  --  66.249.71.0/24       0.0.0.0/0           
4    DROP       all  --  66.249.66.0/24       0.0.0.0/0           
5    DROP       all  --  116.179.33.0/24      0.0.0.0/0           
6    DROP       all  --  36.99.136.0/24       0.0.0.0/0           
7    DROP       all  --  110.249.202.0/24     0.0.0.0/0           
8    DROP       all  --  111.225.149.0/24     0.0.0.0/0           
9    DROP       all  --  110.249.201.0/24     0.0.0.0/0           
10   DROP       all  --  111.225.148.0/24     0.0.0.0/0           
11   DROP       all  --  45.236.118.148       0.0.0.0/0           
12   DROP       all  --  114.119.153.160      0.0.0.0/0           
13   DROP       all  --  216.244.66.240       0.0.0.0/0           
14   DROP       all  --  124.220.161.119      0.0.0.0/0           
15   DROP       all  --  201.87.27.166        0.0.0.0/0           
16   DROP       all  --  157.90.181.207       0.0.0.0/0           
17   DROP       all  --  114.119.145.239      0.0.0.0/0           
18   DROP       all  --  185.142.236.41       0.0.0.0/0           
19   DROP       all  --  114.119.148.165      0.0.0.0/0           
20   DROP       all  --  65.21.206.44         0.0.0.0/0           
21   DROP       all  --  111.7.100.21         0.0.0.0/0           
22   DROP       all  --  111.7.100.27         0.0.0.0/0           
23   DROP       all  --  111.7.100.26         0.0.0.0/0           
24   DROP       all  --  111.7.100.23         0.0.0.0/0           
25   DROP       all  --  111.7.100.20         0.0.0.0/0           
26   DROP       all  --  111.7.100.22         0.0.0.0/0           
27   DROP       all  --  111.7.100.24         0.0.0.0/0           
28   DROP       all  --  111.7.100.25         0.0.0.0/0           
29   DROP       all  --  220.181.51.116       0.0.0.0/0           
30   DROP       all  --  198.241.206.38       0.0.0.0/0           
31   DROP       all  --  114.119.145.25       0.0.0.0/0           
32   DROP       all  --  114.119.151.9        0.0.0.0/0           
33   DROP       all  --  124.221.247.200      0.0.0.0/0           
34   DROP       all  --  157.55.39.39         0.0.0.0/0           
35   DROP       all  --  216.244.66.238       0.0.0.0/0           
36   DROP       all  --  216.244.66.232       0.0.0.0/0           
37   DROP       all  --  114.119.152.114      0.0.0.0/0           
38   DROP       all  --  216.244.66.244       0.0.0.0/0           
39   DROP       all  --  114.119.145.42       0.0.0.0/0           
40   DROP       all  --  103.232.213.230      0.0.0.0/0           
41   DROP       all  --  185.7.214.104        0.0.0.0/0           
42   DROP       all  --  91.206.201.109       0.0.0.0/0           
43   DROP       all  --  114.119.146.45       0.0.0.0/0           
44   DROP       all  --  114.119.145.3        0.0.0.0/0           
45   DROP       all  --  114.119.151.93       0.0.0.0/0           
46   DROP       all  --  192.99.37.124        0.0.0.0/0           
47   DROP       all  --  177.137.90.250       0.0.0.0/0           
48   DROP       all  --  154.54.249.206       0.0.0.0/0           
49   DROP       all  --  114.119.152.128      0.0.0.0/0           
50   DROP       all  --  216.244.66.237       0.0.0.0/0           
51   DROP       all  --  35.226.171.13        0.0.0.0/0           
52   DROP       all  --  216.244.66.228       0.0.0.0/0           

Chain FORWARD (policy ACCEPT)
num  target     prot opt source               destination         

Chain OUTPUT (policy ACCEPT)
num  target     prot opt source               destination `)

var regexpRule = regexp.MustCompile(`\d+\s+DROP\s+all\s+--\s+([0-9./]+)\s+0\.0\.0\.0/0`)

// Get 获取所有规则
func Get(w io.Writer) error {
	var line string
	result := regexpRule.FindAllSubmatch(demoGetData, -1)
	if len(result) > 0 {
		for _, r := range result {
			if strings.Contains(string(r[1]), "0.0.0.0") {
				continue
			}
			line = string(r[1]) + "\n"
			if _, err := w.Write([]byte(line)); err != nil {
				return err
			}
		}
	}
	return nil
}

func GetOrigin(w io.Writer) error {
	_, err := w.Write(demoGetData)
	return err
}
