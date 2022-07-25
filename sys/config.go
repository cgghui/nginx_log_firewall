package sys

import (
	"bytes"
	"io"
	"io/ioutil"
	"os"
	"regexp"
	"strconv"
	"strings"
	"time"
)

var Br = []byte{10}
var Empty = []byte("")

func NewLogHandle(f string) (*LogHandle, error) {
	fp, err := os.Open(f)
	if err != nil {
		return nil, err
	}
	return &LogHandle{Path: f, fp: fp, store: make([]LogFormat, 0)}, nil
}

type LogHandle struct {
	Path        string
	LastContent []byte    // 最后一次读取日志的内容
	LastTime    time.Time // 最后一次读取日志的时间
	fp          *os.File
	ps          int64
	store       []LogFormat
	first       bool
}

func (l *LogHandle) firstLoad() {
	// 从日志文件末尾读取256kb
	if fi, _ := l.fp.Stat(); fi.Size() <= 262144 {
		l.ps = fi.Size()
	} else {
		l.ps, _ = l.fp.Seek(0, io.SeekEnd)
		_, _ = l.fp.Seek(-262144, io.SeekEnd)
	}
	l.LastTime = time.Now()
	l.LastContent, _ = ioutil.ReadAll(l.fp)
	l.LastContent = l.LastContent[bytes.Index(l.LastContent, Br)+1:]
	for _, line := range bytes.Split(l.LastContent, Br) {
		l.add(line)
	}
}

func (l *LogHandle) load() {
	if l.first == false {
		l.firstLoad()
		l.first = true
		return
	}
	_, _ = l.fp.Seek(l.ps, io.SeekStart)
	l.LastTime = time.Now()
	l.LastContent, _ = ioutil.ReadAll(l.fp)
	if len(l.LastContent) == 0 {
		return
	}
	for _, line := range bytes.Split(l.LastContent, Br) {
		line = bytes.TrimSpace(line)
		line = bytes.ReplaceAll(line, Br, Empty)
		l.add(line)
	}
	l.ps, _ = l.fp.Seek(0, io.SeekCurrent)
}

// 日志格式
var regexpLine = [2]*regexp.Regexp{

	// 第1种格式 带域名
	// log_format main '$remote_addr - $remote_user [$time_local] "$request" $status $body_bytes_sent "$http_referer" "$http_user_agent" "$host"';
	regexp.MustCompile(`(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}) - (.+) \[(.+)] "(.+) (.+) (.+)" (\d+) (\d+) "(.+)" "(.+)" "(.+)"`),

	// 第2种格式 不带域名
	// log_format main '$remote_addr - $remote_user [$time_local] "$request" $status $body_bytes_sent "$http_referer" "$http_user_agent"';
	regexp.MustCompile(`(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}) - (.+) \[(.+)] "(.+) (.+) (.+)" (\d+) (\d+) "(.+)" "(.+)"`),
}

type LogFormat struct {
	Domain    string
	IP        string
	Datetime  time.Time
	Method    string
	Path      string
	Version   string
	Status    int
	BodySize  int64
	Referer   string
	UserAgent string
	Line      string
	Spider    bool
}

func (l *LogHandle) add(line []byte) {
	no := 1
	var ret [][]byte
	for i := range regexpLine {
		ret = regexpLine[i].FindSubmatch(line)
		if ret != nil {
			no = i
			break
		}
	}
	if ret == nil {
		return
	}
	tm, err := time.Parse("02/Jan/2006:15:04:05 -0700", string(ret[3]))
	if err != nil {
		return
	}
	sCode, _ := strconv.Atoi(string(ret[7]))
	sSize, _ := strconv.ParseInt(string(ret[8]), 10, 64)
	referer := string(ret[9])
	if referer == "-" {
		referer = ""
	}
	data := LogFormat{
		Domain:    "",
		IP:        string(ret[1]),
		Datetime:  tm,
		Method:    string(ret[4]),
		Path:      string(ret[5]),
		Version:   string(ret[6]),
		Status:    sCode,
		BodySize:  sSize,
		Referer:   referer,
		Line:      string(line),
		UserAgent: string(ret[10]),
	}
	if no == 0 {
		data.Domain = string(ret[11])
	}
	l.store = append(l.store, data)
}

type Word struct {
	IP            []string `json:"ip"`
	UrlPathWord   []string `json:"url_path_word"`
	UserAgentWord []string `json:"user_agent_word"`
}

func (w *Word) InIP(ip string) bool {
	for _, addr := range w.IP {
		if strings.Contains(ip, addr) {
			return true
		}
	}
	return false
}

func (w *Word) InPath(path string) bool {
	for _, p := range w.UrlPathWord {
		if strings.Contains(path, p) {
			return true
		}
	}
	return false
}

func (w *Word) InUserAgent(UserAgent string) bool {
	for _, ua := range w.UserAgentWord {
		if strings.Contains(UserAgent, ua) {
			return true
		}
	}
	return false
}

type Config struct {
	LogFileList []string `json:"log_file_list"`
	Black       Word     `json:"black"`
	Pass        Word     `json:"pass"`
}
