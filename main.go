package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"github.com/cgghui/nginx_log_firewall/iptables"
	"github.com/cgghui/nginx_log_firewall/sys"
	"github.com/gin-gonic/gin"
	"io"
	"io/ioutil"
	"log"
	"net/http"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"syscall"
	"time"
)

var conf sys.Config

func main() {

	b, err := ioutil.ReadFile("./config.json")
	if err != nil {
		log.Fatalf("Error: %v", err)
	}

	if err = json.Unmarshal(b, &conf); err != nil {
		log.Fatalf("Error: %v", err)
	}

	go func() {
		r := gin.Default()
		gin.SetMode(gin.ReleaseMode)
		r.GET("/", func(ctx *gin.Context) {
			ctx.String(http.StatusOK, "/unlock/:ip 解封IP\n/reload 重载配置\n/black_ip_list 黑名单IP列表\n/log_last_data 最近一次读取的日志\n/log_load/:idx 加载日志\n/black_clear 清除所有黑名单IP")
		})
		r.GET("/unlock/:ip", WebUnlock) // /unlock/:ip?pass=1	   pass设为1时，添加至白名单
		r.GET("/reload", WebReload)
		r.GET("/black_ip_list", WebListBlackIP)
		r.GET("/log_last_data", WebLogLastData)
		r.GET("/black_clear", WebBlackClear)
		r.GET("/log_load/:idx", WebLogLoad)
		srv := &http.Server{
			Addr:           ":8088",
			Handler:        r,
			ReadTimeout:    10 * time.Second,
			WriteTimeout:   20 * time.Second,
			MaxHeaderBytes: 1 << 20,
		}
		if err = srv.ListenAndServe(); err != nil {
			log.Fatalf("启动WEB服务失败: %s", err.Error())
		}
	}()

	sys.Run(&conf)

	quit := make(chan os.Signal)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)
	<-quit
}

func WebUnlock(ctx *gin.Context) {
	ip := ctx.Param("ip")
	msg := ""
	if ctx.DefaultQuery("pass", "") == "1" {
		msg = " 白名单成功"
		if !conf.Pass.InIP(ip) {
			conf.Pass.IP = append(conf.Pass.IP, ip)
		}
	}
	sys.UnlockIP(ip)
	ctx.String(http.StatusOK, fmt.Sprintf("解封成功[%s]%s", ip, msg))
}

func WebReload(ctx *gin.Context) {
	b, err := ioutil.ReadFile("./config.json")
	if err != nil {
		ctx.String(http.StatusOK, "Error: %v", err)
		return
	}
	if err = json.Unmarshal(b, &conf); err != nil {
		ctx.String(http.StatusOK, "Error: %v", err)
		return
	}
	ctx.String(http.StatusOK, "Reload Success.")
}

func WebListBlackIP(ctx *gin.Context) {
	ret := &bytes.Buffer{}
	_ = iptables.GetOrigin(ret)
	text := "[iptables -L -n --line-numbers]\n" + ret.String() + "\n\n[sys memory]\n"
	sys.LockListMx.Lock()
	for pre, list := range sys.LockListIP {
		if len(list) == 1 && list[0].IP == "*" {
			text += list[0].ExpireTime.Format("2006-01-02 15:04:05") + "  " + pre + ".0/24\n"
		} else {
			for _, info := range list {
				text += info.ExpireTime.Format("2006-01-02 15:04:05") + "  " + info.IP + "\n"
			}
		}
	}
	sys.LockListMx.Unlock()
	ctx.String(http.StatusOK, text)
}

func WebLogLastData(ctx *gin.Context) {
	text := ""
	for _, lh := range sys.LogHandleList {
		text += "Path: " + lh.Path + "\n"
		text += "Date: " + lh.LastTime.Format("2006-01-02 15:04:05") + "\n"
		text += "Text\n" + string(lh.LastContent) + "\n"
		text += "\n\n"
	}
	ctx.String(http.StatusOK, text)
}

func WebBlackClear(ctx *gin.Context) {
	_, _ = iptables.Clean()
	sys.Clear()
	ctx.String(http.StatusOK, "已清理")
}

func WebLogLoad(ctx *gin.Context) {
	idx, _ := strconv.Atoi(ctx.Param("idx"))
	if idx > len(conf.LogFileList) {
		ctx.String(http.StatusOK, "打开日志文件失败：索引文件不存在")
		return
	}
	fp, err := os.Open(conf.LogFileList[idx])
	if err != nil {
		ctx.String(http.StatusOK, "打开日志文件失败：%s Error: %v", conf.LogFileList[idx], err)
		return
	}
	_, err = fp.Seek(-262144, io.SeekEnd)
	if err != nil {
		ctx.String(http.StatusOK, "偏移光标位置失败 Error: %v", err)
		return
	}
	text, err := ioutil.ReadAll(fp)
	if err != nil {
		ctx.String(http.StatusOK, "读取日志内容失败 Error: %v", err)
		return
	}
	defer func() {
		_ = fp.Close()
	}()
	dat := strings.Split(string(text[bytes.IndexByte(text, 10)+1:]), "\n")
	length := len(dat)
	tmp := make([]string, length, length)
	for _, line := range dat {
		length--
		tmp[length] = line
	}
	ctx.String(http.StatusOK, "Nginx load size: 256KB"+strings.Join(tmp, "\n"))
}
