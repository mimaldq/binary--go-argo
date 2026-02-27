package main

import (
	"bytes"
	"crypto/rand"
	"embed" // 新增：用于嵌入静态文件
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/http/httputil"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"
)

//go:embed index.html
var embeddedFiles embed.FS

// Config 配置结构体
type Config struct {
	UploadURL     string
	ProjectURL    string
	AutoAccess    bool
	FilePath      string
	SubPath       string
	Port          string
	ArgoPort      string
	UUID          string
	NezhaServer   string
	NezhaPort     string
	NezhaKey      string
	ArgoDomain    string
	ArgoAuth      string
	CFIP          string
	CFPort        string
	Name          string
	MonitorKey    string
	MonitorServer string
	MonitorURL    string
}

// 全局变量
var (
	config         Config
	files          = make(map[string]string)
	mu             sync.RWMutex
	subscription   string
	monitorProcess *os.Process
	proxyServer    *http.Server

	// 统计信息
	wsConnections int64
	totalBytes    int64
)

func main() {
	// 初始化配置
	initConfig()

	// 性能调优
	tunePerformance()

	// 创建目录
	if err := os.MkdirAll(config.FilePath, 0755); err != nil {
		log.Printf("创建目录失败: %v", err)
	} else {
		log.Printf("目录 %s 已创建或已存在", config.FilePath)
	}

	// 生成随机文件名
	generateFilenames()

	// 清理历史文件和节点
	cleanup()

	// 生成配置文件
	generateXrayConfig()

	// 生成Argo隧道配置
	argoType()

	// 启动代理服务器
	go startProxyServer()

	// 启动HTTP服务器
	go startHTTPServer()

	// 主流程
	go startMainProcess()

	// 设置信号处理
	setupSignalHandler()

	// 保持程序运行
	select {}
}

func initConfig() {
	config = Config{
		UploadURL:     getEnv("UPLOAD_URL", ""),
		ProjectURL:    getEnv("PROJECT_URL", ""),
		AutoAccess:    getEnv("AUTO_ACCESS", "false") == "true",
		FilePath:      getEnv("FILE_PATH", "./tmp"),
		SubPath:       getEnv("SUB_PATH", "sub"),
		Port:          getEnv("SERVER_PORT", getEnv("PORT", "3000")),
		ArgoPort:      getEnv("ARGO_PORT", "7860"),
		UUID:          getEnv("UUID", "e2cae6af-5cdd-fa48-4137-ad3e617fbab0"),
		NezhaServer:   getEnv("NEZHA_SERVER", ""),
		NezhaPort:     getEnv("NEZHA_PORT", ""),
		NezhaKey:      getEnv("NEZHA_KEY", ""),
		ArgoDomain:    getEnv("ARGO_DOMAIN", ""),
		ArgoAuth:      getEnv("ARGO_AUTH", ""),
		CFIP:          getEnv("CFIP", "cdns.doon.eu.org"),
		CFPort:        getEnv("CFPORT", "443"),
		Name:          getEnv("NAME", ""),
		MonitorKey:    getEnv("MONITOR_KEY", ""),
		MonitorServer: getEnv("MONITOR_SERVER", ""),
		MonitorURL:    getEnv("MONITOR_URL", ""),
	}

	log.Println("配置初始化完成")
	log.Printf("UUID: %s", config.UUID)
	log.Printf("Argo端口: %s", config.ArgoPort)
	log.Printf("HTTP端口: %s", config.Port)
}

func tunePerformance() {
	// 设置GOMAXPROCS为CPU核心数
	runtime.GOMAXPROCS(runtime.NumCPU())

	log.Printf("性能调优: GOMAXPROCS=%d, CPU核心数=%d", runtime.GOMAXPROCS(0), runtime.NumCPU())
}

func getEnv(key, defaultValue string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	return defaultValue
}

func generateFilenames() {
	// 生成6位随机小写字母
	randomName := func() string {
		const letters = "abcdefghijklmnopqrstuvwxyz"
		b := make([]byte, 6)
		rand.Read(b)
		for i := range b {
			b[i] = letters[int(b[i])%len(letters)]
		}
		return string(b)
	}

	files["npm"] = filepath.Join(config.FilePath, randomName())
	files["web"] = filepath.Join(config.FilePath, randomName())
	files["bot"] = filepath.Join(config.FilePath, randomName())
	files["php"] = filepath.Join(config.FilePath, randomName())
	files["monitor"] = filepath.Join(config.FilePath, "cf-vps-monitor.sh")
	files["sub"] = filepath.Join(config.FilePath, "sub.txt")
	files["list"] = filepath.Join(config.FilePath, "list.txt")
	files["bootLog"] = filepath.Join(config.FilePath, "boot.log")
	files["config"] = filepath.Join(config.FilePath, "config.json")
	files["nezhaConfig"] = filepath.Join(config.FilePath, "config.yaml")
	files["tunnelJson"] = filepath.Join(config.FilePath, "tunnel.json")
	files["tunnelYaml"] = filepath.Join(config.FilePath, "tunnel.yml")

	log.Println("文件名生成完成")
}

func cleanup() {
	// 清理旧文件
	if err := os.RemoveAll(config.FilePath); err != nil {
		log.Printf("清理目录失败: %v", err)
	}

	// 重新创建目录
	os.MkdirAll(config.FilePath, 0755)

	// 删除历史节点
	deleteNodes()
}

func deleteNodes() {
	if config.UploadURL == "" {
		return
	}

	// 读取订阅文件
	data, err := os.ReadFile(files["sub"])
	if err != nil {
		return
	}

	// 解码base64
	decoded, err := base64.StdEncoding.DecodeString(string(data))
	if err != nil {
		return
	}

	// 解析节点
	lines := strings.Split(string(decoded), "\n")
	var nodes []string
	for _, line := range lines {
		if strings.Contains(line, "vless://") ||
			strings.Contains(line, "vmess://") ||
			strings.Contains(line, "trojan://") ||
			strings.Contains(line, "hysteria2://") ||
			strings.Contains(line, "tuic://") {
			nodes = append(nodes, line)
		}
	}

	if len(nodes) == 0 {
		return
	}

	// 发送删除请求
	jsonData, _ := json.Marshal(map[string][]string{"nodes": nodes})
	req, err := http.NewRequest("POST", config.UploadURL+"/api/delete-nodes",
		bytes.NewBuffer(jsonData))
	if err != nil {
		return
	}
	req.Header.Set("Content-Type", "application/json")

	client := &http.Client{Timeout: 10 * time.Second}
	_, err = client.Do(req)
	if err != nil {
		log.Printf("删除节点失败: %v", err)
	}
}

func generateXrayConfig() {
	xrayConfig := map[string]interface{}{
		"log": map[string]interface{}{
			"access":   "/dev/null",
			"error":    "/dev/null",
			"loglevel": "none",
		},
		"dns": map[string]interface{}{
			"servers": []string{
				"https+local://8.8.8.8/dns-query",
				"https+local://1.1.1.1/dns-query",
				"8.8.8.8",
				"1.1.1.1",
			},
			"queryStrategy": "UseIP",
			"disableCache":  false,
		},
		"inbounds": []map[string]interface{}{
			{
				"port":     3001,
				"protocol": "vless",
				"settings": map[string]interface{}{
					"clients": []map[string]interface{}{
						{
							"id":   config.UUID,
							"flow": "xtls-rprx-vision",
						},
					},
					"decryption": "none",
					"fallbacks": []map[string]interface{}{
						{"dest": 3002},
						{"path": "/vless-argo", "dest": 3003},
						{"path": "/vmess-argo", "dest": 3004},
						{"path": "/trojan-argo", "dest": 3005},
					},
				},
				"streamSettings": map[string]interface{}{
					"network": "tcp",
				},
			},
			{
				"port":     3002,
				"listen":   "127.0.0.1",
				"protocol": "vless",
				"settings": map[string]interface{}{
					"clients": []map[string]interface{}{
						{"id": config.UUID},
					},
					"decryption": "none",
				},
				"streamSettings": map[string]interface{}{
					"network":  "tcp",
					"security": "none",
				},
			},
			{
				"port":     3003,
				"listen":   "127.0.0.1",
				"protocol": "vless",
				"settings": map[string]interface{}{
					"clients": []map[string]interface{}{
						{"id": config.UUID, "level": 0},
					},
					"decryption": "none",
				},
				"streamSettings": map[string]interface{}{
					"network":  "ws",
					"security": "none",
					"wsSettings": map[string]interface{}{
						"path": "/vless-argo",
					},
				},
				"sniffing": map[string]interface{}{
					"enabled":      true,
					"destOverride": []string{"http", "tls", "quic"},
					"metadataOnly": false,
				},
			},
			{
				"port":     3004,
				"listen":   "127.0.0.1",
				"protocol": "vmess",
				"settings": map[string]interface{}{
					"clients": []map[string]interface{}{
						{"id": config.UUID, "alterId": 0},
					},
				},
				"streamSettings": map[string]interface{}{
					"network": "ws",
					"wsSettings": map[string]interface{}{
						"path": "/vmess-argo",
					},
				},
				"sniffing": map[string]interface{}{
					"enabled":      true,
					"destOverride": []string{"http", "tls", "quic"},
					"metadataOnly": false,
				},
			},
			{
				"port":     3005,
				"listen":   "127.0.0.1",
				"protocol": "trojan",
				"settings": map[string]interface{}{
					"clients": []map[string]interface{}{
						{"password": config.UUID},
					},
				},
				"streamSettings": map[string]interface{}{
					"network":  "ws",
					"security": "none",
					"wsSettings": map[string]interface{}{
						"path": "/trojan-argo",
					},
				},
				"sniffing": map[string]interface{}{
					"enabled":      true,
					"destOverride": []string{"http", "tls", "quic"},
					"metadataOnly": false,
				},
			},
		},
		"outbounds": []map[string]interface{}{
			{
				"protocol": "freedom",
				"tag":      "direct",
				"settings": map[string]interface{}{
					"domainStrategy": "UseIP",
				},
			},
			{
				"protocol": "blackhole",
				"tag":      "block",
				"settings": map[string]interface{}{},
			},
		},
		"routing": map[string]interface{}{
			"domainStrategy": "IPIfNonMatch",
			"rules":          []interface{}{},
		},
	}

	// 写入配置文件
	data, err := json.MarshalIndent(xrayConfig, "", "  ")
	if err != nil {
		log.Printf("生成配置文件失败: %v", err)
		return
	}

	if err := os.WriteFile(files["config"], data, 0644); err != nil {
		log.Printf("写入配置文件失败: %v", err)
		return
	}

	log.Println("Xray配置文件生成完成")
}

func argoType() {
	if config.ArgoAuth == "" || config.ArgoDomain == "" {
		log.Println("ARGO_DOMAIN 或 ARGO_AUTH 为空，使用快速隧道")
		return
	}

	// 检查是否为TunnelSecret格式
	if strings.Contains(config.ArgoAuth, "TunnelSecret") {
		var tunnelConfig map[string]interface{}
		if err := json.Unmarshal([]byte(config.ArgoAuth), &tunnelConfig); err != nil {
			log.Printf("解析隧道配置失败: %v", err)
			return
		}

		// 写入tunnel.json
		if err := os.WriteFile(files["tunnelJson"], []byte(config.ArgoAuth), 0644); err != nil {
			log.Printf("写入tunnel.json失败: %v", err)
			return
		}

		// 生成tunnel.yml
		tunnelID, _ := tunnelConfig["TunnelID"].(string)
		yamlContent := fmt.Sprintf(`tunnel: %s
credentials-file: %s
protocol: http2

ingress:
  - hostname: %s
    service: http://localhost:%s
    originRequest:
      noTLSVerify: true
  - service: http_status:404
`, tunnelID, files["tunnelJson"], config.ArgoDomain, config.ArgoPort)

		if err := os.WriteFile(files["tunnelYaml"], []byte(yamlContent), 0644); err != nil {
			log.Printf("写入tunnel.yml失败: %v", err)
			return
		}

		log.Println("隧道YAML配置生成成功")
	} else {
		log.Println("ARGO_AUTH 不是TunnelSecret格式，使用token连接隧道")
	}
}

// 启动代理服务器
func startProxyServer() {
	// 创建HTTP服务器
	mux := http.NewServeMux()

	// 添加监控端点
	mux.HandleFunc("/stats", handleStats)

	// 处理所有请求
	mux.HandleFunc("/", handleProxyRequest)

	proxyServer = &http.Server{
		Addr:    ":" + config.ArgoPort,
		Handler: mux,
	}

	// 移除WebSocket相关日志，只保留基本服务器启动信息
	log.Printf("代理服务器启动在端口: %s", config.ArgoPort)

	if err := proxyServer.ListenAndServe(); err != nil && err != http.ErrServerClosed {
		log.Fatalf("代理服务器启动失败: %v", err)
	}
}

// 处理代理请求
func handleProxyRequest(w http.ResponseWriter, r *http.Request) {
	urlPath := r.URL.Path

	// 判断是否是WebSocket升级请求
	isWebSocket := strings.ToLower(r.Header.Get("Upgrade")) == "websocket"

	// 确定目标地址
	var targetHost, targetPort string
	targetHost = "localhost"

	if strings.HasPrefix(urlPath, "/vless-argo") ||
		strings.HasPrefix(urlPath, "/vmess-argo") ||
		strings.HasPrefix(urlPath, "/trojan-argo") ||
		urlPath == "/vless" ||
		urlPath == "/vmess" ||
		urlPath == "/trojan" {
		targetPort = "3001" // Xray端口
	} else {
		targetPort = config.Port // HTTP服务器端口
	}

	// WebSocket请求使用TCP级代理
	if isWebSocket {
		handleWebSocketProxy(w, r, targetHost, targetPort)
		return
	}

	// 普通HTTP请求使用标准反向代理
	handleHTTPProxy(w, r, targetHost, targetPort)
}

// TCP级WebSocket代理实现 - 移除所有正常连接的日志
func handleWebSocketProxy(w http.ResponseWriter, r *http.Request, targetHost, targetPort string) {
	// 验证WebSocket升级请求
	if r.Method != "GET" {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	if strings.ToLower(r.Header.Get("Upgrade")) != "websocket" ||
		strings.ToLower(r.Header.Get("Connection")) != "upgrade" {
		http.Error(w, "Not a WebSocket upgrade request", http.StatusBadRequest)
		return
	}

	// 连接后端服务
	backendAddr := net.JoinHostPort(targetHost, targetPort)
	backendConn, err := net.Dial("tcp", backendAddr)
	if err != nil {
		// 保留错误日志，但简化输出
		log.Printf("连接后端失败: %v", err)
		http.Error(w, "无法连接后端服务", http.StatusBadGateway)
		return
	}
	defer backendConn.Close()

	// 设置连接超时
	backendConn.SetDeadline(time.Now().Add(30 * time.Second))

	// 劫持客户端连接
	hijacker, ok := w.(http.Hijacker)
	if !ok {
		http.Error(w, "不支持连接劫持", http.StatusInternalServerError)
		return
	}

	clientConn, clientBuf, err := hijacker.Hijack()
	if err != nil {
		log.Printf("劫持连接失败: %v", err)
		http.Error(w, "连接劫持失败", http.StatusInternalServerError)
		return
	}
	defer clientConn.Close()

	// 如果有缓冲数据，先发送到后端
	if clientBuf != nil && clientBuf.Reader.Buffered() > 0 {
		buffered, _ := io.ReadAll(clientBuf.Reader)
		if _, err := backendConn.Write(buffered); err != nil {
			return // 移除错误日志，静默处理
		}
	}

	// 转发原始HTTP请求到后端
	if err := r.Write(backendConn); err != nil {
		return // 移除错误日志，静默处理
	}

	// 更新统计信息
	atomic.AddInt64(&wsConnections, 1)
	defer atomic.AddInt64(&wsConnections, -1)

	// 设置双向转发的超时
	clientConn.SetDeadline(time.Time{}) // 不超时
	backendConn.SetDeadline(time.Time{})

	// 错误通道
	errCh := make(chan error, 2)

	// 启动双向数据转发
	var bytesForwarded int64

	// 客户端 -> 后端
	go func() {
		n, err := io.Copy(backendConn, clientConn)
		atomic.AddInt64(&bytesForwarded, n)
		atomic.AddInt64(&totalBytes, n)
		errCh <- err
	}()

	// 后端 -> 客户端
	go func() {
		n, err := io.Copy(clientConn, backendConn)
		atomic.AddInt64(&bytesForwarded, n)
		atomic.AddInt64(&totalBytes, n)
		errCh <- err
	}()

	// 等待任意一端出错或完成
	select {
	case err := <-errCh:
		// 只记录非EOF的错误
		if err != nil && err != io.EOF {
			log.Printf("WebSocket转发错误: %v", err)
		}
		// 正常关闭不输出任何日志
	case <-time.After(24 * time.Hour):
		// 长时间运行，不输出日志
	}

	// 移除连接关闭的日志
}

// 普通HTTP代理处理
func handleHTTPProxy(w http.ResponseWriter, r *http.Request, targetHost, targetPort string) {
	// 直接使用targetHost和targetPort，不需要创建未使用的targetURL变量
	proxy := &httputil.ReverseProxy{
		Director: func(req *http.Request) {
			req.URL.Scheme = "http"
			req.URL.Host = fmt.Sprintf("%s:%s", targetHost, targetPort)
			req.Host = req.URL.Host

			// 保留原始请求头
			if _, ok := req.Header["User-Agent"]; !ok {
				req.Header.Set("User-Agent", "Argo-Tunnel-Proxy/1.0")
			}
		},
		ErrorHandler: func(w http.ResponseWriter, r *http.Request, err error) {
			log.Printf("HTTP代理错误: %v", err)
			http.Error(w, "代理错误", http.StatusInternalServerError)
		},
	}

	proxy.ServeHTTP(w, r)
}

// 处理统计信息请求
func handleStats(w http.ResponseWriter, r *http.Request) {
	// 使用runtime.ReadMemStats获取内存统计信息
	var memStats runtime.MemStats
	runtime.ReadMemStats(&memStats)

	stats := map[string]interface{}{
		"ws_connections": atomic.LoadInt64(&wsConnections),
		"total_bytes":    atomic.LoadInt64(&totalBytes),
		"goroutines":     runtime.NumGoroutine(),
		"memory": map[string]interface{}{
			"alloc":       formatBytes(int64(memStats.Alloc)),
			"total_alloc": formatBytes(int64(memStats.TotalAlloc)),
			"sys":         formatBytes(int64(memStats.Sys)),
			"num_gc":      memStats.NumGC, // 使用memStats.NumGC而不是runtime.NumGC
		},
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(stats)
}

func formatBytes(bytes int64) string {
	const unit = 1024
	if bytes < unit {
		return fmt.Sprintf("%d B", bytes)
	}
	div, exp := int64(unit), 0
	for n := bytes / unit; n >= unit; n /= unit {
		div *= unit
		exp++
	}
	return fmt.Sprintf("%.1f %cB", float64(bytes)/float64(div), "KMGTPE"[exp])
}

func startHTTPServer() {
	// 创建HTTP服务器
	mux := http.NewServeMux()

	// 订阅路径处理
	mux.HandleFunc("/"+config.SubPath, func(w http.ResponseWriter, r *http.Request) {
		mu.RLock()
		encoded := base64.StdEncoding.EncodeToString([]byte(subscription))
		mu.RUnlock()
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		w.Write([]byte(encoded))
	})

	// 根路径处理 - 从嵌入文件系统读取 index.html
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		data, err := embeddedFiles.ReadFile("index.html")
		if err != nil {
			// 如果嵌入文件读取失败（理论上不会），则回退到简单消息
			w.Write([]byte("Hello world!"))
			return
		}
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.Write(data)
	})

	// 启动内部HTTP服务器
	log.Printf("HTTP服务运行在内部端口: %s", config.Port)

	server := &http.Server{
		Addr:    ":" + config.Port,
		Handler: mux,
	}

	if err := server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
		log.Fatalf("HTTP服务器启动失败: %v", err)
	}
}

func startMainProcess() {
	log.Println("开始服务器初始化...")

	// 下载文件并运行
	downloadFilesAndRun()

	// 等待隧道启动
	log.Println("等待隧道启动...")
	time.Sleep(5 * time.Second)

	// 提取域名
	extractDomains()

	// 自动访问任务
	addVisitTask()

	// 启动监控脚本
	go startMonitorScript()

	// 清理文件
	go func() {
		time.Sleep(90 * time.Second)
		cleanFiles()
	}()

	log.Println("服务器初始化完成")
}

func downloadFilesAndRun() {
	// 获取系统架构
	arch := getArchitecture()

	// 确定下载URL
	var baseURL string
	if arch == "arm" {
		baseURL = "https://arm64.ssss.nyc.mn/"
	} else {
		baseURL = "https://amd64.ssss.nyc.mn/"
	}

	// 需要下载的文件列表
	var fileList []struct {
		name     string
		filePath string
		url      string
	}

	// 添加基本文件
	fileList = append(fileList, struct {
		name     string
		filePath string
		url      string
	}{
		name:     "web",
		filePath: files["web"],
		url:      baseURL + "web",
	}, struct {
		name     string
		filePath string
		url      string
	}{
		name:     "bot",
		filePath: files["bot"],
		url:      baseURL + "bot",
	})

	// 如果需要哪吒监控
	if config.NezhaServer != "" && config.NezhaKey != "" {
		if config.NezhaPort != "" {
			// v0版本
			fileList = append([]struct {
				name     string
				filePath string
				url      string
			}{{
				name:     "agent",
				filePath: files["npm"],
				url:      baseURL + "agent",
			}}, fileList...)
		} else {
			// v1版本
			fileList = append([]struct {
				name     string
				filePath string
				url      string
			}{{
				name:     "php",
				filePath: files["php"],
				url:      baseURL + "v1",
			}}, fileList...)
		}
	}

	// 下载所有文件
	var wg sync.WaitGroup
	for _, file := range fileList {
		wg.Add(1)
		go func(name, filePath, url string) {
			defer wg.Done()
			if err := downloadFile(filePath, url); err != nil {
				log.Printf("下载 %s 失败: %v", name, err)
			} else {
				log.Printf("下载 %s 成功", name)
				// 设置执行权限
				os.Chmod(filePath, 0755)
			}
		}(file.name, file.filePath, file.url)
	}
	wg.Wait()

	// 运行哪吒监控
	runNezha()

	// 运行Xray
	runXray()

	// 运行Cloudflared
	runCloudflared()
}

func getArchitecture() string {
	arch := runtime.GOARCH
	if arch == "arm" || arch == "arm64" || arch == "aarch64" {
		return "arm"
	}
	return "amd"
}

func downloadFile(filepath, url string) error {
	// 创建文件
	out, err := os.Create(filepath)
	if err != nil {
		return err
	}
	defer out.Close()

	// 下载文件
	resp, err := http.Get(url)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	// 检查响应状态
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("下载失败: %s", resp.Status)
	}

	// 写入文件
	_, err = io.Copy(out, resp.Body)
	return err
}

func runNezha() {
	if config.NezhaServer == "" || config.NezhaKey == "" {
		log.Println("哪吒监控变量为空，跳过运行")
		return
	}

	if config.NezhaPort == "" {
		// v1版本
		port := "443"
		if idx := strings.LastIndex(config.NezhaServer, ":"); idx != -1 {
			port = config.NezhaServer[idx+1:]
		}

		// 检查是否为TLS端口
		tlsPorts := map[string]bool{
			"443":  true,
			"8443": true,
			"2096": true,
			"2087": true,
			"2083": true,
			"2053": true,
		}

		nezhatls := "false"
		if tlsPorts[port] {
			nezhatls = "true"
		}

		// 生成配置文件
		yamlContent := fmt.Sprintf(`client_secret: %s
debug: false
disable_auto_update: true
disable_command_execute: false
disable_force_update: true
disable_nat: false
disable_send_query: false
gpu: false
insecure_tls: true
ip_report_period: 1800
report_delay: 4
server: %s
skip_connection_count: true
skip_procs_count: true
temperature: false
tls: %s
use_gitee_to_upgrade: false
use_ipv6_country_code: false
uuid: %s`, config.NezhaKey, config.NezhaServer, nezhatls, config.UUID)

		if err := os.WriteFile(files["nezhaConfig"], []byte(yamlContent), 0644); err != nil {
			log.Printf("生成哪吒配置失败: %v", err)
			return
		}

		// 运行哪吒
		cmd := exec.Command(files["php"], "-c", files["nezhaConfig"])
		cmd.Stdout = nil
		cmd.Stderr = nil

		if err := cmd.Start(); err != nil {
			log.Printf("运行哪吒失败: %v", err)
			return
		}

		// 分离进程
		if err := cmd.Process.Release(); err != nil {
			log.Printf("分离哪吒进程失败: %v", err)
		}

		log.Printf("%s 运行中", filepath.Base(files["php"]))
		time.Sleep(1 * time.Second)

	} else {
		// v0版本
		var args []string
		args = append(args, "-s", config.NezhaServer+":"+config.NezhaPort)
		args = append(args, "-p", config.NezhaKey)

		// 检查是否为TLS端口
		tlsPorts := map[string]bool{
			"443":  true,
			"8443": true,
			"2096": true,
			"2087": true,
			"2083": true,
			"2053": true,
		}

		if tlsPorts[config.NezhaPort] {
			args = append(args, "--tls")
		}

		args = append(args, "--disable-auto-update", "--report-delay", "4", "--skip-conn", "--skip-procs")

		cmd := exec.Command(files["npm"], args...)
		cmd.Stdout = nil
		cmd.Stderr = nil

		if err := cmd.Start(); err != nil {
			log.Printf("运行哪吒失败: %v", err)
			return
		}

		// 分离进程
		if err := cmd.Process.Release(); err != nil {
			log.Printf("分离哪吒进程失败: %v", err)
		}

		log.Printf("%s 运行中", filepath.Base(files["npm"]))
		time.Sleep(1 * time.Second)
	}
}

func runXray() {
	cmd := exec.Command(files["web"], "-c", files["config"])
	cmd.Stdout = nil
	cmd.Stderr = nil

	if err := cmd.Start(); err != nil {
		log.Printf("运行Xray失败: %v", err)
		return
	}

	// 分离进程
	if err := cmd.Process.Release(); err != nil {
		log.Printf("分离Xray进程失败: %v", err)
	}

	log.Printf("%s 运行中", filepath.Base(files["web"]))
	time.Sleep(1 * time.Second)
}

func runCloudflared() {
	if _, err := os.Stat(files["bot"]); os.IsNotExist(err) {
		log.Println("cloudflared文件不存在")
		return
	}

	var args []string
	args = append(args, "tunnel", "--edge-ip-version", "auto", "--no-autoupdate", "--protocol", "http2")

	if config.ArgoAuth != "" && config.ArgoDomain != "" {
		// 检查是否为token格式
		if len(config.ArgoAuth) >= 120 && len(config.ArgoAuth) <= 250 {
			args = append(args, "run", "--token", config.ArgoAuth)
		} else if strings.Contains(config.ArgoAuth, "TunnelSecret") {
			// 确保隧道配置文件存在
			for i := 0; i < 10; i++ {
				if _, err := os.Stat(files["tunnelYaml"]); err == nil {
					break
				}
				time.Sleep(1 * time.Second)
			}
			args = append(args, "--config", files["tunnelYaml"], "run")
		} else {
			args = append(args, "--logfile", files["bootLog"], "--loglevel", "info",
				"--url", "http://localhost:"+config.ArgoPort)
		}
	} else {
		args = append(args, "--logfile", files["bootLog"], "--loglevel", "info",
			"--url", "http://localhost:"+config.ArgoPort)
	}

	cmd := exec.Command(files["bot"], args...)
	cmd.Stdout = nil
	cmd.Stderr = nil

	if err := cmd.Start(); err != nil {
		log.Printf("运行cloudflared失败: %v", err)
		return
	}

	// 分离进程
	if err := cmd.Process.Release(); err != nil {
		log.Printf("分离cloudflared进程失败: %v", err)
	}

	log.Printf("%s 运行中", filepath.Base(files["bot"]))
}

func extractDomains() {
	var argoDomain string

	if config.ArgoAuth != "" && config.ArgoDomain != "" {
		argoDomain = config.ArgoDomain
		log.Printf("使用固定域名: %s", argoDomain)
		generateLinks(argoDomain)
		return
	}

	// 尝试从日志读取域名
	data, err := os.ReadFile(files["bootLog"])
	if err != nil {
		log.Printf("读取日志文件失败: %v", err)
		restartCloudflared()
		return
	}

	lines := strings.Split(string(data), "\n")
	for _, line := range lines {
		if strings.Contains(line, "trycloudflare.com") {
			// 提取域名
			start := strings.Index(line, "https://")
			if start == -1 {
				start = strings.Index(line, "http://")
			}
			if start != -1 {
				end := strings.Index(line[start:], " ")
				if end == -1 {
					end = len(line) - start
				}
				url := line[start : start+end]
				argoDomain = strings.TrimPrefix(strings.TrimPrefix(url, "https://"), "http://")
				argoDomain = strings.TrimSuffix(argoDomain, "/")
				log.Printf("找到临时域名: %s", argoDomain)
				generateLinks(argoDomain)
				return
			}
		}
	}

	log.Println("未找到域名，重新运行cloudflared")
	restartCloudflared()
}

func restartCloudflared() {
	// 停止现有进程
	exec.Command("pkill", "-f", filepath.Base(files["bot"])).Run()

	// 删除日志文件
	os.Remove(files["bootLog"])

	time.Sleep(3 * time.Second)

	// 重新启动
	args := []string{
		"tunnel", "--edge-ip-version", "auto", "--no-autoupdate", "--protocol", "http2",
		"--logfile", files["bootLog"], "--loglevel", "info",
		"--url", "http://localhost:" + config.ArgoPort,
	}

	cmd := exec.Command(files["bot"], args...)
	cmd.Stdout = nil
	cmd.Stderr = nil

	if err := cmd.Start(); err != nil {
		log.Printf("重启cloudflared失败: %v", err)
		return
	}

	// 分离进程
	if err := cmd.Process.Release(); err != nil {
		log.Printf("分离cloudflared进程失败: %v", err)
	}

	time.Sleep(5 * time.Second)
	extractDomains()
}

func generateLinks(domain string) {
	// 获取ISP信息
	isp := getISP()
	nodeName := config.Name
	if nodeName != "" {
		nodeName = nodeName + "-" + isp
	} else {
		nodeName = isp
	}

	// 生成VMESS配置
	vmessConfig := map[string]interface{}{
		"v":    "2",
		"ps":   nodeName,
		"add":  config.CFIP,
		"port": config.CFPort,
		"id":   config.UUID,
		"aid":  "0",
		"scy":  "none",
		"net":  "ws",
		"type": "none",
		"host": domain,
		"path": "/vmess-argo?ed=2560",
		"tls":  "tls",
		"sni":  domain,
		"alpn": "",
		"fp":   "firefox",
	}

	vmessJSON, _ := json.Marshal(vmessConfig)
	vmessBase64 := base64.StdEncoding.EncodeToString(vmessJSON)

	// 生成订阅内容
	subTxt := fmt.Sprintf(`
vless://%s@%s:%s?encryption=none&security=tls&sni=%s&fp=firefox&type=ws&host=%s&path=%%2Fvless-argo%%3Fed%%3D2560#%s

vmess://%s

trojan://%s@%s:%s?security=tls&sni=%s&fp=firefox&type=ws&host=%s&path=%%2Ftrojan-argo%%3Fed%%3D2560#%s
`, config.UUID, config.CFIP, config.CFPort, domain, domain, nodeName,
		vmessBase64,
		config.UUID, config.CFIP, config.CFPort, domain, domain, nodeName)

	// 更新订阅缓存
	mu.Lock()
	subscription = subTxt
	mu.Unlock()

	// 保存到文件
	encoded := base64.StdEncoding.EncodeToString([]byte(subTxt))
	if err := os.WriteFile(files["sub"], []byte(encoded), 0644); err != nil {
		log.Printf("保存订阅文件失败: %v", err)
	} else {
		log.Printf("订阅文件已保存: %s", files["sub"])
	}

	// 打印base64内容
	log.Printf("订阅base64内容:\n%s", encoded)

	// 上传节点
	uploadNodes()
}

// 修改后的 getISP 函数
func getISP() string {
	client := &http.Client{Timeout: 3 * time.Second}

	// 第一个API: api.ip.sb/geoip
	req, err := http.NewRequest("GET", "https://api.ip.sb/geoip", nil)
	if err == nil {
		req.Header.Set("User-Agent", "Mozilla/5.0")
		resp, err := client.Do(req)
		if err == nil {
			defer resp.Body.Close()
			var data map[string]interface{}
			if err := json.NewDecoder(resp.Body).Decode(&data); err == nil {
				country, ok1 := data["country_code"].(string)
				isp, ok2 := data["isp"].(string)
				if ok1 && ok2 && country != "" && isp != "" {
					combined := country + "-" + isp
					// 替换所有空白字符为下划线
					re := regexp.MustCompile(`\s+`)
					return re.ReplaceAllString(combined, "_")
				}
			}
		}
	}

	// 备用API: ip-api.com/json
	req, err = http.NewRequest("GET", "http://ip-api.com/json", nil)
	if err == nil {
		req.Header.Set("User-Agent", "Mozilla/5.0")
		resp, err := client.Do(req)
		if err == nil {
			defer resp.Body.Close()
			var data map[string]interface{}
			if err := json.NewDecoder(resp.Body).Decode(&data); err == nil {
				if status, ok := data["status"].(string); ok && status == "success" {
					country, ok1 := data["countryCode"].(string)
					org, ok2 := data["org"].(string)
					if ok1 && ok2 && country != "" && org != "" {
						combined := country + "-" + org
						re := regexp.MustCompile(`\s+`)
						return re.ReplaceAllString(combined, "_")
					}
				}
			}
		}
	}

	return "Unknown"
}

func uploadNodes() {
	if config.UploadURL == "" {
		return
	}

	if config.ProjectURL != "" {
		// 上传订阅
		subscriptionUrl := config.ProjectURL + "/" + config.SubPath
		jsonData := map[string][]string{
			"subscription": {subscriptionUrl},
		}

		data, _ := json.Marshal(jsonData)
		req, err := http.NewRequest("POST", config.UploadURL+"/api/add-subscriptions",
			bytes.NewBuffer(data))
		if err != nil {
			log.Printf("创建上传请求失败: %v", err)
			return
		}
		req.Header.Set("Content-Type", "application/json")

		client := &http.Client{Timeout: 10 * time.Second}
		resp, err := client.Do(req)

		if err != nil {
			log.Printf("订阅上传失败: %v", err)
			return
		}
		defer resp.Body.Close()

		if resp.StatusCode == 200 {
			log.Println("订阅上传成功")
		} else if resp.StatusCode == 400 {
			log.Println("订阅已存在")
		} else {
			log.Printf("订阅上传失败，状态码: %d", resp.StatusCode)
		}
	} else {
		// 上传节点
		if _, err := os.Stat(files["list"]); os.IsNotExist(err) {
			return
		}

		data, err := os.ReadFile(files["list"])
		if err != nil {
			return
		}

		lines := strings.Split(string(data), "\n")
		var nodes []string
		for _, line := range lines {
			if strings.Contains(line, "vless://") ||
				strings.Contains(line, "vmess://") ||
				strings.Contains(line, "trojan://") ||
				strings.Contains(line, "hysteria2://") ||
				strings.Contains(line, "tuic://") {
				nodes = append(nodes, line)
			}
		}

		if len(nodes) == 0 {
			return
		}

		jsonData, _ := json.Marshal(map[string][]string{"nodes": nodes})
		req, err := http.NewRequest("POST", config.UploadURL+"/api/add-nodes",
			bytes.NewBuffer(jsonData))
		if err != nil {
			return
		}
		req.Header.Set("Content-Type", "application/json")

		client := &http.Client{Timeout: 10 * time.Second}
		_, err = client.Do(req)

		if err != nil {
			log.Printf("节点上传失败: %v", err)
		} else {
			log.Println("节点上传成功")
		}
	}
}

func addVisitTask() {
	if !config.AutoAccess || config.ProjectURL == "" {
		log.Println("跳过自动访问任务")
		return
	}

	jsonData := map[string]string{"url": config.ProjectURL}
	data, _ := json.Marshal(jsonData)

	req, err := http.NewRequest("POST", "https://oooo.serv00.net/add-url",
		bytes.NewBuffer(data))
	if err != nil {
		log.Printf("创建自动访问请求失败: %v", err)
		return
	}
	req.Header.Set("Content-Type", "application/json")

	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Do(req)

	if err != nil {
		log.Printf("添加自动访问任务失败: %v", err)
		return
	}
	defer resp.Body.Close()

	if resp.StatusCode == 200 {
		log.Println("自动访问任务添加成功")
	} else {
		log.Printf("添加自动访问任务失败，状态码: %d", resp.StatusCode)
	}
}

func startMonitorScript() {
	// 检查监控配置是否完整
	if config.MonitorKey == "" || config.MonitorServer == "" || config.MonitorURL == "" {
		log.Println("监控环境变量不完整，跳过监控脚本启动")
		return
	}

	// 等待一段时间，确保其他服务已启动
	time.Sleep(10 * time.Second)

	log.Println("开始下载并运行监控脚本...")

	// 下载监控脚本
	if err := downloadMonitorScript(); err != nil {
		log.Printf("下载监控脚本失败: %v", err)
		return
	}

	// 设置执行权限
	if err := os.Chmod(files["monitor"], 0755); err != nil {
		log.Printf("设置监控脚本执行权限失败: %v", err)
		return
	}

	// 运行监控脚本
	go runMonitorScript()
}

func downloadMonitorScript() error {
	monitorURL := "https://raw.githubusercontent.com/mimaldq/cf-vps-monitor/main/cf-vps-monitor.sh"

	log.Printf("从 %s 下载监控脚本", monitorURL)

	// 创建文件
	out, err := os.Create(files["monitor"])
	if err != nil {
		return err
	}
	defer out.Close()

	// 下载文件
	resp, err := http.Get(monitorURL)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	// 检查响应状态
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("下载监控脚本失败: %s", resp.Status)
	}

	// 写入文件
	_, err = io.Copy(out, resp.Body)
	if err != nil {
		return err
	}

	log.Println("监控脚本下载完成")
	return nil
}

func runMonitorScript() {
	// 构建命令参数
	args := []string{
		"-i",                    // 安装模式
		"-k", config.MonitorKey, // 密钥
		"-s", config.MonitorServer, // 服务器标识
		"-u", config.MonitorURL, // 上报地址
	}

	log.Printf("运行监控脚本: %s %s", files["monitor"], strings.Join(args, " "))

	// 执行命令
	cmd := exec.Command(files["monitor"], args...)

	// 捕获输出
	stdout, _ := cmd.StdoutPipe()
	stderr, _ := cmd.StderrPipe()

	if err := cmd.Start(); err != nil {
		log.Printf("运行监控脚本失败: %v", err)
		return
	}

	// 保存进程引用
	monitorProcess = cmd.Process

	// 读取输出
	go func() {
		io.Copy(os.Stdout, stdout)
	}()
	go func() {
		io.Copy(os.Stderr, stderr)
	}()

	log.Println("监控脚本启动成功")

	// 等待进程结束（可选，但为了清理可以等待）
	err := cmd.Wait()
	if err != nil {
		log.Printf("监控脚本退出: %v", err)
	} else {
		log.Println("监控脚本正常退出")
	}
	// 注意：不再递归调用自身，脚本只运行一次
}

func cleanFiles() {
	// 要删除的文件列表
	filesToDelete := []string{
		files["bootLog"],
		files["config"],
		files["web"],
		files["bot"],
		files["monitor"],
	}

	if config.NezhaPort != "" {
		filesToDelete = append(filesToDelete, files["npm"])
	} else if config.NezhaServer != "" && config.NezhaKey != "" {
		filesToDelete = append(filesToDelete, files["php"])
	}

	// 删除文件
	for _, file := range filesToDelete {
		if err := os.Remove(file); err != nil && !os.IsNotExist(err) {
			log.Printf("删除文件失败 %s: %v", file, err)
		}
	}

	log.Println("应用正在运行")
	log.Println("感谢使用此脚本，享受吧！")
}

func setupSignalHandler() {
	c := make(chan os.Signal, 1)
	signal.Notify(c, os.Interrupt, syscall.SIGTERM)

	go func() {
		<-c
		log.Println("收到关闭信号，正在清理...")

		// 停止监控进程
		if monitorProcess != nil {
			log.Println("停止监控脚本...")
			monitorProcess.Kill()
		}

		// 关闭代理服务器
		if proxyServer != nil {
			proxyServer.Close()
		}

		log.Println("程序退出")
		os.Exit(0)
	}()
}
