// Package alert 提供告警通知（Webhook / Email）。
package alert

import (
	"bytes"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"net/smtp"
	"strings"
	"time"
)

// Config 告警配置。
type Config struct {
	WebhookURL  string `yaml:"webhook_url"`
	WebhookType string `yaml:"webhook_type"` // "generic" / "slack" / "dingtalk"
	Email       struct {
		SMTPHost string   `yaml:"smtp_host"`
		SMTPPort int      `yaml:"smtp_port"`
		Username string   `yaml:"username"`
		Password string   `yaml:"password"`
		From     string   `yaml:"from"`
		To       []string `yaml:"to"`
	} `yaml:"email"`
	Threshold int `yaml:"threshold"` // 每秒丢包超过此值触发告警
}

// AlertEvent 告警事件。
type AlertEvent struct {
	Time    time.Time `json:"time"`
	Level   string    `json:"level"` // info / warning / critical
	Message string    `json:"message"`
	Rule    string    `json:"rule,omitempty"`
	SrcIP   string    `json:"src_ip,omitempty"`
}

// Manager 告警管理器。
type Manager struct {
	cfg       *Config
	dropCount int64
	lastAlert time.Time
}

// NewManager 创建告警管理器。
func NewManager(cfg *Config) *Manager {
	if cfg == nil {
		cfg = &Config{}
	}
	if cfg.Threshold <= 0 {
		cfg.Threshold = 100
	}
	return &Manager{cfg: cfg}
}

// Notify 发送告警。
func (m *Manager) Notify(evt AlertEvent) {
	if evt.Time.IsZero() {
		evt.Time = time.Now()
	}
	// Webhook
	if m.cfg.WebhookURL != "" {
		go m.sendWebhook(evt)
	}
	// Email
	if m.cfg.Email.SMTPHost != "" && len(m.cfg.Email.To) > 0 {
		go m.sendEmail(evt)
	}
}

// CheckDropRate 检查丢包率，超过阈值触发告警（节流：每 60 秒最多一次）。
func (m *Manager) CheckDropRate(dropsPerSec int64) {
	if dropsPerSec < int64(m.cfg.Threshold) {
		return
	}
	if time.Since(m.lastAlert) < 60*time.Second {
		return
	}
	m.lastAlert = time.Now()
	m.Notify(AlertEvent{
		Level:   "critical",
		Message: fmt.Sprintf("高丢包率告警: %d pps 超过阈值 %d", dropsPerSec, m.cfg.Threshold),
	})
}

func (m *Manager) sendWebhook(evt AlertEvent) {
	body, _ := json.Marshal(evt)
	var payload []byte
	switch m.cfg.WebhookType {
	case "slack":
		payload, _ = json.Marshal(map[string]string{
			"text": fmt.Sprintf("[%s] %s", evt.Level, evt.Message),
		})
	case "dingtalk":
		payload, _ = json.Marshal(map[string]interface{}{
			"msgtype": "text",
			"text":    map[string]string{"content": fmt.Sprintf("[%s] %s", evt.Level, evt.Message)},
		})
	default:
		payload = body
	}
	resp, err := http.Post(m.cfg.WebhookURL, "application/json", bytes.NewReader(payload))
	if err != nil {
		log.Printf("[alert] webhook failed: %v", err)
		return
	}
	resp.Body.Close()
}

func (m *Manager) sendEmail(evt AlertEvent) {
	cfg := m.cfg.Email
	subject := fmt.Sprintf("[gofw %s] %s", evt.Level, evt.Message)
	body := fmt.Sprintf("From: %s\r\nTo: %s\r\nSubject: %s\r\nContent-Type: text/plain; charset=UTF-8\r\n\r\n%s",
		cfg.From, strings.Join(cfg.To, ","), subject, evt.Message)
	addr := fmt.Sprintf("%s:%d", cfg.SMTPHost, cfg.SMTPPort)
	auth := smtp.PlainAuth("", cfg.Username, cfg.Password, cfg.SMTPHost)
	if err := smtp.SendMail(addr, auth, cfg.From, cfg.To, []byte(body)); err != nil {
		log.Printf("[alert] email failed: %v", err)
	}
}
