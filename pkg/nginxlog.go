package main

import (
	"bufio"
	"context"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/falcosecurity/plugin-sdk-go/pkg/sdk"
	"github.com/falcosecurity/plugin-sdk-go/pkg/sdk/plugins"
	"github.com/falcosecurity/plugin-sdk-go/pkg/sdk/plugins/source"
	"github.com/falcosecurity/plugin-sdk-go/pkg/sdk/plugins/extractor"
)

const (
	PluginID          uint32 = 42
	PluginName               = "nginxlog"
	PluginDescription        = "Falco plugin for monitoring nginx access logs"
	PluginContact            = "you@example.com"
	PluginVersion            = "0.1.0"
	PluginEventSource        = "nginx"
)

type Plugin struct {
	plugins.BasePlugin
	eventChan chan string
}

func (p *Plugin) Info() *plugins.Info {
	return &plugins.Info{
		ID:          PluginID,
		Name:        PluginName,
		Description: PluginDescription,
		Contact:     PluginContact,
		Version:     PluginVersion,
		EventSource: PluginEventSource,
	}
}

func (p *Plugin) Init(config string) error {
	p.eventChan = make(chan string, 1000)
	return nil
}

func (p *Plugin) Open(prms string) (source.Instance, error) {
	logFile := "/var/log/nginx/access.log"
	if prms != "" {
		logFile = prms
	}
	f, err := os.Open(logFile)
	if err != nil {
		return nil, fmt.Errorf("cannot open log file: %s", err)
	}
	go func() {
		r := bufio.NewReader(f)
		for {
			line, err := r.ReadString('\n')
			if err != nil {
				time.Sleep(200 * time.Millisecond)
				continue
			}
			p.eventChan <- strings.TrimSpace(line)
		}
	}()

	pull := func(ctx context.Context, evt sdk.EventWriter) error {
		select {
		case <-ctx.Done():
			f.Close()
			return ctx.Err()
		case line := <-p.eventChan:
			evt.SetTimestamp(uint64(time.Now().UnixNano()))
			evt.Writer().Write([]byte(line))
			return nil
		}
	}
	return source.NewPullInstance(pull)
}

func (p *Plugin) Fields() []sdk.FieldEntry {
	return []sdk.FieldEntry{
		{
			Type: "string",
			Name: "nginx.uri",
			Desc: "Request URI",
		},
	}
}

func (p *Plugin) Extract(req sdk.ExtractRequest, evt sdk.EventReader) error {
	data, err := io.ReadAll(evt.Reader())
	if err != nil {
		return err
	}
	line := string(data)
	parts := strings.Split(line, "\"")
	if len(parts) >= 2 {
		tokens := strings.Fields(parts[1])
		if len(tokens) >= 2 {
			req.SetValue(tokens[1]) // URI
			return nil
		}
	}
	req.SetValue("")
	return nil
}

func init() {
	plugins.SetFactory(func() plugins.Plugin {
		p := &Plugin{}
		source.Register(p)
		extractor.Register(p)
		return p
	})
}

func main() {}

