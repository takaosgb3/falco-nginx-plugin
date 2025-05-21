package main

import (
    "bytes"
    "io"
    "testing"
)

type mockEvent struct{
    *bytes.Buffer
}

func (m mockEvent) Reader() io.Reader { return m.Buffer }

type mockRequest struct{
    value interface{}
}

func (m *mockRequest) SetValue(v interface{}) { m.value = v }

func TestExtractURI(t *testing.T) {
    logLine := `127.0.0.1 - - [12/Jun/2021:19:04:04 +0000] "GET /admin HTTP/1.1" 200 612 "-" "curl/7.68.0"`
    evt := mockEvent{Buffer: bytes.NewBufferString(logLine)}
    req := &mockRequest{}
    p := &Plugin{}
    if err := p.Extract(req, evt); err != nil {
        t.Fatalf("extract failed: %v", err)
    }
    if req.value != "/admin" {
        t.Fatalf("unexpected uri: %v", req.value)
    }
}
