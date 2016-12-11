package rest

import (
	"bytes"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"io"
	"io/ioutil"
	"net/http"
	"strings"
	"time"

	"errors"
	"fmt"
	"net/url"
)

// borrowed from net/http
func BasicAuth(username, password string) string {
	auth := username + ":" + password
	return base64.StdEncoding.EncodeToString([]byte(auth))
}

func MakeQueryString(m map[string]string) string {
	qs := ""
	for k, v := range m {
		if len(v) == 0 {
			continue
		}
		if len(qs) == 0 {
			qs += "?"
		} else {
			qs += "&"
		}
		qs += k + "=" + url.QueryEscape(v)
	}
	return qs
}

type Config struct {
	BaseURL     string
	Token       string
	TokenHeader string
	AuthScheme  string
}

type Client struct {
	config     *Config
	httpClient *http.Client
}

func NewClient(config Config) *Client {
	// TODO should be configurable
	transport := &http.Transport{
		TLSClientConfig: &tls.Config{
			InsecureSkipVerify: true, // ignore expired SSL certificates
		},
	}

	httpClient := &http.Client{
		Timeout:   time.Second * 30,
		Transport: transport,
	}

	return &Client{
		config:     &config,
		httpClient: httpClient,
	}
}

func (c *Client) Get(path string, result interface{}) error {
	return c.Fetch("GET", path, c.makeHeader(), nil, result)
}

func (c *Client) Post(path string, payload, result interface{}) error {
	return c.Fetch("POST", path, c.makeHeader(), payload, result)
}

func (c *Client) Put(path string, payload, result interface{}) error {
	return c.Fetch("PUT", path, c.makeHeader(), payload, result)
}

func (c *Client) Delete(path string) error {
	return c.Fetch("DELETE", path, c.makeHeader(), nil, nil)
}

func (c *Client) makeHeader() http.Header {
	h := http.Header{}

	if len(c.config.Token) > 0 {
		if len(c.config.TokenHeader) > 0 {
			h.Set(c.config.TokenHeader, c.config.Token)
		} else if len(c.config.AuthScheme) > 0 {
			h.Set("Authorization", c.config.AuthScheme+" "+c.config.Token)
		} else {
			h.Set("Authorization", "Bearer "+c.config.Token)
		}
	}

	return h
}

func (c *Client) Fetch(method, path string, header http.Header, payload, result interface{}) error {
	url := joinURL(c.config.BaseURL, path)
	logVerbose("%s %s", method, url)

	var body io.Reader

	if payload != nil {
		if reader, ok := payload.(io.Reader); ok {
			body = reader
		} else {
			data, err := json.MarshalIndent(payload, "", "  ")
			if err != nil {
				return err
			}
			logVerbose("payload:\n: %v", string(data))
			body = bytes.NewReader(data)
		}
	}

	req, err := http.NewRequest(method, url, body)
	if err != nil {
		logVerbose("http.NewRequest() error: %v", err)
		return err
	}

	if header != nil {
		for k, v := range header {
			req.Header.Set(k, v[0])
		}
	}

	res, err := c.httpClient.Do(req)
	if err != nil {
		logVerbose("client.Do() error: %v", err)
		return err
	}

	defer res.Body.Close()

	data, err := ioutil.ReadAll(res.Body)
	if err != nil {
		logVerbose("ioutil.ReadAll() error: %v", err)
		return err
	}

	ok := res.StatusCode >= 200 && res.StatusCode <= 299
	if verbose || !ok {
		logVerbose("response %d:\n%v", res.StatusCode, indentedJSON(data))
	}

	if result != nil && ok {
		err = json.Unmarshal(data, result)

		if err != nil && verbose {
			logVerbose("json.Decode() error: %v", err)
			logVerbose("payload:\n%v", indentedJSON(data))
		}
	}

	if !ok && err == nil {
		err = errors.New("internal server error")
	}

	return err
}

func joinURL(a, b string) string {
	a = strings.TrimRight(a, "/")
	b = strings.TrimLeft(b, "/")
	return a + "/" + b
}

func indentedJSON(d []byte) string {
	var out map[string]interface{}
	err := json.Unmarshal(d, &out)
	if err != nil {
		return string(d)
	}
	b, err := json.MarshalIndent(out, "", "  ")
	if err != nil {
		return string(d)
	}
	return string(b)
}

var verbose = false

func SetVerbose(value bool) {
	verbose = value
}

type LogFunc func(message string)

var logger LogFunc = func(message string) {
	fmt.Println(message)
}

func SetLogger(fn LogFunc) {
	logger = fn
}

func logVerbose(format string, args ...interface{}) {
	if verbose {
		logger(fmt.Sprintf(format, args...))
	}
}
