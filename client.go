package rest

import (
	"bytes"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/ioutil"
	"net/http"
	"net/url"
	"strings"
	"time"
)

const (
	MimeJSON = "application/json"
	MimeXML  = "application/xml"
)

type RequestStat struct {
	RequestTime  time.Duration
	ResponseSize int
	StatusCode   int
	Error        error
}

// BasicAuth encodes credentials according to basic authentication scheme.
func BasicAuth(username, password string) string {
	// borrowed from net/http
	auth := username + ":" + password
	return base64.StdEncoding.EncodeToString([]byte(auth))
}

// MakeQueryString from given map.
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

// Config of the REST API client.
type Config struct {
	BaseURL     string
	Token       string
	TokenHeader string
	AuthScheme  string
	Timeout     int64
	CollectStat func(s *RequestStat)
}

// Client to REST API service.
type Client struct {
	config     *Config
	httpClient *http.Client
}

// NewClient creates new instance of REST API client with given config.
func NewClient(config Config) *Client {
	if config.Timeout <= 0 {
		config.Timeout = 30
	}
	if config.CollectStat == nil {
		config.CollectStat = func(s *RequestStat) {}
	}

	// TODO should be configurable
	transport := &http.Transport{
		TLSClientConfig: &tls.Config{
			InsecureSkipVerify: true, // ignore expired SSL certificates
		},
	}

	httpClient := &http.Client{
		Timeout:   time.Duration(config.Timeout * int64(time.Second)),
		Transport: transport,
	}

	return &Client{
		config:     &config,
		httpClient: httpClient,
	}
}

// Config returns current client configuration.
func (c *Client) Config() *Config {
	return c.config
}

// Download makes GET request to download raw bytes of given resource.
func (c *Client) Download(path string, accept string) ([]byte, error) {
	var result []byte
	err := c.Fetch("GET", path, c.makeHeader(accept), nil, &result)
	if err != nil {
		return nil, err
	}
	return result, nil
}

// Get makes GET request to given resource.
func (c *Client) Get(path string, result interface{}) error {
	return c.Fetch("GET", path, c.makeHeader(MimeJSON), nil, result)
}

// Post makes POST request to given resource.
func (c *Client) Post(path string, payload, result interface{}) error {
	return c.Fetch("POST", path, c.makeHeader(MimeJSON), payload, result)
}

// PostData makes POST request to upload given data.
func (c *Client) PostData(path, contentType string, data io.Reader, result interface{}) error {
	h := c.makeHeader(MimeJSON)
	h.Set("Content-Type", contentType)
	return c.Fetch("POST", path, h, data, result)
}

// Put makes PUT request to given resource.
func (c *Client) Put(path string, payload, result interface{}) error {
	return c.Fetch("PUT", path, c.makeHeader(MimeJSON), payload, result)
}

// Delete makes DELETE request to given resource.
func (c *Client) Delete(path string) error {
	return c.Fetch("DELETE", path, c.makeHeader(""), nil, nil)
}

func (c *Client) makeHeader(accept string) http.Header {
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

	if len(accept) > 0 {
		h.Set("Accept", accept)
	}

	return h
}

// Fetch makes HTTP request to given resource.
func (c *Client) Fetch(method, path string, header http.Header, payload, result interface{}) error {
	url := JoinURL(c.config.BaseURL, path)
	if verbose {
		log("%s %s", method, url)
	}

	var body io.Reader

	if payload != nil {
		if reader, ok := payload.(io.Reader); ok {
			body = reader
		} else {
			data, err := json.MarshalIndent(payload, "", "  ")
			if err != nil {
				log("json.MarshalIndent error: %v", err)
				return err
			}
			if verbose {
				log("payload:\n: %v", string(data))
			}
			body = bytes.NewReader(data)
		}
	}

	req, err := http.NewRequest(method, url, body)
	if err != nil {
		log("http.NewRequest error: %v", err)
		return err
	}

	if header != nil {
		for k, v := range header {
			req.Header.Set(k, v[0])
		}
	}

	start := time.Now()
	stat := &RequestStat{StatusCode: 500}

	res, err := c.httpClient.Do(req)
	if err != nil {
		stat.Error = err
		stat.RequestTime = time.Since(start)
		c.config.CollectStat(stat)
		log("client.Do error: %v", err)
		return err
	}

	defer res.Body.Close()

	data, err := ioutil.ReadAll(res.Body)
	if err != nil {
		stat.Error = err
		stat.RequestTime = time.Since(start)
		c.config.CollectStat(stat)
		log("ioutil.ReadAll error: %v", err)
		return err
	}

	stat.RequestTime = time.Since(start)
	stat.ResponseSize = len(data)
	stat.StatusCode = res.StatusCode
	c.config.CollectStat(stat)

	ok := res.StatusCode >= 200 && res.StatusCode <= 299
	if verbose || !ok {
		log("response %d:\n%v", res.StatusCode, indentedJSON(data))
	}

	if result != nil && ok {
		rawResult, ok := result.(*[]byte)
		if ok {
			*rawResult = data
		} else {
			err = json.Unmarshal(data, result)

			if err != nil {
				log("json.Decode error: %v", err)
				log("payload:\n%v", indentedJSON(data))
			}
		}
	}

	if !ok && err == nil {
		err = errors.New("internal server error")
	}

	return err
}

// JoinURL joins two pathes
func JoinURL(a, b string) string {
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

// SetVerbose enables/disabled verbose logging.
func SetVerbose(value bool) {
	verbose = value
}

// LogFunc defines logging func.
type LogFunc func(message string)

var logger LogFunc = func(message string) {
	fmt.Println(message)
}

// SetLogger allows to change default logger.
func SetLogger(fn LogFunc) {
	logger = fn
}

func log(format string, args ...interface{}) {
	logger(fmt.Sprintf(format, args...))
}
