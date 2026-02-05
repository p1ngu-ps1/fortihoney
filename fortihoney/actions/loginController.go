package actions

import (
	"encoding/json"
	"fmt"
	"fortihoney/models"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/gobuffalo/buffalo"
	"github.com/gobuffalo/pop"
)

type loginRequest struct {
	Ajax       string `form:"ajax" json:"ajax"`
	Username   string `form:"username" json:"username"`
	Realm      string `form:"realm" json:"realm"`
	Credential string `form:"credential" json:"credential"`
}

type ipAPIResponse struct {
	Status      string `json:"status"`
	Country     string `json:"country"`
	CountryCode string `json:"countryCode"`
	AS          string `json:"as"`
	Message     string `json:"message,omitempty"`
}

// Simple in-memory cache for geolocation results
var (
	geoCache      = make(map[string]*ipAPIResponse)
	geoCacheMutex sync.RWMutex
)

func createLog(log *models.Log) error {

	connect, err := pop.Connect("development")

	if err != nil {
		return err
	}

	return connect.Create(log)
}

func getRealIP(c buffalo.Context) string {
	xRealIP := c.Request().Header.Get("X-Real-IP")
	if xRealIP != "" {
		return xRealIP
	}

	remoteAddr := c.Request().RemoteAddr
	if ip, _, err := net.SplitHostPort(remoteAddr); err == nil {
		return ip
	}

	return strings.Split(c.Request().RemoteAddr, ":")[0]
}

func getGeoData(ipv4 string) (*ipAPIResponse, error) {
	// Check cache first
	geoCacheMutex.RLock()
	if cached, exists := geoCache[ipv4]; exists {
		geoCacheMutex.RUnlock()
		return cached, nil
	}
	geoCacheMutex.RUnlock()

	// Create HTTP client with timeout
	client := &http.Client{
		Timeout: 5 * time.Second,
	}

	// Make API request
	url := fmt.Sprintf("http://ip-api.com/json/%s?fields=status,country,countryCode,as", ipv4)
	resp, err := client.Get(url)
	if err != nil {
		return nil, fmt.Errorf("api request failed: %w", err)
	}
	defer resp.Body.Close()

	// Parse JSON response
	var result ipAPIResponse
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, fmt.Errorf("failed to parse response: %w", err)
	}

	// Check API status
	if result.Status != "success" {
		return nil, fmt.Errorf("api error: %s", result.Message)
	}

	// Cache the result
	geoCacheMutex.Lock()
	geoCache[ipv4] = &result
	geoCacheMutex.Unlock()

	return &result, nil
}

func getCountryByIP(ipv4 string) (string, error) {
	data, err := getGeoData(ipv4)
	if err != nil {
		return "--", err
	}
	return data.CountryCode, nil
}

func debugRequest(log *models.Log) {
	if ENV != "production" {
		fmt.Printf("~~~~~~~~~~~~~~~~~")
		fmt.Printf("\n [+] USERNAME: %s", log.Username)
		fmt.Printf("\n [+] PASSWORD: %s", log.Password)
		fmt.Printf("\n [+] UAGENT: %s", log.BrowserAgent)
		fmt.Printf("\n [+] IPV4: %s", log.IPv4)
		fmt.Printf("\n [+] Country: %s", log.Country)
		fmt.Printf("\n [+] AS: %s", log.AS)
		fmt.Printf("\n~~~~~~~~~~~~~~~~\n")
	}
}

func loginViewHandler(c buffalo.Context) error {
	c.Set("title", "Please Login")
	return c.Render(http.StatusOK, r.HTML("views/login.plush.html"))
}

func loginUserCheckHandler(c buffalo.Context) error {

	request := &loginRequest{}
	err := c.Bind(request)

	if err != nil {
		return err
	}

	ipv4 := getRealIP(c)
	geoData, err := getGeoData(ipv4)

	// Default values for degraded mode
	country := "--"
	asNumber := "--"

	if err != nil {
		fmt.Printf("\n [-] GeoIP API error: %s \n", err)
	} else {
		country = geoData.CountryCode
		asNumber = geoData.AS
	}

	log := &models.Log{
		Username:     request.Username,
		Password:     request.Credential,
		IPv4:         ipv4,
		Country:      country,
		AS:           asNumber,
		BrowserAgent: c.Request().Header.Get("User-Agent"),
	}

	debugRequest(log)
	err = createLog(log)

	if err != nil {
		return err
	}

	c.Flash().Add("error", "Error: Permission denied.")

	return c.Render(http.StatusTemporaryRedirect, r.HTML("views/login.plush.html"))
}
