package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/buger/jsonparser"
	"github.com/fatih/color"
	"github.com/go-ini/ini"
)

/* ---------------------------------------------------------------------------------------- */
// Authentication header used for POST call to fetch token and tenant_id
// Need to create json object: {"auth": {"tenantName": "xxx", "passwordCredentials": {"username": "xxx", "password": "xxx"}}}
type AuthHeader struct {
	Auth struct {
		TenantName          string `json:"tenantName"`
		PasswordCredentials struct {
			Username string `json:"username"`
			Password string `json:"password"`
		} `json:"passwordCredentials"`
	} `json:"auth"`
}

/* ---------------------------------------------------------------------------------------- */

/*
 * Type Query holds everything needed to make a query
 * TODO: Right now method isn't used since only GET in use
 */
type Query struct {
	url, method    string
	region, tenant string // Names, not ID
	tenant_id      string
	service_id     string
	service_desc   string // Description, not ID
}

/*
 * Type QueryResult holds returned status & message from a query
 * Should also hold a reference to the original Query object
 * We don't include token because it's ephemeral
 * TODO: Right now status is a string, stores both HTTP status + message
 *       Make status an integer (or new type) and message separately?
 */
type QueryResult struct {
	status, message string
	query           *Query
}

// Generic function to check for any errors
func checkErr(e error) {
	if e != nil {
		panic(e)
		return
	}
}

/*
 * Singleton access to config file by loading only once
 * Avoids repeatedly opening/accessing file each time, and
 * potentially by multiple goroutines
 */
var g_CFG *ini.File // Ideally this should be const... but then can't assign
var once sync.Once

func get_config_file() *ini.File {
	once.Do(func() {
		cfg, err := ini.Load("config.ini") // TODO: Non-hardcoded filename
		if err != nil {
			fmt.Printf("ERROR: Unable to load configuration file %s\n", "config.ini")
			panic(err)
		}
		g_CFG = cfg
	})

	return g_CFG
}

// Generic function that reads the config.ini file for certain key and returns the value
func get_config_val(key string) string {

	config := get_config_file()

	// Load section
	sec, err := config.GetSection("config")
	checkErr(err)

	// Get key under "config" section
	value, err := sec.GetKey(key)
	checkErr(err)

	return value.String()
}

// Like get_config_val() but returns keys that hold comma-separated list of values
// e.g. If config file has: MYKEY = val-1, val-2, val-3
//      This function would return array of strings: ["val-1", "val-2", "val-3"]
func get_config_list(key string) []string {
	config := get_config_file()

	// Load section
	sec, err := config.GetSection("config")
	checkErr(err)

	// Get key under "config" section
	value, err := sec.GetKey(key)
	checkErr(err)

	return value.Strings(",")
}

// Function to fetch Token and Tenant ID given admin auth information
// Returns token and tenant_id
func get_token(tenant string) (token string, tenant_id string) {

	// Load config variables
	var USER_NAME = get_config_val("USER_NAME")
	var PASSWORD = get_config_val("PASSWORD")
	var KEYSTONE_GET_TOKEN_URL = get_config_val("KEYSTONE_GET_TOKEN_URL")

	// Create Auth Body for CURL request
	auth := AuthHeader{}
	auth.Auth.TenantName = tenant
	auth.Auth.PasswordCredentials.Username = USER_NAME
	auth.Auth.PasswordCredentials.Password = PASSWORD

	// Convert it into bytes
	auth_bytes := new(bytes.Buffer)
	json.NewEncoder(auth_bytes).Encode(auth)

	// Make the POST call
	resp, err := http.Post(KEYSTONE_GET_TOKEN_URL, "application/json", auth_bytes)
	checkErr(err)
	defer resp.Body.Close()

	// Store it as string
	body, err := ioutil.ReadAll(resp.Body)
	checkErr(err)

	// Get token
	token, err = jsonparser.GetString(body, "access", "token", "id")
	checkErr(err)

	// Get Tenant ID
	tenant_id, err = jsonparser.GetString(body, "access", "token", "tenant", "id")
	checkErr(err)

	return token, tenant_id
}

//Function that executes a GET REST call to a given URL
//The last paramter (url_type) is to differentiate between fetching lists/services and getting status of url
//We perform this in order to handle errors differently for these scenarios
//Returns: response and it's status (i.e. 200, 500 etc.)
func get_request(url string, token string, url_type string) ([]byte, string) {

	client := &http.Client{
		Timeout: 2 * time.Second, // Cause I don't have the patience
	}

	req, err := http.NewRequest("GET", url, nil)
	checkErr(err)

	req.Header.Add("X-Auth-Token", token)
	resp, err := client.Do(req)

	//If the request was to fetch endpoint list or service list, check for errors
	if url_type == "list" {
		checkErr(err)
	} else {
		// Handle error differently for this case.
		// You don't want to panic and shutdown for a connection timeout
		if err != nil {
			var err_string string

			if strings.Contains(err.Error(), "connection refused") {
				err_string = "500: Connection Refused"
			} else if strings.Contains(err.Error(), "Timeout") {
				err_string = "500: Connection Timeout"
			} else {
				err_string = "500: " + err.Error()
			}

			return nil, err_string
		}
	}

	defer resp.Body.Close()

	// Read the response
	resp_body, _ := ioutil.ReadAll(resp.Body)

	return resp_body, resp.Status
}

// Function that executes an HTTP call to a given URL
// Receives output channel in parameters, used to send results of queries
func service_status(query Query, token string, chOut chan QueryResult) {

	//Load config variables
	var COMPUTE_PORT = get_config_val("COMPUTE_PORT")

	// replace the variables in the url with appropriate values
	replace_vals := strings.NewReplacer("$(tenant_id)s", query.tenant_id,
		"%(tenant_id)s", query.tenant_id,
		"$(project_id)s", query.tenant_id,
		"%(project_id)s", query.tenant_id,
		"$(compute_port)s", COMPUTE_PORT)
	query.url = replace_vals.Replace(query.url)

	// Make the call
	_, status := get_request(query.url, token, "status")

	var result QueryResult
	result.query = &query
	result.status = status

	chOut <- result
}

/*
	Function that makes a map (or hash table) of the service_id and it's description.
	Ex: of keystone service-list

	|	SERVICE_ID							|	NAME				|	TYPE		|	DESCRIPTION			|
	|	722966fd1ed04a0d8769ee151ab781dc	|	ceilometer			|	metering	|	Ceilometer Service	|

	For each row, this function maps the id and the description such that:
	service_map[722...dc] = "Ceilometer Service"

	The whole point is that we can use this map's key (i.e. service_id) to match the id (returned from
	endpoint-list and get the description for that specific endpoint

	Ex. of endpoint-list output:
	|	...	|	REGION		|	PUBLICURL								|	...	|	...	|	SERVICE_ID							|
	|	...	|	EDGE-VC-1	|	http://vc-edge-1.savitestbed.ca:8777 	|	...	|	...	|	722966fd1ed04a0d8769ee151ab781dc	|

	In the end, we can get the description of that specific endpoint url
*/
func get_service_map(services []byte) map[string]string {

	// Initialize the string map
	service_map := make(map[string]string)

	// Loop through each row of the service-list output
	jsonparser.ArrayEach(services, func(value []byte, dataType jsonparser.ValueType, offset int, err error) {

		// Get the service_id
		service_id, err := jsonparser.GetString(value, "id")
		checkErr(err)

		// Get the service description
		service_description, err := jsonparser.GetString(value, "description")
		checkErr(err)

		// Create entry in map
		service_map[service_id] = service_description

	}, "services")

	return service_map
}

/*
 * Sort endpoints by region and filtering by the list in .ini file
 * Returns map w/ region name as key, and an array of endpoint info as values
 * Each endpoint info is a JSON formatted []byte array:
 *   - e.g. {
 *            "publicurl": "http://test-edge-1.savitestbed.ca:9696/",
 *            "id": "b1c11fdeh3344z72aaf02d0d2a3c238e",
 *            "enabled": true,
 *            "region": "EDGE-TEST-1",
 *            "service_id": "c3z76a9602274w4182117db5e9z458t5",
 *            "adminurl": "http://99.99.99.10:9696/",
 *            "internalurl": "http://99.99.99.10:9696/"
 *          }
 */
func get_regional_endpoints(endpoints []byte, in_regions map[string]bool) map[string][][]byte {
	var REGIONS = get_config_list("REGIONS")

	var regional_endpoints = make(map[string][][]byte)
	for _, reg := range REGIONS {
		regional_endpoints[reg] = make([][]byte, 0) // Length/Cap of 0, append will extend it
	}

	jsonparser.ArrayEach(endpoints, func(value []byte, dataType jsonparser.ValueType, offset int, err error) {
		// Get the region
		region, err := jsonparser.GetString(value, "region")
		checkErr(err)

		if !in_regions[region] {
			// Skip over this region
			return
		}

		regional_endpoints[region] = append(regional_endpoints[region], value)
	}, "endpoints")

	return regional_endpoints
}

//Execute REST API
//Prints output on std.out
func execute_code(tenant string) {

	//Load config values
	var KEYSTONE_GET_ENDPOINT_URL = get_config_val("KEYSTONE_GET_ENDPOINT_URL")
	var KEYSTONE_GET_SERVICE_URL = get_config_val("KEYSTONE_GET_SERVICE_URL")
	var REGIONS = get_config_list("REGIONS")

	// Construct map object for list of regions, enables quick membership check
	var inRegionsList = make(map[string]bool)
	for _, reg := range REGIONS {
		inRegionsList[reg] = true
	}

	// Get token and tenant_id, given the tenant name
	token, tenant_id := get_token(tenant)

	// Get output of keystone endpoint-list. Don't care about the status of this call
	endpoints, _ := get_request(KEYSTONE_GET_ENDPOINT_URL, token, "list")

	// Re-order and filter endpoints
	reg_endpoints_map := get_regional_endpoints(endpoints, inRegionsList)

	// Get output of keystone service-list. Don't care about the status of this call
	services, _ := get_request(KEYSTONE_GET_SERVICE_URL, token, "list")

	// Create the service map
	services_map := get_service_map(services)

	// For each region, loop through each endpoint entry
	var results_chan = make(chan QueryResult)
	var num_queries = 0
	for _, reg := range REGIONS {
		var regional_endpoints = reg_endpoints_map[reg]

		for _, endpoint := range regional_endpoints {
			// Get the publicurl
			url, err := jsonparser.GetString(endpoint, "url")
			checkErr(err)

			// Get it's service_id
			service_id, err := jsonparser.GetString(endpoint, "service_id")
			checkErr(err)

			var query Query
			query.url = url
			query.region = reg
			query.tenant = tenant
			query.tenant_id = tenant_id
			query.service_id = service_id
			query.service_desc = services_map[service_id]

			// Run each query in separate goroutine
			go service_status(query, token, results_chan)
			num_queries++
		}
	}

	// Ensure program doesn't hang if a query goroutine dies or takes too long
	// Close channel after 3 second timeout
	go func() {
		time.Sleep(3 * time.Second)
		close(results_chan)
	}()

	// Print Header
	header := color.New(color.Bold, color.Underline)
	header.Printf("%10s | %12s | %-35s | %-26s | %-90s \n",
		"TENANT", "REGION", "SERVICE DESCRIPTION", "STATUS", "ENDPOINT URL")

	var query *Query
	for i := 0; i < num_queries; i++ {
		result, ok := <-results_chan
		if !ok {
			// Channel closed
			return
		}

		query = result.query

		// Colourize status
		// NOTE: Colours add 9 characters with no width
		//       See width difference in header and data Printf's
		if strings.HasPrefix(result.status, "2") {
			result.status = color.GreenString(result.status)
		} else {
			result.status = color.MagentaString(result.status)
		}

		fmt.Printf("%10s | %12s | %-35s | %-35s | %-90s \n",
			query.tenant, query.region, query.service_desc, result.status, query.url)
	}

	return
}

func main() {

	//Load config variable and split the string into a List (Delimiter: ",")
	TENANTS := strings.Split(get_config_val("TENANTS"), ",")

	for _, element := range TENANTS {
		execute_code(element)
	}
}
