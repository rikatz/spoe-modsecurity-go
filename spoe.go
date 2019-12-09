package main

import (
	"log"
	"net"
	"os"
	"unsafe"

	"github.com/negasus/haproxy-spoe-go/action"
	"github.com/negasus/haproxy-spoe-go/agent"
	"github.com/negasus/haproxy-spoe-go/request"
)

/*
#cgo CFLAGS: -g -Wall
#cgo LDFLAGS: -lmodsecurity
#include <stdlib.h>
#include <modsecurity/modsecurity.h>
#include <modsecurity/rules.h>
#include <modsecurity/transaction.h>
#include <modsecurity/intervention.h>

int checkTransaction(Transaction *transaction) {

	ModSecurityIntervention intervention;
	intervention.status = 200;
    intervention.url = NULL;
    intervention.log = NULL;
	intervention.disruptive = 0;

	if (msc_intervention(transaction, &intervention) == 0) {
        fprintf(stderr, "No intervention required!\n");
        return 0;
    } else {
			fprintf(stderr, "We should intervene...!\n");
			return 1;
    }
    return 0;
}

*/
import "C"

func main() {

	log.Print("listen 9000")

	listener, err := net.Listen("tcp4", "172.16.224.1:9000")
	if err != nil {
		log.Printf("error create listener, %v", err)
		os.Exit(1)
	}
	defer listener.Close()

	a := agent.New(handler)

	if err := a.Serve(listener); err != nil {
		log.Printf("error agent serve: %+v\n", err)
	}
}

// TODO: This should be a better loop, a for inside another for is pretty ugly
func decodeHeaders(bytesIn []uint8) (headers map[string]string) {

	res := make(map[string]string)
	offset := 0
	var keylen, vallen int
	var keystr, valstr string

	for offset < len(bytesIn)-2 {
		// Whats the LEN of the Key Value. Example: the key 'host' has 4 chars
		keylen = int(bytesIn[offset])
		vallen = 0
		keystr, valstr = "", ""

		// Add +1 for the next field
		offset++

		// Example: Keyfinish = 5 (1 + 4)
		keyfinish := offset + keylen

		//    1         5
		for offset < keyfinish {
			char := rune(int(bytesIn[offset]))
			keystr += string(char)
			offset++
		}

		// Example: 172.16.224.111 has 14 characters
		vallen = int(bytesIn[offset])
		// Add +1 for next field (in the example, it's going to be 6)
		offset++

		// Example: valfinish = 6 + 14
		valfinish := offset + vallen

		for offset < valfinish {
			char := rune(int(bytesIn[offset]))
			valstr += string(char)
			offset++
		}
		// And the next offset would be 20 and the loop moves on
		res[keystr] = valstr
	}

	return res
}

func handler(req *request.Request) {

	log.Printf("handle request EngineID: '%s', StreamID: '%d', FrameID: '%d' with %d messages\n", req.EngineID, req.StreamID, req.FrameID, req.Messages.Len())

	messageName := "modsecurity"

	mes, err := req.Messages.GetByName(messageName)
	if err != nil {
		log.Printf("message %s not found: %v", messageName, err)
		return
	}

	ipValue, ok := mes.KV.Get("ip")
	if !ok {
		log.Printf("IP field not found")
		return
	}
	ip, ok := ipValue.(net.IP)
	if !ok {
		log.Printf("var 'ip' has wrong type. expect IP addr")
		return
	}

	method, ok := mes.KV.Get("method")
	if !ok {
		log.Printf("Method field not found")
		return
	}

	log.Printf("METHOD: %s", method)
	// unique-id method path query req.ver req.hdrs_bin req.body_size req.body

	path, ok := mes.KV.Get("path")
	if !ok {
		log.Printf("Path field not found")
		return
	}
	log.Printf("path: %s", path)

	query, ok := mes.KV.Get("query")
	if !ok {
		log.Printf("Query field not found")
		return
	}

	log.Printf("query: %s", query)

	reqver, ok := mes.KV.Get("reqver")
	if !ok {
		log.Printf("Reqver field not found")
		return
	}

	log.Printf("reqver: %s", reqver)

	reqhdrs, ok := mes.KV.Get("reqhdrs")
	if !ok {
		log.Printf("Reqhdrs field not found")
		return
	}

	headers := decodeHeaders(reqhdrs.([]uint8))

	log.Println("map:", headers)

	// Initializing ModSecurity with the Agent
	// TODO: Shouldn't this be added into the main function to not keep reloading ModSecurity?
	var errC *C.char
	defer C.free(unsafe.Pointer(errC))

	modsec := C.msc_init()
	defer C.free(unsafe.Pointer(modsec))

	conninfo := C.CString("ModSecurity-test v0.0.1-alpha (Simple example on how to use ModSecurity API")
	defer C.free(unsafe.Pointer(conninfo))
	C.msc_set_connector_info(modsec, conninfo)

	ruleURI := C.CString("basic_rules.conf")
	defer C.free(unsafe.Pointer(ruleURI))

	rules := C.msc_create_rules_set()
	defer C.free(unsafe.Pointer(rules))

	ret := C.msc_rules_add_file(rules, ruleURI, &errC)
	if int(ret) < 0 {
		log.Fatalf(C.GoString(errC))
	}

	var transaction *C.Transaction
	defer C.free(unsafe.Pointer(transaction))

	transaction = C.msc_new_transaction(modsec, rules, nil)

	ret = C.msc_process_connection(transaction, C.CString(ip.String()), 12345, C.CString("127.0.0.1"), 80)
	if ret < 1 {
		log.Fatalf("Error processing conection: %d", int(ret))
	}

	C.msc_process_uri(transaction, C.CString("http://www.modsecurity.org/../etc/passwd"), C.CString(method.(string)), C.CString(reqver.(string)))

	//TODO: How to convert String to C uchar??
	/*for k, v := range headers {
		C.msc_add_request_header(transaction, C.CString([]uint8(k)), C.CString([]uint8(v)))
	}*/

	ret = C.checkTransaction(transaction)

	log.Printf("Intervetion: %d", int(ret))
	req.Actions.SetVar(action.ScopeSession, "ip_score", 1)

}
