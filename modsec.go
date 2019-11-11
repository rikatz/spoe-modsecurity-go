package main

// #cgo CFLAGS: -g -Wall
// #cgo LDFLAGS: -lmodsecurity
// #include <stdlib.h>
// #include "old/greeter.h"
// #include <modsecurity/modsecurity.h>
// #include <modsecurity/rules.h>
// #include <modsecurity/transaction.h>
import "C"

import (
	"log"
	"unsafe"
)

func main() {
	
	var err *C.char
	defer C.free(unsafe.Pointer(err))

	modsec := C.msc_init();
	defer C.free(unsafe.Pointer(modsec))

	conninfo := C.CString("ModSecurity-test v0.0.1-alpha (Simple example on how to use ModSecurity API")
	defer C.free(unsafe.Pointer(conninfo))
	C.msc_set_connector_info(modsec, conninfo);

	ruleURI := C.CString("basic_rules.conf")
	defer C.free(unsafe.Pointer(ruleURI))

	rules := C.msc_create_rules_set();
	defer C.free(unsafe.Pointer(rules))


	ret := C.msc_rules_add_file(rules, ruleURI, &err);
	if int(ret) < 0 {
		log.Fatalf(C.GoString(err))
	}

	C.msc_rules_dump(rules);


	transaction := C.msc_new_transaction(modsec, rules, nil);

	ret = C.msc_process_connection(transaction, C.CString("127.0.0.1"), 12345, C.CString("127.0.0.1"), 80);
	if ret < 1 {
		log.Fatalf("Error processing conection: %d", int(ret))
	}
	
	ret = C.msc_process_uri(transaction, C.CString("http://localhost/?param='><script>alert(1);</script>'"), C.CString("GET"), C.CString("1.1"));
	//log.Fatalf("Error processing conection: %d", int(ret))
	
	//msc_add_request_header(transaction, "User-Agent", "Basic ModSecurity example");
    //msc_process_request_headers(transaction);
    //msc_process_request_body(transaction);
    //msc_add_response_header(transaction, "Content-type", "text/html");
    //msc_process_response_headers(transaction, 200, "HTTP 1.0");
    //msc_process_response_body(transaction);
    //msc_process_logging(transaction);
	//msc_transaction_cleanup(transaction);

/*
	year := C.int(2018)

	ptr := C.malloc(C.sizeof_char * 1024)
	defer C.free(unsafe.Pointer(ptr))

	size := C.greet(name, year, (*C.char)(ptr))

	b := C.GoBytes(ptr, size)
	fmt.Println(string(b))
	*/
}