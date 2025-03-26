package main

/*
#cgo CFLAGS: -I/usr/include/glib-2.0
#include <stdint.h>
#include <string.h>
#include <fixbuf/public.h>
#define FATAL(e)                                \
    { fprintf(stderr, "Failed at %s:%d: %s\n",  \
            __FILE__, __LINE__, e->message);    \
        exit(1); }

fbInfoElementSpec_t collectTemplate[] = {
    {"flowStartMilliseconds",               8, 0 },
    {"flowEndMilliseconds",                 8, 0 },
    {"sourceIPv4Address",                   4, 0 },
    {"destinationIPv4Address",              4, 0 },
    {"sourceTransportPort",                 2, 0 },
    {"destinationTransportPort",            2, 0 },
    {"protocolIdentifier",                  1, 0 },
    {"paddingOctets",                       3, 0 },
    {"packetTotalCount",                    8, 0 },
    {"octetTotalCount",                     8, 0 },
    {"ipPayloadPacketSection",              0, 0 },
    FB_IESPEC_NULL
};
struct collectRecord_st {
    uint64_t      flowStartMilliseconds;
    uint64_t      flowEndMilliseconds;
    uint32_t      sourceIPv4Address;
    uint32_t      destinationIPv4Address;
    uint16_t      sourceTransportPort;
    uint16_t      destinationTransportPort;
    uint8_t       protocolIdentifier;
    uint8_t       padding[3];
    uint64_t      packetTotalCount;
    uint64_t      octetTotalCount;
    fbVarfield_t  payload;
} collectRecord;

fbInfoModel_t *mymodel; // Declare mymodel

fbCollector_t   *collector;
fbTemplate_t    *tmpl;
fBuf_t          *fbuf;
uint16_t         tid;
size_t           reclen;
GError          *err = NULL;
*/
import "C"
import (
	"fmt"
	"unsafe"
)

func main() {

	fmt.Println("Hello, Wor3tld!")

	C.memset(unsafe.Pointer(&C.collectRecord), 0, C.size_t(unsafe.Sizeof(C.collectRecord)))

}
