package main

/*
#cgo LDFLAGS: -L/home/mesb/libfixbuf-3.0.0.alpha2/src/.libs/ -lfixbuf
#cgo CFLAGS: -I/home/mesb/libfixbuf-3.0.0.alpha2/src/
#cgo LDFLAGS: -lglib-2.0
#cgo CFLAGS: -I/usr/include/glib-2.0

#include <stdio.h>
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

typedef struct {
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
} collectRecord_st;

collectRecord_st collectRecord;

fbInfoModel_t   *model;
fbSession_t     *session;
fbCollector_t   *collector;
fbTemplate_t    *tmpl;
fBuf_t          *fbuf;
uint16_t         tid;
size_t           reclen;
FILE            *IpfixFile;
GError          *err = NULL;

void collectRecordFillMemory() {
    memset(&collectRecord, 0, sizeof(collectRecord));
}
collectRecord_st* getCollectRecord() {
    return &collectRecord;
}

void modelInit() {
    model = fbInfoModelAlloc();
    if (!fbInfoModelReadXMLFile(model, "/home/mesb/libfixbuf-3.0.0.alpha2/src/cert_ipfix.xml", &err))
        FATAL(err);
}

void sessionInit() {
    session = fbSessionAlloc(model);
}

void collectorInit(char* filename) {
    IpfixFile = fopen(filename, "r");
    if (!IpfixFile) {
        perror("fopen");
        exit(1);
    }
    collector = fbCollectorAllocFP(NULL, IpfixFile);
}




*/
import "C"

import (
	"github.com/davecgh/go-spew/spew"
)

func main() {

	C.collectRecordFillMemory()

	C.modelInit()
	C.sessionInit()
	C.collectorInit(C.CString("wireshark_new.ipfix"))

	collectRecord := C.getCollectRecord()
	spew.Dump(collectRecord)
}
