package main

/*
#cgo LDFLAGS: -L/home/mesb/libfixbuf-3.0.0.alpha2/src/.libs/ -lfixbuf
#cgo CFLAGS: -I/home/mesb/libfixbuf-3.0.0.alpha2/src/
#cgo LDFLAGS: -lglib-2.0
#cgo CFLAGS: -I/usr/include/glib-2.0

#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <stdbool.h>
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

void templateAlloc() {
    tmpl = fbTemplateAlloc(model);
    if (!fbTemplateAppendSpecArray(tmpl, collectTemplate, ~0, &err))
        FATAL(err);
    if (!(tid = fbSessionAddTemplate(
            session, TRUE, FB_TID_AUTO, tmpl, NULL, &err)))
        FATAL(err);
}

void collectorInit(char* filename) {
    IpfixFile = fopen(filename, "r");
    if (!IpfixFile) {
        perror("fopen");
        exit(1);
    }
    collector = fbCollectorAllocFP(NULL, IpfixFile);
    fbuf = fBufAllocForCollection(session, collector);
    if (!fBufSetInternalTemplate(fbuf, tid, &err))
        FATAL(err);
}

bool nextRecord() {
    reclen = sizeof(collectRecord);
    if (fBufNext(fbuf, (uint8_t *)&collectRecord, &reclen, &err))
        return true;
    else
        return false;
}

void processBuf() {
    reclen = sizeof(collectRecord);
    while (fBufNext(fbuf, (uint8_t *)&collectRecord, &reclen, &err)) {
        ldiv_t     dt;
        char       buf[256];
        size_t     sz;
        uint32_t   ip;
        dt = ldiv(collectRecord.flowStartMilliseconds, 1000);
        sz = strftime(buf, sizeof(buf), "%Y-%m-%d %H:%M:%S",
                      gmtime((time_t *)&dt.quot));
        snprintf(buf + sz, sizeof(buf) - sz, ".%.3ld", dt.rem);
        printf("Start time:   %s\n", buf);
        dt = ldiv(collectRecord.flowEndMilliseconds, 1000);
        sz = strftime(buf, sizeof(buf), "%Y-%m-%d %H:%M:%S",
                      gmtime((time_t *)&dt.quot));
        snprintf(buf + sz, sizeof(buf) - sz, ".%.3ld", dt.rem);
        printf("End time:     %s\n", buf);
        ip = collectRecord.sourceIPv4Address;
        printf("Source:       %d.%d.%d.%d:%d\n",
                (ip >> 24), (ip >> 16) & 0xff, (ip >> 8) & 0xff, ip & 0xff,
                collectRecord.sourceTransportPort);
        ip = collectRecord.destinationIPv4Address;
        printf("Destination:  %d.%d.%d.%d:%d\n",
                (ip >> 24), (ip >> 16) & 0xff, (ip >> 8) & 0xff, ip & 0xff,
                collectRecord.destinationTransportPort);
        printf("Protocol:     %d\n", collectRecord.protocolIdentifier);
        printf("Packets:      %" PRIu64 "\n", collectRecord.packetTotalCount);
        printf("Octets:       %" PRIu64 "\n", collectRecord.octetTotalCount);
        printf("Payload:     ");
        for (sz = 0; sz < collectRecord.payload.len; ++sz)
            printf(" %02x", collectRecord.payload.buf[sz]);
        printf("\n\n");
    }
}

void freeMemory() {
    fBufFree(fbuf);
    fbInfoModelFree(model);
}

*/
import "C"
import "github.com/davecgh/go-spew/spew"

func main() {

	C.collectRecordFillMemory()

	C.modelInit()
	C.sessionInit()
	C.templateAlloc()
	C.collectorInit(C.CString("wireshark_new.ipfix"))

	ipfixCollectRecord := C.getCollectRecord()
	spew.Dump(ipfixCollectRecord)
	C.nextRecord()
	spew.Dump(ipfixCollectRecord)

	C.processBuf()

	C.freeMemory()
}
