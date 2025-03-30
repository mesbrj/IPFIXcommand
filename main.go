package main

/*
#cgo LDFLAGS: -L/home/mesb/libfixbuf-3.0.0.alpha2/src/.libs/ -lfixbuf
#cgo CFLAGS: -I/home/mesb/libfixbuf-3.0.0.alpha2/src/
#cgo LDFLAGS: -lglib-2.0
#cgo CFLAGS: -I/usr/include/glib-2.0


#include <stdbool.h>
#include <fixbuf/public.h>

#define FATAL(e)                                \
    { fprintf(stderr, "Failed at %s:%d: %s\n",  \
            __FILE__, __LINE__, e->message);    \
        exit(1); }

fbInfoElementSpec_t collectTemplate[] = {
    {"privateEnterpriseNumber",             4, 0 },
    {"informationElementId",                2, 0 },
    {"informationElementDataType",          1, 0 },
    {"informationElementSemantics",         1, 0 },
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
    uint32_t      privateEnterpriseNumber;
    uint16_t      informationElementId;
    uint8_t       informationElementDataType;
    uint8_t       informationElementSemantics;
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

void modelInit(char* cert_ipfix_registry) {
    model = fbInfoModelAlloc();
    if (!fbInfoModelReadXMLFile(model, cert_ipfix_registry, &err))
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

void freeMemory() {
    fBufFree(fbuf);
    fbInfoModelFree(model);
}

*/
import "C"
import (
	"fmt"

	"github.com/davecgh/go-spew/spew"
	"github.com/gdamore/tcell/v2"
	"github.com/rivo/tview"
)

func startFileCollector(ipfixFile, cert_ipfix_registry_xml string) {
	C.modelInit(C.CString(cert_ipfix_registry_xml))
	C.sessionInit()
	C.templateAlloc()
	C.collectorInit(C.CString(ipfixFile))
	C.collectRecordFillMemory()
}

func getAllRecordsAsText() string {
	str := ""
	record_count := 0
	ipfixCollectRecord := C.getCollectRecord()
	for C.nextRecord() {
		record_count++
		str += fmt.Sprintf(
			"\nIPFIX RECORD %d\n\n%s",
			record_count,
			spew.Sdump(ipfixCollectRecord))
	}
	return str
}

func main() {

	startFileCollector("wireshark_new.ipfix", "cert_ipfix.xml")
	defer C.freeMemory()

	app := tview.NewApplication()
	flex := tview.NewFlex().
		AddItem(tview.NewBox().SetBorder(true).SetTitle("Left (1/2 x width of Top)"), 0, 1, false).
		AddItem(tview.NewFlex().SetDirection(tview.FlexRow).
			AddItem(tview.NewBox().SetBorder(true).SetTitle("Top"), 0, 1, false).
			AddItem(tview.NewTextView().SetLabel("   IPFIX Records:   ").
				SetTextColor(tcell.ColorGreen).
				SetText(getAllRecordsAsText()), 0, 3, false).
			AddItem(tview.NewBox().SetBorder(true).SetTitle("Bottom (5 rows)"), 5, 1, false), 0, 2, false).
		AddItem(tview.NewBox().SetBorder(true).SetTitle("Right (20 cols)"), 20, 1, false)
	if err := app.SetRoot(flex, true).EnableMouse(true).SetFocus(flex).Run(); err != nil {
		panic(err)
	}

}
