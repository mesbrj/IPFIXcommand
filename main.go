package main

/*
#cgo LDFLAGS: -L/usr/local/lib -lfixbuf
#cgo CFLAGS: -I/usr/local/include/fixbuf
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
    {"informationElementName",              0, 0 },
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
    fbVarfield_t  informationElementName;
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
	"unsafe"
)

func startFileCollector(ipfixFile, cert_ipfix_registry_xml string) {
	C.modelInit(C.CString(cert_ipfix_registry_xml))
	C.sessionInit()
	C.templateAlloc()
	C.collectorInit(C.CString(ipfixFile))
	C.collectRecordFillMemory()
}

func formatIPv4(ip uint32) string {
	// Bit shifting and masking to extract each octet
	return fmt.Sprintf("%d.%d.%d.%d",
		(ip>>24)&0xFF, (ip>>16)&0xFF, (ip>>8)&0xFF, ip&0xFF)
}

func analyzeRecordType(ipfixCollectRecord *C.collectRecord_st) (string, bool) {
	// RFC 5610 Information Element Type Record
	isInfoElement := (ipfixCollectRecord.privateEnterpriseNumber != 0 ||
		ipfixCollectRecord.informationElementId != 0 ||
		ipfixCollectRecord.informationElementDataType != 0)
	// Flow Record
	isFlowData := (ipfixCollectRecord.flowStartMilliseconds != 0 ||
		ipfixCollectRecord.flowEndMilliseconds != 0)

	if isInfoElement && !isFlowData {
		return "RFC_5610_INFO_ELEMENT", true
	} else if isFlowData && !isInfoElement {
		return "FLOW_DATA", true
	}
	return "EMPTY_OR_UNKNOWN", false
}

func getAllRecordsAsText() string {
	str := ""
	record_count := 0
	rfc5610_count := 0
	flow_data_count := 0
	unknown_count := 0

	ipfixCollectRecord := C.getCollectRecord()
	for C.nextRecord() {
		record_count++

		recordType, isKnown := analyzeRecordType(ipfixCollectRecord)

		switch recordType {
		case "RFC_5610_INFO_ELEMENT":
			rfc5610_count++
			str += fmt.Sprintf("\n RFC 5610 INFO ELEMENT RECORD %d:\n", rfc5610_count)
			// Convert fbVarfield_t to Go string
			nameLen := int(ipfixCollectRecord.informationElementName.len)
			var nameStr string
			if nameLen > 0 && ipfixCollectRecord.informationElementName.buf != nil {
				nameStr = C.GoStringN((*C.char)(unsafe.Pointer(ipfixCollectRecord.informationElementName.buf)), C.int(nameLen))
			} else {
				nameStr = "(no name)"
			}
			str += fmt.Sprintf("   Element Name: %s\n", nameStr)
			str += fmt.Sprintf("   Enterprise Number: %d\n", ipfixCollectRecord.privateEnterpriseNumber)
			str += fmt.Sprintf("   Element ID: %d\n", ipfixCollectRecord.informationElementId)
			str += fmt.Sprintf("   Data Type: %d\n", ipfixCollectRecord.informationElementDataType)
			str += fmt.Sprintf("   Semantics: %d\n", ipfixCollectRecord.informationElementSemantics)
		case "FLOW_DATA":
			flow_data_count++
			str += fmt.Sprintf("\n FLOW DATA RECORD %d:\n", flow_data_count)
			str += fmt.Sprintf("   Source IP: %s (%d)\n", formatIPv4(uint32(ipfixCollectRecord.sourceIPv4Address)), ipfixCollectRecord.sourceIPv4Address)
			str += fmt.Sprintf("   Dest IP: %s (%d)\n", formatIPv4(uint32(ipfixCollectRecord.destinationIPv4Address)), ipfixCollectRecord.destinationIPv4Address)
			str += fmt.Sprintf("   Source Port: %d\n", ipfixCollectRecord.sourceTransportPort)
			str += fmt.Sprintf("   Dest Port: %d\n", ipfixCollectRecord.destinationTransportPort)
			str += fmt.Sprintf("   Protocol: %d\n", ipfixCollectRecord.protocolIdentifier)
			str += fmt.Sprintf("   Packets: %d\n", ipfixCollectRecord.packetTotalCount)
			str += fmt.Sprintf("   Octets: %d\n", ipfixCollectRecord.octetTotalCount)
		default:
			if !isKnown {
				unknown_count++
			}
		}
	}

	str = str + fmt.Sprintf("\n SUMMARY:\n   RFC 5610 Records: %d\n   Flow Data Records: %d\n   Other/Unknown Records: %d\n   Total Records: %d\n",
		rfc5610_count, flow_data_count, unknown_count, record_count)

	return str
}

func main() {

	startFileCollector("sample_wireshark.ipfix", "cert_ipfix.xml")
	defer C.freeMemory()

	fmt.Println("IPFIX Records from file:")
	fmt.Println(getAllRecordsAsText())

}
