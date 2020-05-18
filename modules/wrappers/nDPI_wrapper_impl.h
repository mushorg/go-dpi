#include <pcap.h>
#ifndef DISABLE_NDPI
#include <ndpi/ndpi_main.h>
#endif

extern int ndpiInitialize();
extern void ndpiDestroy(void);
extern int ndpiPacketProcess(const struct pcap_pkthdr*, const u_char*, void*);
extern void *ndpiGetFlow(const struct pcap_pkthdr*, const u_char*);
extern void ndpiFreeFlow(void*);
