#include <pcap.h>
#ifndef DISABLE_NDPI
#include <libndpi-2.0.0/libndpi/ndpi_main.h>
#endif

extern int ndpiInitialize();
extern void ndpiDestroy(void);
extern int ndpiPacketProcess(const struct pcap_pkthdr*, const u_char*);
