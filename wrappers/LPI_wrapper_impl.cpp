#ifndef LPI_WRAPPER_ONCE
#define LPI_WRAPPER_ONCE

#include "wrappers_config.h"
#ifndef DISABLE_LPI

#include <iostream>
#include <libprotoident.h>
#include <libprotoident.h>
#include <libtrace.h>

using namespace std;

extern "C"
int lpiInitLibrary() {
    // Initialize the library
    return lpi_init_library();
}

extern "C"
lpi_data_t *lpiCreateFlow() {
    // Create a new flow
    lpi_data_t *data = new lpi_data_t;
    lpi_init_data(data);
    return data;
}

extern "C"
void lpiFreeFlow(lpi_data_t *data) {
    // Free a flow
    delete data;
}

extern "C"
int lpiAddPacketToFlow(lpi_data_t *data, const void *pktData, unsigned short pktLen) {
    // Add the data of a packet to a flow
    int retVal;
    auto packet = trace_create_packet();

    trace_construct_packet(packet, TRACE_TYPE_ETH, pktData, pktLen);
    retVal = lpi_update_data(packet, data, 0);
    trace_destroy_packet(packet);

    return retVal;
}

extern "C"
int lpiGuessProtocol(lpi_data_t *data) {
    // Try to classify a flow
    auto mod = lpi_guess_protocol(data);
    return mod->protocol;
}

extern "C"
void lpiDestroyLibrary() {
    // Free the library
    lpi_free_library();
}

#else
// LPI is disabled, so initialization fails

typedef void lpi_data_t;

extern "C" int lpiInitLibrary() {
    return ERROR_LIBRARY_DISABLED;
}

extern "C" lpi_data_t *lpiCreateFlow() {
    return nullptr;
}

extern "C" void lpiFreeFlow(lpi_data_t*) {
}

extern "C" int lpiAddPacketToFlow(lpi_data_t*, const void*, unsigned short) {
    return -1;
}

extern "C" int lpiGuessProtocol(lpi_data_t*) {
    return -1;
}

extern "C" void lpiDestroyLibrary() {
}

#endif
#endif
