typedef void lpi_data_t;

#ifdef __cplusplus
extern "C" {
#endif
int lpiInitLibrary();
lpi_data_t *lpiCreateFlow();
void lpiFreeFlow(lpi_data_t*);
int lpiAddPacketToFlow(lpi_data_t*, const void*, unsigned short);
int lpiGuessProtocol(lpi_data_t*);
void lpiDestroyLibrary();
#ifdef __cplusplus
}
#endif
