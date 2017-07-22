/*
 * Here you may choose to disable any of the wrappers by uncommenting
 * the lines below.
 * This makes it possible to run the library on machines that do not have
 * the necessary files for running the wrappers.
 */


/**
 * Uncomment the line below to disable compiling with nDPI.
 */
// #define DISABLE_NDPI

/**
 * Uncomment the line below to disable compiling with libprotoident.
 */
// #define DISABLE_LPI

/**
 * Error code returned when initializing a disabled library.
 */
#define ERROR_LIBRARY_DISABLED -0x1000
