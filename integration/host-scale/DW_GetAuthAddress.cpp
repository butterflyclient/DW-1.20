// Retain the current DW startup fix in private host-scaling builds. The native
// caller asks for its address before its port, so both getters need ownership.
extern "C" const char *DW_LocalBackend_GetAuthAddress(const void *);

extern "C" const char *DW_GetAuthAddress(const void *configuration)
{
    return DW_LocalBackend_GetAuthAddress(configuration);
}
