#include <stddef.h>
typedef struct g5120_endpoint g5120_endpoint;
g5120_endpoint *g5120_new(const unsigned char *psk, int client, int *error);
void g5120_free(g5120_endpoint *e);
int g5120_feed(g5120_endpoint *e, const unsigned char *p, size_t n);
int g5120_step(g5120_endpoint *e, unsigned char *p, size_t n);
int g5120_write(g5120_endpoint *e, const unsigned char *p, size_t n);
int g5120_drain(g5120_endpoint *e, unsigned char *p, size_t n);
int g5120_ready(g5120_endpoint *e);
int g5120_preflight(void);
const char *g5120_version(void);
