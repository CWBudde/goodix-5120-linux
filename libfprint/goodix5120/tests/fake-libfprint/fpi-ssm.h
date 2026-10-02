#pragma once
#include "fpi-device.h"

typedef struct _FpiSsm FpiSsm;
typedef void (*FpiSsmHandlerCallback) (FpiSsm *, FpDevice *);
typedef void (*FpiSsmCompletedCallback) (FpiSsm *, FpDevice *, GError *);

#define fpi_ssm_new(dev, handler, states) fake_ssm_new (dev, handler, states, #states)
FpiSsm *fake_ssm_new (FpDevice *, FpiSsmHandlerCallback, int, const char *);
void fpi_ssm_start (FpiSsm *, FpiSsmCompletedCallback);
void fpi_ssm_start_subsm (FpiSsm *, FpiSsm *);
void fpi_ssm_next_state (FpiSsm *);
void fpi_ssm_jump_to_state (FpiSsm *, int);
void fpi_ssm_mark_completed (FpiSsm *);
void fpi_ssm_mark_failed (FpiSsm *, GError *);
int fpi_ssm_get_cur_state (FpiSsm *);
