#pragma once
#include <stdint.h>

extern "C" {
void DW_WeaponInspectInput_Init();
void DW_WeaponInspectInput_Frame();
// The weapon implementation must recheck player/weapon eligibility, including
// alive state, spectating, killcam, frontend scene and unsupported animations.
void DW_WeaponInspect_Request(uint32_t localClient);

int DW_WeaponInspectInput_Capture(void *vm);
int DW_WeaponInspectInput_Unbind(void *vm);
int DW_WeaponInspectInput_Reset(void *vm);
int DW_WeaponInspectInput_GetDefault(void *vm);
int DW_WeaponInspectInput_GetBound(void *vm);
bool DW_WeaponInspectInput_HandleKey(uint32_t localClient, uint32_t key);
}
