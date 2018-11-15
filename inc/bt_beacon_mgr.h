
#ifndef BT_BEACON_MGR_H
#define BT_BEACON_MGR_H

#ifdef __cplusplus
#include <cstdint>
extern "C" {
#else
#include <stdint.h>
#endif /* __cplusplus */

typedef struct BT_BEACON_INFO_TAG* BT_BEACON_HANDLE;
typedef uint32_t bt_uuid_t;

typedef enum BEACON_SERVICE_TYPE_TAG
{
    BEACON_TYPE_iBEACON,
    BEACON_TYPE_ALTBEACON
} BEACON_SERVICE_TYPE;

typedef struct BEACON_DEVICE_INFO_TAG
{
    bt_uuid_t device_uuid;
    uint16_t major_num;
    uint16_t minor_num;
    uint8_t tx_power;
    uint8_t range_meters;
} BEACON_DEVICE_INFO;

typedef void(*BEACON_DEVICE_CALLBACK)(BEACON_DEVICE_INFO dev_info, void* user_ctx);

extern BT_BEACON_HANDLE bt_beacon_create(BEACON_SERVICE_TYPE type);
extern void bt_beacon_destroy(BT_BEACON_HANDLE handle);
extern void bt_beacon_process(BT_BEACON_HANDLE handle, BEACON_DEVICE_CALLBACK beacon_cb, void* user_ctx);

// ****** Scanner Functions ******
// iBeacon
extern bt_uuid_t bt_beacon_device_uuid(BT_BEACON_HANDLE handle);
extern uint16_t bt_beacon_major_number(BT_BEACON_HANDLE handle);
extern uint16_t bt_beacon_minor_number(BT_BEACON_HANDLE handle);
extern uint8_t bt_beacon_tx_power(BT_BEACON_HANDLE handle);

// Alt_Beacon
extern uint16_t bt_beacon_mfg_id(BT_BEACON_HANDLE handle);
extern uint16_t bt_beacon_code(BT_BEACON_HANDLE handle);
extern uint32_t bt_beacon_id(BT_BEACON_HANDLE handle);
extern uint8_t bt_beacon_rssi_value(BT_BEACON_HANDLE handle);

// ****** Advertiser Code ******
extern int bt_beacon_set_ibeacon_info(BT_BEACON_HANDLE handle, uint16_t major_num, uint16_t minor_num);
extern int bt_beacon_set_altbeacon_info(BT_BEACON_HANDLE handle, uint16_t mfg_id, uint16_t code, unsigned int rssi);
extern int bt_beacon_advertise_position(BT_BEACON_HANDLE handle);

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif // BT_BEACON_MGR