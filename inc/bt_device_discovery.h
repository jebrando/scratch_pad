
#ifndef BT_DEVICE_DISCOVERY_H
#define BT_DEVICE_DISCOVERY_H

#ifdef __cplusplus
#include <cstdint>
#include <cstdlib>
extern "C" {
#else
#include <stdint.h>
#include <stdlib.h>
#include <stdbool.h>
#endif /* __cplusplus */

typedef struct BT_DEVICE_LIST_TAG* BT_DISCOVER_HANDLE;

extern BT_DISCOVER_HANDLE bt_discover_create(const char* address, size_t max_response);
extern void bt_discover_destroy(BT_DISCOVER_HANDLE handle);

extern size_t bt_discover_scan(BT_DISCOVER_HANDLE handle, bool include_advert);
extern size_t bt_dev_list_get_count(BT_DISCOVER_HANDLE handle);
extern const char* bt_dev_list_get_device(BT_DISCOVER_HANDLE handle, size_t index);

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif // BT_DEVICE_DISCOVERY_H