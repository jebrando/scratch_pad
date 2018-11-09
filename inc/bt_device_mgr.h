
#ifndef BT_DEVICE_MGR_H
#define BT_DEVICE_MGR_H

#ifdef __cplusplus
#include <cstdint>
extern "C" {
#else
#include <stdint.h>
#endif /* __cplusplus */

typedef struct BT_DEVICE_INFO_TAG* BT_DEVICE_HANDLE;

extern BT_DEVICE_HANDLE bt_device_create(void);
extern void bt_device_destroy(BT_DEVICE_HANDLE handle);
extern void bt_device_process(BT_DEVICE_HANDLE handle);

extern int bt_device_write(BT_DEVICE_HANDLE handle, const unsigned char* data, size_t length);

//extern BT_DEVICE_LIST_HANDLE bt_device_get_device_list(BT_DEVICE_HANDLE handle, const char* address);

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif // BT_DEVICE_MGR