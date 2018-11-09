#include <stdlib.h>
#include "bt_device_mgr.h"

typedef struct BT_DEVICE_INFO_TAG
{
    int error_code;
    int dev_id;
    int socket;
} BT_DEVICE_INFO;

#define MAX_RESPONSE_VALUE      255

BT_DEVICE_HANDLE bt_device_create(void)
{
    BT_DEVICE_INFO* result;
    if ((result = malloc(sizeof(BT_DEVICE_INFO))) != NULL)
    {

    }
    return result;
}

void bt_device_destroy(BT_DEVICE_HANDLE handle)
{
    if (handle != NULL)
    {
        free(handle);
    }
}

void bt_device_process(BT_DEVICE_HANDLE handle)
{
    if (handle != NULL)
    {
    }
}
