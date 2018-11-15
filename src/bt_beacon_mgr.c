#include <stdlib.h>
#include "bt_beacon_mgr.h"
#include "bt_device_mgr.h"

typedef struct BT_BEACON_INFO_TAG
{
    BT_DEVICE_HANDLE bt_device;
} BT_BEACON_INFO;

BT_BEACON_HANDLE bt_beacon_create(BEACON_SERVICE_TYPE type)
{
    BT_BEACON_INFO* result;
    if ((result = (BT_BEACON_INFO*)malloc(sizeof(BT_BEACON_INFO))) != NULL)
    {
        result->bt_device = bt_device_create();
        if (result->bt_device == NULL)
        {
            free(result);
            result = NULL;
        }
        else
        {
        }
    }
    return result;
}

void bt_beacon_destroy(BT_BEACON_HANDLE handle)
{
    if (handle != NULL)
    {
        bt_device_destroy(handle->bt_device);
        free(handle);
    }
}

void bt_beacon_process(BT_BEACON_HANDLE handle, BEACON_DEVICE_CALLBACK beacon_cb, void* user_ctx)
{
    if (handle != NULL)
    {
        bt_device_process(handle->bt_device);
    }
}
