#include <stdlib.h>
#include "bt_device_discovery.h"


typedef struct BT_DEVICE_LIST_TAG
{
    int dev_id;
    size_t resp_count;
    void* device_list;

} BT_DEVICE_LIST;

#define MAX_RESPONSE_VALUE      128
#define TIMEOUT_VALUE           5

BT_DISCOVER_HANDLE bt_discover_create(const char* address, size_t max_response)
{
    BT_DEVICE_LIST* result;
    if ((result = (BT_DEVICE_LIST*)malloc(sizeof(BT_DEVICE_LIST))) == NULL)
    {
    }
    else
    {
    }
    return result;
}

void bt_discover_destroy(BT_DISCOVER_HANDLE handle)
{
    if (handle != NULL)
    {
        free(handle);
    }
}

size_t bt_dev_list_get_count(BT_DISCOVER_HANDLE handle)
{
    size_t result;
    if (handle == NULL)
    {
        result = 0;
    }
    else
    {
        result = handle->resp_count;
    }
    return result;
}

const char* bt_dev_list_get_device(BT_DISCOVER_HANDLE handle, size_t index)
{
    const char* result;
    if (handle == NULL)
    {
        result = NULL;
    }
    else if (index >= handle->resp_count)
    {
        result = NULL;
    }
    else
    {
        result = NULL;
    }
    return result;
}
