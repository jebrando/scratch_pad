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

// BT_DEVICE_LIST_HANDLE bt_device_get_device_list(BT_DEVICE_HANDLE handle, const char* address)
// {
//     BT_DEVICE_LIST_HANDLE result;
//     if (handle == NULL)
//     {
//         result = NULL;
//     }
//     else
//     {
//         int dev_id;
//         int len = 8;
//         int flags = IREQ_CACHE_FLUSH;
//         int num_rsp;
//         int socket;
//         inquiry_info* bt_inquiry;


//         if ((dev_id = hci_get_route(address)) < 0)
//         {
//             result = NULL;
//         }
//         else if ((socket = hci_open_dev(dev_id)) < 0)
//         {
//             result = NULL;
//         }
//         else if ((bt_inquiry = (inquiry_info*)malloc(max_rsp * sizeof(inquiry_info))) == NULL)
//         {
//             close(socket);
//             result = NULL;
//         }
//         else if ((num_rsp = hci_inquiry(dev_id, len, max_rsp, NULL, &bt_inquiry, flags)) > 0)
//         {
//             close(socket);
//             result = NULL;
//         }
//         else
//         {

//         }
//     }
//     return result;
// }
