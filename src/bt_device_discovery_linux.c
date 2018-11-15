#include <stdlib.h>
#include "bt_device_discovery.h"

#include <bluetooth/bluetooth.h>
#include <bluetooth/hci.h>
#include <bluetooth/hci_lib.h>
#include <unistd.h>
#include <inttypes.h>
#include "azure_c_shared_utility/singlylinkedlist.h"

typedef struct BT_DEVICE_LIST_TAG
{
    int dev_id;
    size_t resp_count;
    void* device_list;
    SINGLYLINKEDLIST_HANDLE list_handle;
} BT_DEVICE_LIST;

#define MAX_RESPONSE_VALUE      128
#define TIMEOUT_VALUE           5

BT_DISCOVER_HANDLE bt_discover_create(const char* address, size_t max_response)
{
    BT_DEVICE_LIST* result;
    if ((result = (BT_DEVICE_LIST*)malloc(sizeof(BT_DEVICE_LIST))) != NULL)
    {
        int len = 8;
        int socket;
        bdaddr_t convert_addr;
        bdaddr_t* route_addr = NULL;
        if (address != NULL)
        {
            // Convert the address into a bdaddr_t value
            str2ba(address, &convert_addr);
            route_addr = &convert_addr;
        }

        if ((result->dev_id = hci_get_route(route_addr)) < 0)
        {
            free(result);
            result = NULL;
        }
        else if ((socket = hci_open_dev(result->dev_id)) < 0)
        {
            free(result);
            result = NULL;
        }
        // Setup the scan parameters
        else if (hci_le_set_scan_parameters(socket, 0x01, htobs(0x0010), htobs(0x0010), 0x00, 0x00, 1000) < 0)
        {
            free(result);
            result = NULL;
        }
        else if (hci_le_set_scan_enable(socket, 0x01, 1, 1000) < 0)
        {
            free(result);
            result = NULL;
        }
        else
        {
            int resp_count;
            inquiry_info* bt_inquiry;
            int flags = IREQ_CACHE_FLUSH;

            if ((bt_inquiry = (inquiry_info*)malloc(max_response * sizeof(inquiry_info))) == NULL)
            {
                free(result);
                result = NULL;
            }
            else if ((resp_count = hci_inquiry(result->dev_id, len, max_response, NULL, &bt_inquiry, flags)) > 0)
            {
                free(bt_inquiry);
                free(result);
                result = NULL;
            }
            else if ((result->list_handle = singlylinkedlist_create()) == NULL)
            {
                free(bt_inquiry);
                free(result);
                result = NULL;
            }
            else
            {
                char addr_string[19] = { 0 };
                char device_name[248] = { 0 };

                for (size_t index = 0; index < resp_count; index++)
                {
                    ba2str(&(bt_inquiry+index)->bdaddr, addr_string);
                    memset(device_name, 0, sizeof(device_name));
                    if (hci_read_remote_name(socket, &(bt_inquiry+index)->bdaddr, sizeof(device_name), device_name, TIMEOUT_VALUE) < 0)
                    {
                        strcpy(device_name, "[unknown]");
                    }
                    else
                    {
                        // Add it to the list here
                        singlylinkedlist_add(result->list_handle, 0);
                    }
                    printf("%s %s\n", addr_string, device_name);
                }
            }
            free(bt_inquiry);
            close(socket);
        }
    }
    return result;
}

void bt_discover_destroy(BT_DISCOVER_HANDLE handle)
{
    if (handle != NULL)
    {
        singlylinkedlist_destroy(handle->list_handle);
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
