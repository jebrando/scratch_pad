// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

//#include <vld.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <unistd.h>
#include <inttypes.h>
#include <sys/socket.h>

#include <bluetooth/bluetooth.h>
#include <bluetooth/hci.h>
#include <bluetooth/hci_lib.h>
#include <bluetooth/sdp.h>
#include <bluetooth/sdp_lib.h>

#include "bt_beacon_mgr.h"
#include "bt_device_mgr.h"
#include "bt_device_discovery.h"

/*#include "azure_c_shared_utility/base64.h"
#include "azure_c_shared_utility/buffer_.h"
#include "azure_c_shared_utility/xlogging.h"*/

/*typedef enum X509_ASN1_STATE_TAG
{
    STATE_INITIAL,
    STATE_TBS_CERTIFICATE,
    STATE_SIGNATURE_ALGO,
    STATE_SIGNATURE_VALUE
} X509_ASN1_STATE;*/

static int read_write_devices()
{

/*struct sockaddr_rc addr = { 0 };
    int s, status, len=0;
    char dest[18] = "00:12:01:31:01:13";
    char buf[256];
    // allocate a socket
    s = socket(AF_BLUETOOTH, SOCK_STREAM, BTPROTO_RFCOMM);
 
    // set the connection parameters (who to connect to)
    addr.rc_family = AF_BLUETOOTH;
    addr.rc_channel = (uint8_t) 1;
    str2ba( dest, &addr.rc_bdaddr );
 
    // connect to server
    status = connect(s, (struct sockaddr *)&addr, sizeof(addr));
 
 
    if(status){
        printf(" failed to connect the device!\n");
        return -1;
    }
 
 
    do{
        len = read(s, buf, sizeof buf);
 
     if( len>0 ) {
         buf[len]=0;
         printf("%s\n",buf);
         write(s, buf, strlen(buf));
     }
    }while(len>0);
 
    close(s);*/
    return 0;
}

static int discover_devices()
{
    int result;

    BT_DISCOVER_HANDLE device_discover = bt_discover_create(NULL, 255);
    if (device_discover == NULL)
    {
        printf("Failed create discover handle");
        result = __LINE__;
    }
    else
    {
        result = 0;
        bt_discover_destroy(device_discover);
    }
    /*int dev_id;
    int socket;
    inquiry_info* bt_inquiry;
    int max_rsp = 255;
    int devs[16];

    //int devices = hci_get_devs(devs);
    //printf("hci get devices %d\r\n", devices);

    (void)printf("getting routes and opening device\r\n");
    if ((dev_id = hci_get_route(NULL)) < 0)
    {
        printf("Failure opening device: %d\r\n", dev_id);
        result = __LINE__;
    }
    else if ((socket = hci_open_dev(dev_id)) < 0)
    {
        printf("Failure opening socket %d\r\n", socket);
        result = __LINE__;
    }
    else if ((bt_inquiry = (inquiry_info*)malloc(max_rsp * sizeof(inquiry_info))) == NULL)
    {
        printf("Failure allocating inquiry buffer\r\n");
        close(socket);
        result = __LINE__;
    }
    else
    {
        int len = 8;
        int flags = IREQ_CACHE_FLUSH;
        int num_rsp;
        //sdp_session_t* session = 0;
        bdaddr_t target;

        //session = sdp_connect(BDADDR_ANY, &target, SDP_RETRY_IF_BUSY);

        (void)printf("Inquirying devices\r\n");
        num_rsp = hci_inquiry(dev_id, len, max_rsp, NULL, &bt_inquiry, flags);
        if (num_rsp < 0) 
        {
            printf("Failure inquiry of devices\r\n");
            result = __LINE__;
        }
        else
        {
            char addr[19] = { 0 };
            char name[248] = { 0 };

            (void)printf("%d devices found\r\n", num_rsp);
            for (size_t index = 0; index < num_rsp; index++)
            {
                ba2str(&(bt_inquiry+index)->bdaddr, addr);
                memset(name, 0, sizeof(name));
                if (hci_read_remote_name(socket, &(bt_inquiry+index)->bdaddr, sizeof(name), name, 0) < 0)
                {
                    strcpy(name, "[unknown]");
                }
                printf("%s %s\n", addr, name);
            }
            result = 0;
        }
        free(bt_inquiry);
        close(socket);
    }*/
    return result;
}

/*static int connect_to_beacon(void)
{
    int result;
    BT_BEACON_HANDLE beacon = bt_beacon_create(BEACON_TYPE_iBEACON);
    if (beacon == NULL)
    {
        result = __LINE__;
    }
    else
    {
        result = 0;
    }
    return result;
}*/

int main(void)
{
    int result = 0;

    discover_devices();

    return result;
}
