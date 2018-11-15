// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

//#include <vld.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <unistd.h>
#include <inttypes.h>
#include <sys/socket.h>

#include <sys/param.h>
#include <sys/ioctl.h>
#include <signal.h>

#include <bluetooth/bluetooth.h>
#include <bluetooth/hci.h>
#include <bluetooth/hci_lib.h>
#include <bluetooth/sdp.h>
#include <bluetooth/sdp_lib.h>

#include "bt_beacon_mgr.h"
#include "bt_device_mgr.h"
#include "bt_device_discovery.h"

static int read_write_devices()
{
    return 0;
}

static int discover_devices()
{
    int result;
    printf("Discovering devices\r\n");
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
    return result;
}

static volatile int signal_received = 0;

static void sigint_handler(int sig)
{
    signal_received = sig;
}

static int print_advert_devices(int dev_conn)
{
    int result;
    struct hci_filter nf, of;
    socklen_t olen = sizeof(of);
    struct sigaction sa;

    if (getsockopt(dev_conn, SOL_HCI, HCI_FILTER, &of, &olen) < 0)
    {
        printf("Could not get socket options\n");
        result = __LINE__;
    }
    else
    {
        hci_filter_clear(&nf);
        hci_filter_set_ptype(HCI_EVENT_PKT, &nf);
        hci_filter_set_event(EVT_LE_META_EVENT, &nf);

        if (setsockopt(dev_conn, SOL_HCI, HCI_FILTER, &nf, sizeof(nf)) < 0)
        {
            printf("Could not set socket options\n");
        }
        else
        {
            memset(&sa, 0, sizeof(sa));
            sa.sa_flags = SA_NOCLDSTOP;
            sa.sa_handler = sigint_handler;
            sigaction(SIGINT, &sa, NULL);

            result = 0;
        }
    }
    return result;
}

int main(void)
{
    int result = 0;

    int device_address = 0;
    int dev_conn;
    if (device_address < 0)
    {
        device_address = hci_get_route(NULL);
    }
    if ((dev_conn = hci_open_dev(device_address)) < 0)
    {
        (void)printf("Open device failed\r\n");
        result = __LINE__;
    }
    else if (hci_le_set_scan_parameters(dev_conn, 0x01, htobs(0x0010), htobs(0x0010), 0x00, 0x00, 1000) < 0)
    {
        (void)printf("hci_le_set_scan_parameters failed\r\n");
        hci_close_dev(dev_conn);
        result = __LINE__;
    }
    else if (hci_le_set_scan_enable(dev_conn, 0x01, 0, 1000) < 0)
    {
        (void)printf("hci_le_set_scan_enable failed\r\n");
        hci_close_dev(dev_conn);
        result = __LINE__;
    }
    else
    {

        hci_le_set_scan_enable(dev_conn, 0x00, 0, 1000);
        hci_close_dev(dev_conn);
    }

    //discover_devices();

    return result;
}
