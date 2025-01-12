// SPDX-License-Identifier: GPL-2.0-or-later

/***************************************************************************
 *   Copyright (C) 2024              xx                                    *
 *   xxxxx@xxx.xx                                                          *
 ***************************************************************************/

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#if IS_CYGWIN == 1
#include "windows.h"
#undef LOG_ERROR
#endif

/* project specific includes */
#include <jtag/adapter.h>
#include <jtag/interface.h>
#include <jtag/commands.h>
#include <helper/time_support.h>
#include "libusb_helper.h"

/* system includes */
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/time.h>
#include <time.h>

#include "port_link.h"

void print_hex(uint8_t *data, int len)
{
    for (int i = 0; i < len; i++)
    {
        printf("%02X ", data[i]);
    }
    printf("\n");
}
static int xxlink_init(void)
{
    cklink_init();
    log_info("xxlink_init");
    return ERROR_OK;
}

static int xxlink_quit(void)
{
    log_info("xxlink_quit");
    return ERROR_OK;
}

static int xxlink_speed_div(int divisor, int *khz)
{
    /* Maximum 3 Mbaud. */
    if (divisor == 0)
        *khz = 3000;
    else if (divisor == 1)
        *khz = 2000;
    else
        *khz = 3000 / divisor;
    log_info("xxlink_speed_div divisor=%d rate %d khz", divisor, *khz);
    return ERROR_OK;
}

static int xxlink_khz(int khz, int *divisor)
{
    if (khz == 0)
    {
        log_info("RCLK not supported");
        return ERROR_FAIL;
    }

    /* Calculate frequency divisor. */
    if (khz > 2500)
        *divisor = 0; /* Special case: 3 MHz */
    else if (khz > 1700)
        *divisor = 1; /* Special case: 2 MHz */
    else
    {
        *divisor = (2 * 3000 / khz + 1) / 2;
        if (*divisor > 0x3FFF)
            *divisor = 0x3FFF;
    }
    log_info("xxlink_khz %d divisor=%d", khz, *divisor);
    return ERROR_OK;
}

static int xxlink_speed(int divisor)
{
    int baud = (divisor == 0) ? 3000000 : (divisor == 1) ? 2000000
                                                         : 3000000 / divisor;
    log_info("xxlink_speed(%d) rate %d bits/sec", divisor, baud);

    // if (jtag_libusb_control_transfer(adapter,
    //   LIBUSB_REQUEST_TYPE_VENDOR | LIBUSB_RECIPIENT_DEVICE | LIBUSB_ENDPOINT_OUT,
    //   SIO_SET_BAUD_RATE, divisor, 0, NULL, 0, 1000, NULL) != ERROR_OK) {
    //   LOG_ERROR("cannot set baud rate");
    //   return ERROR_JTAG_DEVICE_ERROR;
    // }

    return ERROR_OK;
}

COMMAND_HANDLER(xxlink_handle_hello_command)
{
    printf("%s", __func__);
    return ERROR_OK;
}

static const struct command_registration xxlink_subcommand_handlers[] = {
    {
        .name = "hello",
        .handler = &xxlink_handle_hello_command,
        .mode = COMMAND_ANY,
        .help = "USB VID and PID of the adapter",
        .usage = "vid pid",
    },
    COMMAND_REGISTRATION_DONE};

static const struct command_registration xxlink_command_handlers[] = {
    {
        .name = "xxlink",
        .mode = COMMAND_ANY,
        .help = "perform xxlink management",
        .chain = xxlink_subcommand_handlers,
        .usage = "",
    },
    COMMAND_REGISTRATION_DONE};

/* TODO: Is there need to call cmsis_dap_flush() for the JTAG_PATHMOVE,
 * JTAG_RUNTEST, JTAG_STABLECLOCKS? */
static void xxlink_execute_command(struct jtag_command *cmd)
{
    // log_info("xxlink_execute_command:jtag interface cmd");
    switch (cmd->type)
    {
    case JTAG_SCAN:
        log_info("-->JTAG_SCAN");
        break;
    case JTAG_TLR_RESET:
        // JTAG 测试逻辑复位（Test-Logic-Reset）操作
        // 重置 JTAG 状态机
        log_info("-->JTAG_TLR_RESET");
        break;
    case JTAG_RUNTEST:
        log_info("-->JTAG_RUNTEST");
        //  cmsis_dap_execute_runtest(cmd);
        break;
    case JTAG_RESET:
        log_info("-->JTAG_RESET");
        break;
    case JTAG_PATHMOVE:
        log_info("-->JTAG_PATHMOVE");
        //  cmsis_dap_execute_pathmove(cmd);
        break;
    case JTAG_SLEEP:
        log_info("-->JTAG_SLEEP");
        Sleep(cmd->cmd.sleep->us);
        break;
    case JTAG_STABLECLOCKS:
        log_info("-->JTAG_STABLECLOCKS");
        break;
    case JTAG_TMS:
        log_info("-->JTAG_TMS");
        break;
    default:
        LOG_ERROR("BUG: unknown JTAG command type 0x%X encountered", cmd->type);
        exit(-1);
    }
}

static int xxlink_execute_queue(struct jtag_command *cmd_queue)
{
    struct jtag_command *cmd = cmd_queue;

    while (cmd)
    {
        xxlink_execute_command(cmd);
        cmd = cmd->next;
    }

    return ERROR_OK;
}

static struct jtag_interface xxlink_interface = {
    .supported = DEBUG_CAP_TMS_SEQ,
    .execute_queue = xxlink_execute_queue,
};

struct adapter_driver xxlink_adapter_driver = {
    .name = "xxlink",
    .transports = jtag_only,
    .commands = xxlink_command_handlers,

    .init = xxlink_init,
    .quit = xxlink_quit,
    .speed = xxlink_speed,
    .khz = xxlink_khz,
    .speed_div = xxlink_speed_div,

    .jtag_ops = &xxlink_interface,
};