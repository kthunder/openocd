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

static uint16_t xxlink_vid = 0x0403;
static uint16_t xxlink_pid = 0x6001;

static int xxlink_init(void)
{
    LOG_DEBUG("xxlink_init");
    return ERROR_OK;
}

static int xxlink_quit(void)
{
    LOG_DEBUG("xxlink_quit");
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
    LOG_DEBUG("xxlink_speed_div divisor=%d rate %d khz", divisor, *khz);
    return ERROR_OK;
}

static int xxlink_khz(int khz, int *divisor)
{
    if (khz == 0)
    {
        LOG_DEBUG("RCLK not supported");
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
    LOG_DEBUG("xxlink_khz %d divisor=%d", khz, *divisor);
    return ERROR_OK;
}

static int xxlink_speed(int divisor)
{
    int baud = (divisor == 0) ? 3000000 : (divisor == 1) ? 2000000
                                                         : 3000000 / divisor;
    LOG_DEBUG("xxlink_speed(%d) rate %d bits/sec", divisor, baud);

    // if (jtag_libusb_control_transfer(adapter,
    //   LIBUSB_REQUEST_TYPE_VENDOR | LIBUSB_RECIPIENT_DEVICE | LIBUSB_ENDPOINT_OUT,
    //   SIO_SET_BAUD_RATE, divisor, 0, NULL, 0, 1000, NULL) != ERROR_OK) {
    //   LOG_ERROR("cannot set baud rate");
    //   return ERROR_JTAG_DEVICE_ERROR;
    // }

    return ERROR_OK;
}

COMMAND_HANDLER(xxlink_handle_vid_pid_command)
{
    if (CMD_ARGC > 2)
    {
        LOG_WARNING("ignoring extra IDs in ft232r_vid_pid "
                    "(maximum is 1 pair)");
        CMD_ARGC = 2;
    }
    if (CMD_ARGC == 2)
    {
        COMMAND_PARSE_NUMBER(u16, CMD_ARGV[0], xxlink_vid);
        COMMAND_PARSE_NUMBER(u16, CMD_ARGV[1], xxlink_pid);
        LOG_DEBUG("xxlink_vid:%x,xxlink_pid:%x", xxlink_vid, xxlink_pid);
    }
    else
        LOG_WARNING("incomplete ft232r_vid_pid configuration");

    return ERROR_OK;
}

static const struct command_registration xxlink_subcommand_handlers[] = {
    {
        .name = "vid_pid",
        .handler = &xxlink_handle_vid_pid_command,
        .mode = COMMAND_CONFIG,
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
    LOG_DEBUG("xxlink_execute_command:jtag interface cmd\r\n");
    switch (cmd->type)
    {
    case JTAG_SLEEP:
        LOG_DEBUG("-->JTAG_SLEEP\r\n");
        // cmsis_dap_flush();
        // cmsis_dap_execute_sleep(cmd);
        break;
    case JTAG_TLR_RESET:
        LOG_DEBUG("-->JTAG_TLR_RESET\r\n");
        // cmsis_dap_flush();
        // cmsis_dap_execute_tlr_reset(cmd);
        break;
    case JTAG_SCAN:
        LOG_DEBUG("-->JTAG_SCAN\r\n");
        // cmsis_dap_execute_scan(cmd);
        break;
    case JTAG_PATHMOVE:
        LOG_DEBUG("-->JTAG_PATHMOVE\r\n");
        // cmsis_dap_execute_pathmove(cmd);
        break;
    case JTAG_RUNTEST:
        LOG_DEBUG("-->JTAG_RUNTEST\r\n");
        // cmsis_dap_execute_runtest(cmd);
        break;
    case JTAG_STABLECLOCKS:
        LOG_DEBUG("-->JTAG_STABLECLOCKS\r\n");
        // cmsis_dap_execute_stableclocks(cmd);
        break;
    case JTAG_TMS:
        LOG_DEBUG("-->JTAG_TMS\r\n");
        // cmsis_dap_execute_tms(cmd);
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