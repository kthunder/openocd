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
#include <stdio.h>

extern int open_serial_port(const char *port);
extern int write_serial_port(const char *data, size_t length);
extern int read_serial_port(char *buffer, size_t length);
extern int serial_port_send_message(uint8_t opcode, uint16_t bits, uint8_t *ucData);

typedef struct
{
    uint8_t head;
    uint8_t len;
    uint8_t padding1;
    uint8_t padding2;
    uint8_t opcode;
    uint8_t opcode_ex;
    uint16_t bits;
    uint8_t data[];
} message;

static int xxlink_init(void)
{
    log_set_level(LOG_WARN);
    log_debug("xxlink_init");
#ifdef _WIN32
    const char *port = "COM5";
#else
    const char *port = "/dev/ttyACM0";
#endif
    int ret = open_serial_port(port);
    log_trace("open_serial_port ret:%d", ret);
    serial_port_send_message(0xFF, 0, NULL);
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

static void xxlink_execute_scan(struct jtag_command *cmd)
{
    uint8_t buffer[0x1000] = {0};
    // log_trace("%s type:%d", cmd->cmd.scan->ir_scan ? "IRSCAN" : "DRSCAN",
    //          jtag_scan_type(cmd->cmd.scan));
    struct scan_field *field = cmd->cmd.scan->fields;

    for (unsigned int i = 0; i < cmd->cmd.scan->num_fields; i++, field++)
    {
        // log_debug("%s%s field %u/%u %u bits",
        //           field->in_value ? "in" : "",
        //           field->out_value ? "out" : "",
        //           i,
        //           cmd->cmd.scan->num_fields,
        //           field->num_bits);
        serial_port_send_message(cmd->cmd.scan->ir_scan ? 0 : 1, field->num_bits, field->out_value);
        read_serial_port(field->in_value != NULL ? (char *)field->in_value : (char *)buffer, (field->num_bits + 7) / 8);
        // if (field->out_value)
        //     log_hex("SCAN out:", (uint8_t *)field->out_value, bytes - 8);
        // if (field->in_value)
        //     log_hex("SCAN in :", field->in_value, bytes - 8);
    }
    tap_set_state(TAP_IDLE);
}

/* TODO: Is there need to call cmsis_dap_flush() for the JTAG_PATHMOVE,
 * JTAG_RUNTEST, JTAG_STABLECLOCKS? */
static void xxlink_execute_command(struct jtag_command *cmd)
{
    switch (cmd->type)
    {
    case JTAG_SCAN:
        log_trace("-->JTAG_SCAN");
        xxlink_execute_scan(cmd);
        break;
    case JTAG_TLR_RESET:
        log_trace("-->JTAG_TLR_RESET");
        uint8_t ucFF[0x10] = {0};
        memset(ucFF, 0xFF, 0x10);
        serial_port_send_message(2, cmd->cmd.runtest->num_cycles, ucFF);
        ucFF[0] = 0;
        serial_port_send_message(2, 1, ucFF);
        break;
    case JTAG_RUNTEST:
        log_trace("-->JTAG_RUNTEST");
        uint8_t uc00[0x10] = {0};
        serial_port_send_message(2, cmd->cmd.runtest->num_cycles, uc00);
        break;
    case JTAG_RESET:
        log_trace("-->JTAG_RESET");
        break;
    case JTAG_PATHMOVE:
        log_trace("-->JTAG_PATHMOVE");
        break;
    case JTAG_SLEEP:
        log_trace("-->JTAG_SLEEP");
        sleep(cmd->cmd.sleep->us);
        break;
    case JTAG_STABLECLOCKS:
        log_trace("-->JTAG_STABLECLOCKS");
        uint8_t ucbuff[0x10] = {0};
        if (tap_get_state() == TAP_RESET)
            memset(ucbuff, 0xFF, 0x10);
        serial_port_send_message(2, cmd->cmd.stableclocks->num_cycles, ucbuff);
        break;
    case JTAG_TMS:
        log_trace("-->JTAG_TMS");
        serial_port_send_message(2, cmd->cmd.tms->num_bits, cmd->cmd.tms->bits);
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

    .jtag_ops = &xxlink_interface,
};