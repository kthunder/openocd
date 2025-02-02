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

#include <fcntl.h>
#include <errno.h>
#include <termios.h>

/*******************************usb cdc*******************************/
int tty_fd = 0;
// 打开串口
int open_serial_port(const char *port)
{
    int fd = open(port, O_RDWR | O_NOCTTY | O_SYNC);
    if (fd < 0)
    {
        perror("open");
        return -1;
    }
    return fd;
}

// 设置串口参数
int set_serial_port(int fd, int baud_rate)
{
    struct termios tty;

    if (tcgetattr(fd, &tty) != 0)
    {
        perror("tcgetattr");
        return -1;
    }

    cfsetospeed(&tty, baud_rate);
    cfsetispeed(&tty, baud_rate);

    tty.c_cflag = (tty.c_cflag & ~CSIZE) | CS8; // 8-bit characters
    tty.c_iflag &= ~IGNBRK;                     // disable break processing
    tty.c_lflag = 0;                            // no signaling chars, no echo, etc.
    tty.c_oflag = 0;                            // no remapping, no delays
    tty.c_cc[VMIN] = 0;                         // read doesn't block
    tty.c_cc[VTIME] = 5;                        // 0.5 seconds read timeout

    tty.c_iflag &= ~(IXON | IXOFF | IXANY); // shut off xon/xoff ctrl
    tty.c_cflag |= (CLOCAL | CREAD);        // ignore modem controls, enable reading
    tty.c_cflag &= ~(PARENB | PARODD);      // shut off parity
    tty.c_cflag &= ~CSTOPB;                 // only need 1 stop bit
    tty.c_cflag &= ~CRTSCTS;                // no hardware flow control

    if (tcsetattr(fd, TCSANOW, &tty) != 0)
    {
        perror("tcsetattr");
        return -1;
    }

    return 0;
}

// 写入串口数据
int write_serial_port(const char *data, size_t length)
{
    int n = write(tty_fd, data, length);
    if (n < 0)
    {
        perror("write");
        return -1;
    }
    return n;
}

// 读取串口数据
int read_serial_port(char *buffer, size_t length)
{
    size_t read_len = 0;
    while (length != read_len)
    {
        int n = read(tty_fd, buffer + read_len, length - read_len);
        if (n < 0)
        {
            perror("read");
            return -1;
        }
        else
        {
            read_len += n;
        }
    }

    return 0;
}
/*******************************usb cdc*******************************/
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
    // log_debug("xxlink_init");
    tty_fd = open_serial_port("/dev/ttyACM0");
    set_serial_port(tty_fd, 115200);
    return tty_fd ? ERROR_OK : ERROR_FAIL;
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
    uint8_t msg_buffer[0x1000] = {0};
    uint8_t buffer[0x1000] = {0};
    message *msg = (message *)msg_buffer;

    // log_info("%s type:%d", cmd->cmd.scan->ir_scan ? "IRSCAN" : "DRSCAN",
    //          jtag_scan_type(cmd->cmd.scan));

    if (cmd->cmd.scan->ir_scan)
    {
        msg->opcode = 0;
    }
    else
    {
        msg->opcode = 1;
    }

    struct scan_field *field = cmd->cmd.scan->fields;
    unsigned int scan_size = 0;

    for (unsigned int i = 0; i < cmd->cmd.scan->num_fields; i++, field++)
    {
        uint16_t bytes = 8 + field->num_bits / 8 + (field->num_bits % 8 ? 1 : 0);
        scan_size += field->num_bits;
        // log_debug("%s%s field %u/%u %u bits",
        //           field->in_value ? "in" : "",
        //           field->out_value ? "out" : "",
        //           i,
        //           cmd->cmd.scan->num_fields,
        //           field->num_bits);
        msg->bits = field->num_bits;
        msg->len = bytes;
        // msg->bits = ((field->num_bits << 8) & 0xFF00) | ((field->num_bits >> 8) & 0x00FF);
        // msg->len = ((bytes << 8) & 0xFF00) | ((bytes >> 8) & 0x00FF);
        memcpy(msg->data, field->out_value, bytes - 8);
        write_serial_port((const char *)msg, bytes);
        read_serial_port(field->in_value != NULL ? (char *)field->in_value : (char *)buffer, bytes - 8);
        // if (field->out_value)
        //     log_hex("SCAN out:", (uint8_t *)field->out_value, bytes - 8);
        // if (field->in_value)
        //     log_hex("SCAN in :", field->in_value, bytes - 8);
    }

    tap_set_state(TAP_IDLE);
}

// static void xxlink_execute_tlr_reset(struct jtag_command *cmd)
// {
//     uint8_t msg_buffer[0x1000] = {0};
//     uint8_t buffer[0x1000] = {0};
//     message *msg = (message *)msg_buffer;

//     msg->opcode = 2;
//     msg->bits = 8;
//     msg->len = 9;
//     msg->data[0] = 0xFF;

//     write_serial_port((const char *)msg, msg->len);
//     read_serial_port((char *)buffer, 1);
//     tap_set_state(TAP_RESET);
// }

static void xxlink_execute_runtest(struct jtag_command *cmd)
{
    uint8_t msg_buffer[0x1000] = {0};
    uint8_t buffer[0x1000] = {0};
    message *msg = (message *)msg_buffer;

    msg->opcode = 2;
    msg->bits = 8;
    // msg->bits = cmd->cmd.runtest->num_cycles;
    msg->len = 8 + cmd->cmd.runtest->num_cycles / 8 + (cmd->cmd.runtest->num_cycles % 8 ? 1 : 0);

    write_serial_port((const char *)msg, msg->len);
    read_serial_port((char *)buffer, 1);
    tap_set_state(TAP_RESET);
}

// static void xxlink_execute_reset(struct jtag_command *cmd)
// {
//     uint8_t msg_buffer[0x1000] = {0};
//     uint8_t buffer[0x1000] = {0};
//     message *msg = (message *)msg_buffer;

//     msg->opcode = 2;
//     msg->bits = 8;
//     msg->len = 9;
//     msg->data[0] = 0x7F;

//     write_serial_port((const char *)msg, msg->len);
//     read_serial_port((char *)buffer, 1);
//     tap_set_state(TAP_IDLE);
// }

// static void xxlink_execute_pathmove(struct jtag_command *cmd)
// {
//     log_error("-->xxlink_execute_pathmove");
// }

// static void xxlink_execute_stableclocks(struct jtag_command *cmd)
// {
//     log_error("-->xxlink_execute_stableclocks");
// }

// static void xxlink_execute_tms(struct jtag_command *cmd)
// {
//     log_error("-->xxlink_execute_tms");
// }
/* TODO: Is there need to call cmsis_dap_flush() for the JTAG_PATHMOVE,
 * JTAG_RUNTEST, JTAG_STABLECLOCKS? */
static void xxlink_execute_command(struct jtag_command *cmd)
{
    // log_info("xxlink_execute_command:jtag interface cmd");
    switch (cmd->type)
    {
    case JTAG_SCAN:
        // log_info("-->JTAG_SCAN");
        // if (tap_get_state() != TAP_IDLE)
        //     xxlink_execute_reset(cmd);
        xxlink_execute_scan(cmd);
        break;
    case JTAG_TLR_RESET:
        // JTAG 测试逻辑复位（Test-Logic-Reset）操作
        // 重置 JTAG 状态机
        // log_info("-->JTAG_TLR_RESET");
        // xxlink_execute_tlr_reset(cmd);
        break;
    case JTAG_RUNTEST:
        // log_info("-->JTAG_RUNTEST");
        xxlink_execute_runtest(cmd);
        //  cmsis_dap_execute_runtest(cmd);
        break;
    case JTAG_RESET:
        // log_info("-->JTAG_RESET");
        // xxlink_execute_reset(cmd);
        break;
    case JTAG_PATHMOVE:
        // log_info("-->JTAG_PATHMOVE");
        // xxlink_execute_pathmove(cmd);
        //  cmsis_dap_execute_pathmove(cmd);
        break;
    case JTAG_SLEEP:
        // log_info("-->JTAG_SLEEP");
        sleep(cmd->cmd.sleep->us);
        break;
    case JTAG_STABLECLOCKS:
        // log_info("-->JTAG_STABLECLOCKS");
        // xxlink_execute_stableclocks(cmd);
        break;
    case JTAG_TMS:
        // log_info("-->JTAG_TMS");
        // xxlink_execute_tms(cmd);
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