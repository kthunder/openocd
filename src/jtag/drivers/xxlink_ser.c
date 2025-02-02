#include <stdio.h>
#include <unistd.h>
#include <fcntl.h>
#include <termios.h>
#include <string.h>
#include <stdint.h>
#include <stdlib.h>

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

typedef struct
{
    uint8_t head;
    uint8_t opcode;
    uint16_t len;
    uint16_t bits;
    uint8_t data[];
} message;

int main()
{
    message* msg = malloc(7);
    msg->head = 0;
    msg->opcode = 0;
    const char *port = "/dev/ttyACM0";
    int fd = open_serial_port(port);
    if (fd < 0)
    {
        fprintf(stderr, "Failed to open serial port %s\n", port);
        return -1;
    }
    uint32_t bytes = 6 + 1;
    msg->bits = 5;
    msg->len = 7;
    // msg->bits = ((5 << 8) & 0xFF00) | ((5 >> 8) & 0x00FF);
    // msg->len = ((bytes << 8) & 0xFF00) | ((bytes >> 8) & 0x00FF);

    uint8_t * ucdata = (uint8_t *)msg;
    for (size_t i = 0; i < bytes; i++)
    {
       printf("%02X\r\n", ucdata[i]);
    }
    

    if (write(fd, (const void *)msg, bytes) < 0)
    {
        perror("write");
    }

    // 关闭串口
    close(fd);
    return 0;
}