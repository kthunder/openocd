#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <stdbool.h>
#include <fcntl.h>
#include <errno.h>
#ifdef _WIN32
#include <windows.h>
#else
#include <termios.h>
#endif

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

int open_serial_port(const char *port);
int write_serial_port(const char *data, size_t length);
int read_serial_port(char *buffer, size_t length);
int serial_port_send_message(uint8_t opcode, uint16_t bits, uint8_t *ucData);

#ifdef _WIN32
HANDLE hSerial;
int open_serial_port(const char *port)
{
    printf("%s : %s\r\n", __func__, port);
    hSerial = CreateFile(
        port,
        GENERIC_READ | GENERIC_WRITE,
        0,
        NULL,
        OPEN_EXISTING,
        FILE_ATTRIBUTE_NORMAL,
        NULL);

    if (hSerial == INVALID_HANDLE_VALUE)
        return -1;

    // 配置串口9600,8,N,1
    DCB dcb = {0};
    dcb.DCBlength = sizeof(dcb);
    GetCommState(hSerial, &dcb);
    dcb.BaudRate = CBR_115200;
    dcb.ByteSize = 8;
    SetCommState(hSerial, &dcb);
}

int write_serial_port(const char *data, size_t length)
{
    DWORD bytesWritten;
    if (!WriteFile(hSerial, data, length, &bytesWritten, 0))
        return -1;
    else
        return bytesWritten;
}

// 读取串口数据
int read_serial_port(char *buffer, size_t length)
{
    size_t read_len = 0;
    DWORD bytesRead;
    while (length != read_len)
    {
        if (!ReadFile(hSerial, buffer + read_len, length - read_len, &bytesRead, NULL))
            return -1;
        else
            read_len += bytesRead;
    }

    return length;
}
#else
int tty_fd = 0;
int open_serial_port(const char *port)
{
    struct termios tty;
    int baud_rate = 115200;

    int fd = open(port, O_RDWR | O_NOCTTY | O_SYNC);
    if (fd < 0)
        return -1;

    if (tcgetattr(fd, &tty) != 0)
        return -1;

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
        return -1;

    tty_fd = fd;

    return fd;
}

int write_serial_port(const char *data, size_t length)
{
    int n = write(tty_fd, data, length);
    if (n < 0)
        return -1;

    return n;
}

int read_serial_port(char *buffer, size_t length)
{
    size_t read_len = 0;
    while (length != read_len)
    {
        int n = read(tty_fd, buffer + read_len, length - read_len);
        if (n < 0)
            return -1;
        else
            read_len += n;
    }

    return 0;
}
#endif

static uint8_t ucBuffer[0x1000] = {0};
static uint8_t ackBuffer[0x10] = {0};

int serial_port_send_message(uint8_t opcode, uint16_t bits, uint8_t *ucData)
{
    message *msg = (message *)ucBuffer;

    msg->len = 8 + (bits + 7) / 8;
    msg->opcode = opcode;
    msg->bits = bits;

    memcpy(&msg->data[0], ucData, msg->len - 8);
    write_serial_port(ucBuffer, msg->len);
    if (opcode == 2)
        read_serial_port(ackBuffer, 1);
    
    return 1;
}