

#include <stdio.h>
#include <stdint.h>
#include <ctype.h>

#define BYTES_PER_LINE 16

/**
 * @brief 打印内存数据的十六进制和 ASCII 转储
 * @param addr 数据起始地址
 * @param len  要输出的字节数
 */
void hexdump(const void *addr, uint32_t len)
{
    if (addr == NULL || len == 0) {
        return;
    }

    const unsigned char *buf = (const unsigned char *)addr;
    size_t i, j;
    for (i = 0; i < len; i += BYTES_PER_LINE) {
        // 打印偏移地址 (8位十六进制)
        printf("%08zx  ", i);
        // 打印十六进制部分
        for (j = 0; j < BYTES_PER_LINE; j++) {
            if (i + j < len) {
                printf("%02x ", buf[i + j]);
            } else {
                // 补齐空格，保持对齐
                printf("   ");
            }
        }

        // 分隔符号
        printf(" |");
        // 打印 ASCII 可打印字符，不可打印的用 '.' 代替
        for (j = 0; j < BYTES_PER_LINE && (i + j) < len; j++) {
            unsigned char c = buf[i + j];
            putchar(isprint(c) ? c : '.');
        }
        // 补齐空格，确保 '|' 在固定位置
        for (; j < BYTES_PER_LINE; j++) {
            putchar(' ');
        }
        printf("|\n");
    }
}


