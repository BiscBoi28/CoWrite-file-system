#define _POSIX_C_SOURCE 200809L

#include "cli_input.h"

#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <termios.h>
#include <unistd.h>

#define CLI_HISTORY_MAX 128

static char *g_history[CLI_HISTORY_MAX];
static size_t g_history_len = 0;
static int g_stdio_is_tty = 0;
static struct termios g_orig_termios;
static int g_termios_saved = 0;

static void free_history(void) {
    for (size_t i = 0; i < g_history_len; ++i) {
        free(g_history[i]);
        g_history[i] = NULL;
    }
    g_history_len = 0;
}

void cli_input_init(void) {
    g_stdio_is_tty = isatty(STDIN_FILENO);
    if (!g_stdio_is_tty) {
        return;
    }
    if (tcgetattr(STDIN_FILENO, &g_orig_termios) == 0) {
        g_termios_saved = 1;
    } else {
        g_stdio_is_tty = 0;
    }
    atexit(free_history);
}

static int enable_raw_mode(void) {
    if (!g_stdio_is_tty || !g_termios_saved) {
        return 0;
    }
    struct termios raw = g_orig_termios;
    raw.c_lflag &= ~(ICANON | ECHO);
    raw.c_cc[VMIN] = 1;
    raw.c_cc[VTIME] = 0;
    return tcsetattr(STDIN_FILENO, TCSAFLUSH, &raw);
}

static void disable_raw_mode(void) {
    if (g_stdio_is_tty && g_termios_saved) {
        tcsetattr(STDIN_FILENO, TCSAFLUSH, &g_orig_termios);
    }
}

void cli_input_remember(const char *line) {
    if (!line || !*line) {
        return;
    }
    char *copy = strdup(line);
    if (!copy) {
        return;
    }
    if (g_history_len == CLI_HISTORY_MAX) {
        free(g_history[0]);
        memmove(&g_history[0], &g_history[1], sizeof(char *) * (CLI_HISTORY_MAX - 1));
        g_history_len--;
    }
    g_history[g_history_len++] = copy;
}

static void redraw_prompt(const char *prompt, const char *line) {
    write(STDOUT_FILENO, "\r", 1);
    if (prompt) {
        write(STDOUT_FILENO, prompt, strlen(prompt));
    }
    if (line) {
        write(STDOUT_FILENO, line, strlen(line));
    }
    write(STDOUT_FILENO, "\x1b[K", 3);
}

static void load_history_entry(int index, char *buf, size_t buf_size, size_t *len_out) {
    if (index < 0 || (size_t)index >= g_history_len || !buf || buf_size == 0) {
        buf[0] = '\0';
        if (len_out) {
            *len_out = 0;
        }
        return;
    }
    snprintf(buf, buf_size, "%s", g_history[index]);
    if (len_out) {
        *len_out = strlen(buf);
        if (*len_out >= buf_size) {
            *len_out = buf_size - 1;
        }
    }
}

static void reset_line(char *buf, size_t *len, size_t buf_size, const char *prompt) {
    redraw_prompt(prompt, buf);
    if (len) {
        *len = strlen(buf);
        if (*len >= buf_size) {
            *len = buf_size - 1;
        }
    }
}

int cli_input_readline(const char *prompt, char *buf, size_t buf_size) {
    if (!buf || buf_size == 0) {
        return -1;
    }
    if (!prompt) {
        prompt = "";
    }
    if (!g_stdio_is_tty) {
        fputs(prompt, stdout);
        fflush(stdout);
        if (!fgets(buf, buf_size, stdin)) {
            return 0;
        }
        return 1;
    }
    if (enable_raw_mode() < 0) {
        return -1;
    }
    write(STDOUT_FILENO, prompt, strlen(prompt));
    size_t len = 0;
    buf[0] = '\0';
    char scratch[buf_size];
    size_t scratch_len = 0;
    int have_scratch = 0;
    int history_index = (int)g_history_len;
    while (1) {
        char ch;
        ssize_t r = read(STDIN_FILENO, &ch, 1);
        if (r <= 0) {
            disable_raw_mode();
            return 0;
        }
        if (ch == '\n' || ch == '\r') {
            if (len + 1 < buf_size) {
                buf[len++] = '\n';
            }
            buf[len] = '\0';
            write(STDOUT_FILENO, "\r\n", 2);
            disable_raw_mode();
            return 1;
        }
        if (ch == 0x04) { /* Ctrl-D */
            if (len == 0) {
                disable_raw_mode();
                return 0;
            }
            continue;
        }
        if (ch == 0x7f || ch == 0x08) { /* Backspace */
            if (len > 0) {
                len--;
                buf[len] = '\0';
                write(STDOUT_FILENO, "\b \b", 3);
            }
            continue;
        }
        if (ch == 0x1b) { /* Escape sequence */
            char seq[2];
            if (read(STDIN_FILENO, seq, 2) != 2) {
                continue;
            }
            if (seq[0] != '[') {
                continue;
            }
            if (seq[1] == 'A') { /* Up */
                if (history_index > 0) {
                    if (!have_scratch) {
                        memcpy(scratch, buf, len + 1);
                        scratch_len = len;
                        have_scratch = 1;
                    }
                    history_index--;
                    load_history_entry(history_index, buf, buf_size, &len);
                    reset_line(buf, &len, buf_size, prompt);
                }
            } else if (seq[1] == 'B') { /* Down */
                if (history_index < (int)g_history_len) {
                    history_index++;
                    if (history_index == (int)g_history_len) {
                        if (have_scratch) {
                            memcpy(buf, scratch, scratch_len + 1);
                            len = scratch_len;
                        } else {
                            buf[0] = '\0';
                            len = 0;
                        }
                    } else {
                        load_history_entry(history_index, buf, buf_size, &len);
                    }
                    reset_line(buf, &len, buf_size, prompt);
                }
            }
            continue;
        }
        if (isprint((unsigned char)ch)) {
            if (len + 1 < buf_size) {
                buf[len++] = ch;
                buf[len] = '\0';
                write(STDOUT_FILENO, &ch, 1);
            }
            continue;
        }
    }
    /* Unreachable */
    disable_raw_mode();
    return -1;
}
