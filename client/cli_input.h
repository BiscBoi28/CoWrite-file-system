#ifndef CLI_INPUT_H
#define CLI_INPUT_H

#include <stddef.h>

void cli_input_init(void);
int cli_input_readline(const char *prompt, char *buf, size_t buf_size);
void cli_input_remember(const char *line);

#endif /* CLI_INPUT_H */
