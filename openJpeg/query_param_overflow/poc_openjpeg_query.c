#include "query_parser.h"

int main(void) {
    const char *q =
        "metareq=["
        "aaaa!;bbbb!;cccc!;dddd!;eeee!;"
        "ffff!;gggg!;hhhh!;iiii!;jjjj!;"
        "kkkk!"
        "]";

    query_param_t *p = parse_query(q);
    (void)p;
    return 0;
}
