#ifndef DB_RUNTIME_H
#define DB_RUNTIME_H

#include "config.h"

int run_db_check(const char *const *keywords, const char *const *values, int only_id);
int build_merged_config(struct app_config *out_cfg, const int *ids, int id_count, const char *db_pass);

#endif
