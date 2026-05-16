#ifndef DB_CONFIG_H
#define DB_CONFIG_H

#include "config.h"

int config_load_from_db(struct app_config *cfg, int config_id, const char *conn_str);
int db_update_profile_identity(const char **keywords, const char **values, int profile_id, const char *fingerprint);

#endif
