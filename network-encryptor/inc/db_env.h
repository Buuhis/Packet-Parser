#ifndef DB_ENV_H
#define DB_ENV_H

void load_env_from_file(const char *path);
const char *resolve_db_password(void);
int parse_config_id_arg(const char *s, int *out);

#endif
