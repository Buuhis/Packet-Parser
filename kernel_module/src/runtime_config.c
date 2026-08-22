#include "runtime_config.h"

#include <pthread.h>

static pthread_mutex_t config_mutex = PTHREAD_MUTEX_INITIALIZER;
static uint64_t config_generation;

uint64_t runtime_config_begin_reload(uint64_t *previous_generation)
{
    uint64_t generation;

    pthread_mutex_lock(&config_mutex);
    if (previous_generation)
        *previous_generation = config_generation;
    config_generation++;
    if (config_generation == 0)
        config_generation++;
    generation = config_generation;
    pthread_mutex_unlock(&config_mutex);
    return generation;
}

void runtime_config_cancel_reload(uint64_t generation,
                                  uint64_t previous_generation)
{
    pthread_mutex_lock(&config_mutex);
    if (config_generation == generation)
        config_generation = previous_generation;
    pthread_mutex_unlock(&config_mutex);
}

void runtime_config_lock(void)
{
    pthread_mutex_lock(&config_mutex);
}

void runtime_config_unlock(void)
{
    pthread_mutex_unlock(&config_mutex);
}

bool runtime_config_generation_is_current_locked(uint64_t generation)
{
    return generation != 0 && generation == config_generation;
}
