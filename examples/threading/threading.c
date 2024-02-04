#include "threading.h"
#include <string.h>
#include <unistd.h>
#include <stdlib.h>
#include <stdio.h>

#define DEBUG_LOG(msg,...)
#define ERROR_LOG(msg,...) printf("threading ERROR: " msg "\n" , ##__VA_ARGS__)

void* threadfunc(void* thread_param) {
    struct thread_data* thread_func_args = (struct thread_data*)thread_param;
    
    usleep(thread_func_args->wait_to_obtain_ms * 1000);

    int mutex_result = pthread_mutex_lock(thread_func_args->mutex);
    if (mutex_result != 0) {
        ERROR_LOG("Failed to obtain mutex: %s", strerror(mutex_result));
        thread_func_args->thread_complete_success = false;
        return NULL;
    }

    usleep(thread_func_args->wait_to_release_ms * 1000);

    mutex_result = pthread_mutex_unlock(thread_func_args->mutex);
    if (mutex_result != 0) {
        ERROR_LOG("Failed to release mutex: %s", strerror(mutex_result));
        thread_func_args->thread_complete_success = false;
    } else {
        thread_func_args->thread_complete_success = true;
    }

    return thread_param;
}

bool start_thread_obtaining_mutex(pthread_t *thread, pthread_mutex_t *mutex, int wait_to_obtain_ms, int wait_to_release_ms) {
    struct thread_data *thread_args = (struct thread_data *)malloc(sizeof(struct thread_data));
    if (thread_args == NULL) {
        ERROR_LOG("Failed to allocate memory for thread_data");
        return false;
    }

    thread_args->mutex = mutex;
    thread_args->wait_to_obtain_ms = wait_to_obtain_ms;
    thread_args->wait_to_release_ms = wait_to_release_ms;

    int thread_create_result = pthread_create(thread, NULL, threadfunc, (void *)thread_args);
    if (thread_create_result != 0) {
        ERROR_LOG("Failed to create thread: %s", strerror(thread_create_result));
        free(thread_args);
        return false;
    }

    return true;
}
