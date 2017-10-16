/*****************************************************************************
 * Copyright (C) Queen's University Belfast, ECIT, 2016                      *
 *                                                                           *
 * This file is part of libsafecrypto.                                       *
 *                                                                           *
 * This file is subject to the terms and conditions defined in the file      *
 * 'LICENSE', which is part of this source code package.                     *
 *****************************************************************************/

/*
 * Git commit information:
 *   Author: $SC_AUTHOR$
 *   Date:   $SC_DATE$
 *   Branch: $SC_BRANCH$
 *   Id:     $SC_IDENT$
 */

#include "safecrypto_private.h"
#include "threading.h"


#ifdef SAFECRYPTO_WINDOWS

sc_mutex_t * mutex_create_windows(void);
void mutex_destroy_windows(sc_mutex_t **mtx);
SINT32 mutex_trylock_windows(sc_mutex_t *mtx);
SINT32 mutex_lock_windows(sc_mutex_t *mtx);
SINT32 mutex_unlock_windows(sc_mutex_t *mtx);

#else // SAFECRYPTO_POSIX

sc_mutex_t * mutex_create_posix(void);
void mutex_destroy_posix(sc_mutex_t **mtx);
SINT32 mutex_trylock_posix(sc_mutex_t *mtx);
SINT32 mutex_lock_posix(sc_mutex_t *mtx);
SINT32 mutex_unlock_posix(sc_mutex_t *mtx);

sc_sem_t * sem_create_posix(UINT32 value);
void sem_destroy_posix(sc_sem_t **sem);
SINT32 sem_trywait_posix(sc_sem_t *sem);
SINT32 sem_wait_posix(sc_sem_t *sem);
SINT32 sem_post_posix(sc_sem_t *sem);

sc_cond_t * cond_create_posix(void);
void cond_destroy_posix(sc_cond_t **cond);
SINT32 cond_signal_posix(sc_cond_t *cond);
SINT32 cond_broadcast_posix(sc_cond_t *cond);
SINT32 cond_wait_posix(sc_cond_t *cond, sc_mutex_t *mtx);

sc_thread_t * thread_create_posix(void * (*routine)(void *),
    void *argument, SINT32 cpu);
void thread_destroy_posix(sc_thread_t **thd);
SINT32 thread_join_posix(sc_thread_t *thd);
SINT32 thread_exit_posix(void);

#endif


static const utils_threading_t utils_threading_table = {
    mutex_create_posix, mutex_destroy_posix, mutex_trylock_posix,
    mutex_lock_posix, mutex_unlock_posix,
    sem_create_posix, sem_destroy_posix, sem_trywait_posix,
    sem_wait_posix, sem_post_posix,
    cond_create_posix, cond_destroy_posix, cond_signal_posix,
    cond_broadcast_posix, cond_wait_posix,
    thread_create_posix, thread_destroy_posix, thread_join_posix, thread_exit_posix
};


const utils_threading_t *utils_threading(void)
{
	return &utils_threading_table;
}



#ifdef SAFECRYPTO_POSIX
//-------------------------------- MUTEX ------------------------------------//

sc_mutex_t * mutex_create_posix(void)
{
	sc_mutex_t *sc_mtx = SC_MALLOC(sizeof(sc_mutex_t));
    if (NULL == sc_mtx) {
        return NULL;
    }

	if (pthread_mutex_init(&sc_mtx->m, NULL) != 0) {
        SC_FREE(sc_mtx, sizeof(sc_mutex_t));
		return NULL;
    }
	else
		return sc_mtx;
}

void mutex_destroy_posix(sc_mutex_t **mtx)
{
	sc_mutex_t *sc_mtx = *mtx;
	pthread_mutex_destroy(&sc_mtx->m);
	SC_FREE(*mtx, sizeof(sc_mutex_t));
}

SINT32 mutex_trylock_posix(sc_mutex_t *mtx)
{
	if (0 != pthread_mutex_trylock(&mtx->m))
		return SC_FAILED_LOCK;
	else
		return SC_OK;
}

SINT32 mutex_lock_posix(sc_mutex_t *mtx)
{
	if (0 != pthread_mutex_lock(&mtx->m))
		return SC_FAILED_LOCK;
	else
		return SC_OK;
}

SINT32 mutex_unlock_posix(sc_mutex_t *mtx)
{
	if (0 != pthread_mutex_unlock(&mtx->m))
		return SC_FAILED_LOCK;
	else
		return SC_OK;
}


//------------------------------ SEMAPHORE ----------------------------------//

sc_sem_t * sem_create_posix(UINT32 value)
{
    sc_sem_t *sc_sem = SC_MALLOC(sizeof(sc_sem_t));
    if (NULL == sc_sem) {
        return NULL;
    }

    if (sem_init(&sc_sem->s, 0, value) != 0) {
        SC_FREE(sc_sem, sizeof(sc_sem_t));
        return NULL;
    }
    else
        return sc_sem;
}

void sem_destroy_posix(sc_sem_t **sem)
{
    sc_sem_t *sc_sem = *sem;
    sem_destroy(&sc_sem->s);
    SC_FREE(*sem, sizeof(sc_sem_t));
}

SINT32 sem_trywait_posix(sc_sem_t *sem)
{
    if (0 != sem_trywait(&sem->s))
        return SC_FAILED_LOCK;
    else
        return SC_OK;
}

SINT32 sem_wait_posix(sc_sem_t *sem)
{
    if (0 != sem_wait(&sem->s))
        return SC_FAILED_LOCK;
    else
        return SC_OK;
}

SINT32 sem_post_posix(sc_sem_t *sem)
{
    if (0 != sem_post(&sem->s))
        return SC_FAILED_LOCK;
    else
        return SC_OK;
}


//-------------------------- CONDITION VARIABLE -----------------------------//

sc_cond_t * cond_create_posix(void)
{
    sc_cond_t *sc_cond = SC_MALLOC(sizeof(sc_cond_t));
    if (NULL == sc_cond) {
        return NULL;
    }

    if (0 != pthread_cond_init(&sc_cond->c, NULL)) {
        SC_FREE(sc_cond, sizeof(sc_cond_t));
        return NULL;
    }
    else
        return sc_cond;
}

void cond_destroy_posix(sc_cond_t **cond)
{
    sc_cond_t *sc_cond = *cond;
    pthread_cond_destroy(&sc_cond->c);
    SC_FREE(*cond, sizeof(sc_cond_t));
}

SINT32 cond_signal_posix(sc_cond_t *cond)
{
    if (0 != pthread_cond_signal(&cond->c))
        return SC_FAILED_LOCK;
    else
        return SC_OK;
}

SINT32 cond_broadcast_posix(sc_cond_t *cond)
{
    if (0 != pthread_cond_broadcast(&cond->c))
        return SC_FAILED_LOCK;
    else
        return SC_OK;
}

SINT32 cond_wait_posix(sc_cond_t *cond, sc_mutex_t *mtx)
{
    if (0 != pthread_cond_wait(&cond->c, &mtx->m))
        return SC_FAILED_LOCK;
    else
        return SC_OK;
}


//------------------------------- THREADS -----------------------------------//

sc_thread_t * thread_create_posix(void * (*routine)(void *),
    void *arguments, SINT32 cpu)
{
    sc_thread_t *thd = SC_MALLOC(sizeof(sc_thread_t));
    if (NULL == thd) {
        return NULL;
    }

    thd->thread = SC_MALLOC(sizeof(pthread_t));
    if (NULL == thd->thread) {
        SC_FREE(thd, sizeof(sc_thread_t));
        return NULL;
    }

    pthread_attr_t attr;
    pthread_attr_init(&attr);

    // If CPU pinning is enabled then assign the processor to this thread
    if (-1 != cpu) {
        cpu_set_t cpus;
        CPU_ZERO(&cpus);
        CPU_SET(cpu, &cpus);
        if (0 != pthread_attr_setaffinity_np(&attr, sizeof(cpu_set_t), &cpus)) {
            return NULL;
        }
    }

    // Create the thread with the defined attributes
    if (0 != pthread_create(thd->thread, &attr, routine, (void*) arguments)) {
        return NULL;
    }

    pthread_attr_destroy(&attr);

    // Return a pointer to the thread that has been created
    return thd;
}

void thread_destroy_posix(sc_thread_t **thd)
{
    sc_thread_t *sc_thd = *thd;
    SC_FREE(sc_thd->thread, sizeof(sizeof(pthread_t)));
    SC_FREE(*thd, sizeof(sc_thread_t));
}

SINT32 thread_join_posix(sc_thread_t *thd)
{
    if (0 != pthread_join(*thd->thread, NULL)) {
        return SC_THREAD_ERROR;
    }

    return SC_OK;
}

SINT32 thread_exit_posix(void)
{
    pthread_exit(NULL);
    return SC_OK;
}


#else // SAFECRYPTO_WINDOWS
//-------------------------------- MUTEX ------------------------------------//

sc_mutex_t * mutex_create_windows(void)
{
	sc_mutex_t *sc_mtx = SC_MALLOC(sizeof(sc_mutex_t));
	sc_mtx->m = CreateMutex(NULL, FALSE, NULL);
	return sc_mtx;
}

void mutex_destroy_windows(sc_mutex_t **mtx)
{
	sc_mutex_t *sc_mtx = *mtx;
	CloseHandle(sc_mtx->m)
	SC_FREE(*mtx, sizeof(sc_mutex_t));
}

SINT32 mutex_trylock_windows(sc_mutex_t *mtx)
{
	if (WAIT_OBJECT_0 == WaitForSingleObject(m, 0))
		return SC_OK;
	else
		return SC_FAILED_LOCK;
}

SINT32 mutex_lock_windows(sc_mutex_t *mtx)
{
	WaitForSingleObject(mtx->m, INFINITE);
	return SC_OK;
}

SINT32 mutex_unlock_windows(sc_mutex_t *mtx)
{
	ReleaseMutex(mtx->m);
	return SC_OK;
}


//-------------------------- CONDITION VARIABLE -----------------------------//

/// @todo Add support for condition variables under Windows

//------------------------------- THREADS -----------------------------------//

/// @todo Add support for threads under Windows


#endif


