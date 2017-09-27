/*
 * Copyright (c) 2017 Cisco and/or its affiliates.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at:
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#ifndef SRLB_PLUGIN_SRLB_SA_APACHE_H
#define SRLB_PLUGIN_SRLB_SA_APACHE_H

#include <srlb/srlb-sa.h>

#include <sys/types.h>
#include <sys/shm.h>
/*
 * apr_hashfunc_default() and our_ftok() from:
 * https://svn.apache.org/repos/asf/apr/apr/trunk/tables/apr_hash.c
 *
 * Licensed to the Apache Software Foundation (ASF) under one or more
 * contributor license agreements.  See the NOTICE file distributed with
 * this work for additional information regarding copyright ownership.
 * The ASF licenses this file to You under the Apache License, Version 2.0
 * (the "License"); you may not use this file except in compliance with
 * the License.  You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
static unsigned int apr_hashfunc_default(const char *char_key, ssize_t *klen)
{
  const unsigned char *key = (const unsigned char *)char_key;
  const unsigned char *p;
  ssize_t i;
  unsigned int hash = 0;

  for (p = key, i = *klen; i; i--, p++) {
    hash = hash * 33 + *p;
  }

  return hash;
}

static key_t our_ftok(const char *filename_orig, const char *filename)
{
  ssize_t slen = strlen(filename_orig);
  return ftok(filename, (int)apr_hashfunc_default(filename_orig, &slen));
}

/*
 * End from https://svn.apache.org/repos/asf/apr/apr/trunk/tables/apr_hash.c
 */

/*
 * From https://svn.apache.org/repos/asf/httpd/httpd/trunk/include/scoreboard.h
 *
 * Licensed to the Apache Software Foundation (ASF) under one or more
 * contributor license agreements.  See the NOTICE file distributed with
 * this work for additional information regarding copyright ownership.
 * The ASF licenses this file to You under the Apache License, Version 2.0
 * (the "License"); you may not use this file except in compliance with
 * the License.  You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
#define APACHE_VERSION 20120211
#define APR_HAS_THREADS 1
#define HAVE_TIMES 1
typedef __off64_t apr_off_t;
typedef uint32_t apr_uint32_t;
typedef time_t apr_time_t;
typedef pthread_t apr_os_thread_t;
#include <sys/times.h>

/* Scoreboard info on a process is, for now, kept very brief ---
 * just status value and pid (the latter so that the caretaker process
 * can properly update the scoreboard when a process dies).  We may want
 * to eventually add a separate set of long_score structures which would
 * give, for each process, the number of requests serviced, and info on
 * the current, or most recent, request.
 *
 * Status values:
 */

#define SERVER_DEAD 0
#define SERVER_STARTING 1       /* Server Starting up */
#define SERVER_READY 2          /* Waiting for connection (or accept() lock) */
#define SERVER_BUSY_READ 3      /* Reading a client request */
#define SERVER_BUSY_WRITE 4     /* Processing a client request */
#define SERVER_BUSY_KEEPALIVE 5 /* Waiting for more requests via keepalive */
#define SERVER_BUSY_LOG 6       /* Logging the request */
#define SERVER_BUSY_DNS 7       /* Looking up a hostname */
#define SERVER_CLOSING 8        /* Closing the connection */
#define SERVER_GRACEFUL 9       /* server is gracefully finishing request */
#define SERVER_IDLE_KILL 10     /* Server is cleaning up idle children. */
#define SERVER_NUM_STATUS 11    /* number of status settings */

/* Type used for generation indicies.  Startup and every restart cause a
 * new generation of children to be spawned.  Children within the same
 * generation share the same configuration information -- pointers to stuff
 * created at config time in the parent are valid across children.  However,
 * this can't work effectively with non-forked architectures.  So while the
 * arrays in the scoreboard never change between the parent and forked
 * children, so they do not require shm storage, the contents of the shm
 * may contain no pointers.
 */

typedef int ap_generation_t;
/* Is the scoreboard shared between processes or not?
 * Set by the MPM when the scoreboard is created.
 */
typedef enum {
    SB_NOT_SHARED = 1,
    SB_SHARED = 2
} ap_scoreboard_e;

/* stuff which is worker specific */
typedef struct worker_score worker_score;
struct worker_score {
#if APR_HAS_THREADS
    apr_os_thread_t tid;
#endif
    int thread_num;
    /* With some MPMs (e.g., worker), a worker_score can represent
     * a thread in a terminating process which is no longer
     * represented by the corresponding process_score.  These MPMs
     * should set pid and generation fields in the worker_score.
     */
    pid_t pid;
    ap_generation_t generation;
    unsigned char status;
    unsigned short conn_count;
    apr_off_t     conn_bytes;
    unsigned long access_count;
    apr_off_t     bytes_served;
    unsigned long my_access_count;
    apr_off_t     my_bytes_served;
    apr_time_t start_time;
    apr_time_t stop_time;
    apr_time_t last_used;
#ifdef HAVE_TIMES
    struct tms times;
#endif
#if APACHE_VERSION > 20130903
/* ad908355 include/scoreboard.h                 (Christophe Jaillet 2013-09-03 04:49:20 +0000 115) */
    char client[40];            /* Keep 'em small... but large enough to hold an IPv6 address */
#else
    char client[32];		/* Keep 'em small... */
#endif
    char request[64];           /* We just want an idea... */
    char vhost[32];             /* What virtual host is being accessed? */
#if APACHE_VERSION > 20160121
/* 1ffef9d4 include/scoreboard.h                 (Stefan Eissing     2016-01-21 16:36:33 +0000 118) */
    char protocol[16];          /* What protocol is used on the connection? */
#endif
};

typedef struct {
    int             server_limit;
    int             thread_limit;
    ap_generation_t running_generation; /* the generation of children which
                                         * should still be serving requests.
                                         */
    apr_time_t restart_time;
} global_score;

/* stuff which the parent generally writes and the children rarely read */
typedef struct process_score process_score;
struct process_score {
    pid_t pid;
    ap_generation_t generation; /* generation of this child */
    char quiescing;         /* the process whose pid is stored above is
                             * going down gracefully
                             */
    char not_accepting;     /* the process is busy and is not accepting more
                             * connections (for async MPMs)
                             */
    apr_uint32_t connections;       /* total connections (for async MPMs) */
    apr_uint32_t write_completion;  /* async connections doing write completion */
    apr_uint32_t lingering_close;   /* async connections in lingering close */
    apr_uint32_t keep_alive;        /* async connections in keep alive */
    apr_uint32_t suspended;         /* connections suspended by some module */
#if APACHE_VERSION > 20141007
/* f6f82bbc include/scoreboard.h                 (Yann Ylavic        2014-10-07 15:16:02 +0000 146) */
    int bucket;             /* Listener bucket used by this child */
#endif
};

/* Scoreboard is now in 'local' memory, since it isn't updated once created,
 * even in forked architectures.  Child created-processes (non-fork) will
 * set up these indicies into the (possibly relocated) shmem records.
 */
typedef struct {
    global_score *global;
    process_score *parent;
    worker_score **servers;
} scoreboard;

/*
 * End from https://svn.apache.org/repos/asf/httpd/sandbox/replacelimit/include/scoreboard.h
 */


#endif /* SRLB_PLUGIN_SRLB_SA_APACHE_H */
