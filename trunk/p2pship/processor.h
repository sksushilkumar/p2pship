/*
  p2pship - A peer-to-peer framework for various applications
  Copyright (C) 2007-2010  Helsinki Institute for Information Technology
  
  This program is free software; you can redistribute it and/or
  modify it under the terms of the GNU General Public License
  as published by the Free Software Foundation; either version 2
  of the License, or (at your option) any later version.
  
  This program is distributed in the hope that it will be useful,
  but WITHOUT ANY WARRANTY; without even the implied warranty of
  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
  GNU General Public License for more details.
  
  You should have received a copy of the GNU General Public License
  along with this program; if not, write to the Free Software
  Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.
*/
#ifndef __PROCESSOR_H__
#define __PROCESSOR_H__

#include <stdio.h>
#include <unistd.h>
#include <signal.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <arpa/inet.h>

#include "processor_config.h"

/* ..which are: */
typedef struct processor_worker_s processor_worker_t;
struct processor_worker_s {
	THREAD *thread;
	THREAD thread_data;
	char name[100];

	void (*start_func)(processor_worker_t*);
	void *data;
	void (*kill_func)(processor_worker_t*);
	void *extra;
};

/* a module of the system */
typedef struct processor_module_s
{
	int (*init) (processor_config_t *config);
	void (*close) (void);
	
	const char *name;
	const char *depends;
}
processor_module_t;

/* a processing queue item */
typedef struct processor_task_s processor_task_t;
struct processor_task_s 
{
        int (*func) (void *data, processor_task_t **wait, int wait_for_code);
        void (*cb_processor_complete) (void *qt, int code);

        void *data;
        int status_code;
	unsigned long created;
	int timeout;
	
        processor_task_t *wait_for;
	int wait_for_code;
};

/* the queued packets */
typedef struct processor_queued_packet_s
{
        char *target;
        char *data_packet;
}
processor_queued_packet_t;

/* struct for holding eventing info */
typedef struct processor_event_receiver_s {
	void (*func) (char *event, void *data, void *eventdata);
	char *event;
	void *data;
} processor_event_receiver_t;

/* todo: make into ship_obj */
typedef struct processor_to_thread_s {
	
	char *name;
	ship_list_t *task_queue;

	LOCK_DECL(lock);
	COND_DECL(cond);
	THREAD_DECL(thread);

	int running;
	int idle;

} processor_to_thread_t;

typedef struct processor_to_task_s {
	ship_obj_t parent;

	int ret;
	int (*func) (void *param);
	void *data;

	COND_DECL(cond);
	
	/* whether the task was performed successfully */
	int done;
	int valid;
} processor_to_task_t;

SHIP_INCLUDE_TYPE(processor_to_task);

/* inits the processor */
int processor_init(processor_config_t *config);

/* closes the processor & everyting */
void processor_close();
void processor_shutdown();

/* registers a new module */
void processor_register(processor_module_t *module);

/* inits just one module */
int processor_init_module(const char *module, processor_config_t *config);

/* inits all modules */
int processor_init_modules(processor_config_t *config);

/* starts the main loop of the processor */
int processor_run();

/* returns the config that is currently in use */
processor_config_t *processor_get_config();

/* the task interface */
processor_task_t * processor_tasks_add(int (*func) (void *data, processor_task_t **wait, int wait_for_code), 
				       void *data, void (*callback) (void *qt, int code));

processor_task_t *processor_tasks_add_timed(int (*func) (void *data, processor_task_t **wait, int wait_for_code), 
					    void *data, void (*callback) (void *qt, int code),
					    int secs);

/* processor_task_t *processor_tasks_add_timed(void (*callback) (void *qt, int code), */
/* 					    void *data, int secs); */
processor_task_t *processor_create_wait();
void processor_signal_wait(processor_task_t *wait, int status);

/* the event interface */
int processor_event_receive(char *event, void *data, 
			    void (*func) (char *event, void *data, void *eventdata));
void processor_event_deregister(char *event, void *data, 
				void (*func) (char *event, void *data, void *eventdata));
void processor_event_generate(char *event, void *eventdata, void (*callback) (char *event, void *eventdata));

void *processor_to_init(const char *name);
int processor_to(void *thread_id, 
		 int (*func) (void *param),
		 void (*cleanup) (void *param, int to_ret, int func_ret),
		 void *param,
		 int *function_ret,
		 int timeout_ms);

void processor_run_async(void (*func)(void));
int processor_tasks_add_periodic(int (*func) (void), int period);
void processor_kill_workers(const char *type);
int processor_create_worker(const char *type, void (*func)(processor_worker_t*), void *data,
			    void (*kill_func)(processor_worker_t*));


#define PROCESSOR_TO_ERROR -1
#define PROCESSOR_TO_STUCK -2
#define PROCESSOR_TO_DONE 0

#endif
