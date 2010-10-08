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
#include <stdio.h>
#include <unistd.h>
#include <signal.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <sys/time.h>

#include "processor.h"
#ifdef CONFIG_SIP_ENABLED
#include "sipp.h"
#endif
#include "ship_debug.h"
#include "ship_utils.h"
#include "ident.h"

#ifdef CONFIG_PYTHON_ENABLED
#include "pymod.h"
#endif

#ifdef CONFIG_START_GTK
#include <glib.h>
#include <gtk/gtk.h>
#include <gdk/gdk.h>
#endif


/* the configuration for the current .. */
static processor_config_t *pconfig;

/* the event queue list */
static ship_list_t *processor_tasks = NULL;
STATIC_LOCK_DECL(processor_tasks_lock);
STATIC_COND_DECL(processor_tasks_cond);

/* whether we should be alive still */
static int processor_alive = 0;

/* the worker threads */
static ship_list_t *processor_workers = 0;

/* the global wait */
static unsigned long global_wakeup = 0;

/* queue for storing pending async events */
static ship_list_t *queued_tasks = NULL;
static ship_list_t *being_processed_tasks = NULL;

/* queue for storing completed tasks that other might depend on */
static ship_list_t *completed_tasks = NULL;
static int task_in_process = 0;

/* events */
static ship_list_t *event_receivers = 0;

/* workders */
static int worker_threads = 0;

/* the modules */
static ship_list_t *modules = 0;
static ship_list_t *active_modules = 0;

/* the to threads */
static ship_list_t *to_threads = 0;
static ship_list_t *dead_threads = 0;

static void processor_to_free(void *data);
static int processor_to_cleanup_dead(void *data, processor_task_t **wait, int wait_for_code);


static void
processor_event_free(processor_event_receiver_t* ret)
{
	if (ret) {
		freez(ret->event);
		freez(ret);
	}
}

static processor_event_receiver_t*
processor_event_new(char *event, void *data, 
		    void (*func) (char *event, void *data, void *eventdata))
{
	processor_event_receiver_t* ret = 0;
	ASSERT_TRUE(ret = mallocz(sizeof(processor_event_receiver_t)), err);
	ASSERT_TRUE(ret->event = strdup(event), err);
	ret->data = data;
	ret->func = func;
	return ret;
 err:
	processor_event_free(ret);
	return 0;
}

/* frees an entry */
static void 
processor_tasks_free(processor_task_t *qt)
{
        /* free the data .. */
        if (qt->data && qt->cb_processor_complete) {
                qt->cb_processor_complete(qt->data, -1);
        }
	LOG_VDEBUG("free'd task %08x\n", qt);
        free(qt);
}

static processor_task_t *
processor_tasks_new(int (*func) (void *data, processor_task_t **wait, int wait_for_code), void *data, 
                     void (*callback) (void *qt, int code))
{
        processor_task_t *qt;
        if (!processor_alive)
                return NULL;

        if ((qt = (processor_task_t*)mallocz(sizeof(processor_task_t)))) {
		LOG_VDEBUG("created task %08x\n", qt);
                qt->func = func;
                qt->data = data;
                qt->cb_processor_complete = callback;
		qt->created = ship_systemtimemillis();
		qt->timeout = 60000; /* one minute? */
        }
	return qt;
}

processor_task_t *
processor_tasks_add(int (*func) (void *data, processor_task_t **wait, int wait_for_code), 
		    void *data, 
		    void (*callback) (void *qt, int code))
{
        processor_task_t *qt;
        if ((qt = processor_tasks_new(func, data, callback))) {
                SYNCHRONIZE_SIGNAL(processor_tasks_lock, processor_tasks_cond, 
				   ship_list_add(processor_tasks, qt) );
		LOG_VDEBUG("added task %08x to active list\n", qt);
        }
        return qt;
}

static int
processor_run_async_do(void *data, processor_task_t **wait, int wait_for_code)
{
	void (*func)(void) = data;
	func();
	return 0;
}

void
processor_run_async(void (*func)(void))
{
	processor_tasks_add(processor_run_async_do, func, NULL);
}

/* runs a periodic task */
static int
processor_tasks_run_periodic(void *data, processor_task_t **wait, int wait_for_code)
{
	int (*func) (void) = data;
	if (func())
		return 0;
	else
		return 1;
}

int
processor_tasks_add_periodic(int (*func) (void), int period)
{
	int ret = -1;
	processor_task_t *task = 0;
	ASSERT_TRUE(task = processor_tasks_add_timed(processor_tasks_run_periodic,
						     func, NULL, period), err);
	ret = 0;
 err:
	return ret;
}

/*
processor_task_t *
processor_tasks_add_timed(void (*callback) (void *qt, int code),
			  void *data,
			  int msecs)
{
        processor_task_t *qt;
        if (qt = processor_tasks_new(NULL, data, callback)) {
		qt->timeout = msecs;
                SYNCHRONIZE_SIGNAL(processor_tasks_lock, processor_tasks_cond, 
                                   ship_list_add(queued_tasks, qt));
		LOG_VDEBUG("added task %08x to queued\n", qt);
        }
        return qt;
}
*/

processor_task_t *processor_tasks_add_timed(int (*func) (void *data, processor_task_t **wait, int wait_for_code), 
					    void *data, void (*callback) (void *qt, int code),
					    int msecs)
{
        processor_task_t *qt;
        if ((qt = processor_tasks_new(func, data, callback))) {
		qt->timeout = msecs;
                SYNCHRONIZE_SIGNAL(processor_tasks_lock, processor_tasks_cond, 
                                   ship_list_add(queued_tasks, qt));
		LOG_VDEBUG("added task %08x to queued\n", qt);
        }
        return qt;
}

processor_task_t *
processor_queue_add(int (*func) (void *data, processor_task_t **wait, int wait_for_code), 
                    void *data, 
                    processor_task_t *wait,
                    void (*callback) (void *qt, int code))
{
        processor_task_t *qt;
        if ((qt = processor_tasks_new(func, data, callback))) {
                qt->wait_for = wait;
                SYNCHRONIZE_SIGNAL(processor_tasks_lock, processor_tasks_cond,
                                   ship_list_add(queued_tasks, qt));
		LOG_VDEBUG("added task %08x to queued\n", qt);
        }
        return qt;
}

/* creates an empty, 'dummy' event used when the async task we are
   waiting for doesn't really fit into the event-structure. E.g. when
   sending data, create one, when receiving, signal it (=the 'task'
   done) */
processor_task_t *
processor_create_wait()
{
        return processor_queue_add(NULL, NULL, NULL, NULL);
}

/* signals that an empty-event task has been completed with the given 
   error code. This should normally not be 1, as it will make the
   task remain queued */
void 
processor_signal_wait(processor_task_t *wait, int status)
{
        int f = 0;
	void *ptr = 0, *last = 0;
	processor_task_t *tqt;
	if (!processor_tasks_lock || !wait)
		return;

        SYNCHRONIZE(processor_tasks_lock, {
			while ((tqt = ship_list_next(queued_tasks, &ptr))) {
                        if (tqt == wait){
                                ship_list_remove(queued_tasks, tqt);
				if (!f) {
					/* add only once, but remove from queue all instances.. */
					wait->status_code = status;
					ship_list_add(processor_tasks, tqt);
					f = 1;
				}
				ptr = last;
			} else
				last = ptr;
                }
        });
	
        COND_WAKEUP(processor_tasks_cond, processor_tasks_lock);
}


/* executes the func, queues for async execution if it goes into
   wait */
int
processor_exec_async(int (*func) (void *data, processor_task_t **wait, int wait_for_code), 
                     void *data, processor_task_t **wait, 
                     void (*callback) (void *qt, int code))
{
        processor_task_t *wait2 = NULL;
        int ret = func(data, &wait2, 0);
        if (ret == 1) {
                /* put on queue for wait, not execution */
                (*wait) = processor_queue_add(func, data, wait2, callback);
                if (!(*wait))
                        ret = -1;
                else
                        return 1;
        }
        
        callback(data, ret);
        return ret;
}

/* interrupts & shutdowns the processor and all submodules */
void
processor_shutdown()
{
	if (processor_alive) {
		processor_alive = 0;
		LOG_DEBUG("interrupting all workers..\n");
		COND_WAKEUP_ALL(processor_tasks_cond, processor_tasks_lock);
		LOG_DEBUG("interrupted\n");
#ifdef CONFIG_START_GTK
		gtk_exit(0);
#endif
	} else {
		LOG_WARN("forcing exit\n");
		exit(0);
	}
}

static void
processor_signal_handler(int signum)
{
        switch (signum) {
        case SIGHUP:
        case SIGINT:
        case SIGQUIT:
        case SIGTERM:
                LOG_WARN("termination request (signal %d) received\n", signum);
		processor_shutdown();
                break;
		//case SIGSEGV:
	case SIGCHLD:
		LOG_WARN("got signal %d for to thread\n", signum);
		TREAD_EXIT();
		break;
        default:
                LOG_WARN("unknown signal %d received, ignoring\n", signum);
                break;
        }
}

/* fetches a module from an array */
static processor_module_t *
processor_get_module_from(const char *name, ship_list_t *list)
{
	void *ptr = 0;
	processor_module_t *mod = 0;
	while ((mod = ship_list_next(list, &ptr))) {
		if (!strcmp(mod->name, name))
			return mod;
	}
	return 0;
}

/* registers a new module */
void
processor_register(processor_module_t *module)
{
	ship_list_add(modules, module);
}

/* inits just one module */
int 
processor_init_module(const char *name, processor_config_t *config)
{
	/* move the module to the queue-for-init */
	char **tokens = 0;
	int toklen = 0;
	int ret = -1;
	int i;
	ship_list_t *queue = ship_list_new();
	processor_module_t *mod = 0;
	ASSERT_TRUE(queue, err);

	LOG_DEBUG("initing module %s\n", name);

	/* go throught the queue-for-init, init all that  */
	if (processor_get_module_from(name, active_modules)) {
		ret = 0;
		goto err;
	}
	
	ASSERT_TRUE(mod = processor_get_module_from(name, modules), err);
	ship_list_add(queue, mod);
	while ((mod = ship_list_pop(queue))) {
		int dep = 0;
		
		/* check deps */
		ASSERT_ZERO(ship_tokenize_trim(mod->depends, strlen(mod->depends), &tokens, &toklen, ','), err);
		for (i = 0; i < toklen; i++) {
			processor_module_t *mod2 = 0;
			if (strlen(tokens[i]) && !processor_get_module_from(tokens[i], active_modules)) {
				dep = 1;
				if (!processor_get_module_from(tokens[i], queue)) {
					if (!(mod2 = processor_get_module_from(tokens[i], modules))) {
						LOG_ERROR("Could not find module '%s', needed by '%s'\n", tokens[i], mod->name);
						ASSERT_TRUE(0, err);
					}
					ship_list_add(queue, mod2);
				}
			}
		}
		
		if (dep) {
			ship_list_add(queue, mod);
		} else {
			LOG_DEBUG("Initing %s..\n", mod->name);
			ASSERT_ZERO(mod->init(config), err);
			LOG_VDEBUG("%s initialized ok\n", mod->name);
			ship_list_add(active_modules, mod);
		}
		ship_tokens_free(tokens, toklen);
		tokens = 0;
		toklen = 0;
	}

	ret = 0;
 err:
	ship_list_free(queue);
	ship_tokens_free(tokens, toklen);
	return ret;
}

/* inits all modules */
int 
processor_init_modules(processor_config_t *config)
{
	void *ptr = 0;
	processor_module_t *mod;
	while ((mod = ship_list_next(modules, &ptr))) {
		int ret = processor_init_module(mod->name, config);
		if (ret)
			return ret;
	}
	return 0;
}

processor_config_t *
processor_get_config()
{
	return pconfig;
}

/* Starts up the processor */
int 
processor_init(processor_config_t *config)
{	
        LOG_INFO("initing processor..\n");

        ASSERT_TRUE(queued_tasks = ship_list_new(), err);
        ASSERT_TRUE(processor_tasks = ship_list_new(), err);
	ASSERT_TRUE(event_receivers = ship_list_new(), err);
	ASSERT_TRUE(completed_tasks = ship_list_new(), err);
	ASSERT_TRUE(being_processed_tasks = ship_list_new(), err);
		
	ASSERT_TRUE(modules = ship_list_new(), err);
	ASSERT_TRUE(active_modules = ship_list_new(), err);
	ASSERT_TRUE(to_threads = ship_list_new(), err);
	ASSERT_TRUE(dead_threads = ship_list_new(), err);

        LOCK_INIT(processor_tasks_lock);
        ASSERT_TRUE(processor_tasks_lock, err);
        COND_INIT(processor_tasks_cond);
        ASSERT_TRUE(processor_tasks_cond, err);

	ASSERT_TRUE(processor_workers = ship_list_new(), err);
	
	/* todo: init the dynamic configuraiton? */
	ASSERT_ZERO(processor_config_init(), err);

        pconfig = config;

        /* if more than 1 thread, create those */
        if (!processor_config_get_int(pconfig, P2PSHIP_CONF_WORKER_THREADS, &worker_threads)) {
	    
#ifdef CONFIG_START_GTK
		/* if gtk should be started, reserve one thread for it */
		worker_threads++;
#elif CONFIG_PYTHON_ENABLED
		if (processor_config_is_true(config, P2PSHIP_CONF_START_SHELL))
			worker_threads++;
#endif
	}
	
        processor_alive = 1;
        return 0;
 err:
        return -1;
}

static void
processor_kill_worker(processor_worker_t *w)
{
	if (w && w->thread) {
		if (w->kill_func) {
			LOG_INFO("trying to kill [%s]\n", w->name);
			w->kill_func(w);
		}
		if (w->thread) {
			THREAD_JOIN(w->thread);
		}
	}
	freez(w);
}

void
processor_kill_workers(const char *type)
{
        /* wait for all threads to close */
        if (processor_workers) {
		processor_worker_t *w;
		void *ptr = 0, *last = 0;
		while ((w = ship_list_next(processor_workers, &ptr))) {
			if (str_startswith(w->name, type)) {
				ship_list_remove(processor_workers, w);
				processor_kill_worker(w);
				ptr = last;
			}
			last = ptr;
		}
        }
}

void 
processor_close()
{
        int i;
        
        LOG_DEBUG("closing processor..\n");
	if (processor_alive)
		processor_shutdown();
        processor_alive = 0;
        
	ship_list_empty_with(to_threads, processor_to_free);
	ship_list_free(to_threads);
	ship_list_empty_with(dead_threads, processor_to_cleanup_dead);
	ship_list_free(dead_threads);

        /* wait for all threads to close */
        if (processor_workers) {
		processor_kill_workers("");
		ship_list_free(processor_workers);
		processor_workers = NULL;
        }

	/* now, go through all the active modules and close them. in
	   reverse order! */
	if (active_modules) {
		processor_module_t *mod = 0;
		for (i = ship_list_length(active_modules)-1; i > -1; i--) {
			mod = ship_list_get(active_modules, i);
			LOG_DEBUG("closing module %s\n", mod->name);
			mod->close();
		}
		ship_list_free(active_modules);
	}

	/* free the modules, active modules lists */
	if (modules) {
		ship_list_free(modules);
	}

        SYNCHRONIZE(processor_tasks_lock, {
                while (processor_tasks && ship_list_first(processor_tasks))
                        processor_tasks_free((processor_task_t*)ship_list_pop(processor_tasks));
                    
                while (queued_tasks && ship_list_first(queued_tasks))
                        processor_tasks_free((processor_task_t *)ship_list_pop(queued_tasks));

                while (completed_tasks && ship_list_first(completed_tasks))
                        processor_tasks_free((processor_task_t *)ship_list_pop(completed_tasks));

                ship_list_free(processor_tasks);
                ship_list_free(completed_tasks);
                ship_list_free(queued_tasks);
                ship_list_free(being_processed_tasks);
                processor_tasks = 0;
                queued_tasks = 0; 
                completed_tasks = 0; 
        });

	/* free up the eventing stuff */
	if (event_receivers) {
		while (ship_list_first(event_receivers))
			processor_event_free(ship_list_pop(event_receivers));
		ship_list_free(event_receivers);
		event_receivers = 0;
	}

        LOCK_FREE(processor_tasks_lock);
        COND_FREE(processor_tasks_cond);

	processor_config_close();
        LOG_DEBUG("closed\n");
}

static void
processor_thread_run(processor_worker_t* data)
{
        while (processor_alive) {
                processor_task_t *qt = 0;
                int i;
		unsigned long now, wakeup = 0;

		LOCK_ACQ(processor_tasks_lock);
		now = ship_systemtimemillis();
		
		if (processor_alive) {
			/* check for timed-out ones */
			for (i=0; i < ship_list_length(queued_tasks); i++) {
				processor_task_t *tqt;
				unsigned long wu;
				int waittime;

				tqt = ship_list_get(queued_tasks, i);
				wu = tqt->created + (long)tqt->timeout;
				waittime = wu - now;
					
				if (waittime < 1) {
					tqt->status_code = -10; /* timed out! */
					ship_list_remove(queued_tasks, tqt);
					ship_list_add(processor_tasks, tqt);
					i--;
				} else if (wakeup == 0 || wakeup > wu) {
					wakeup = wu;
				}
			}

			/* retrieve next for processing.. */
			qt = ship_list_pop(processor_tasks);
			if (!qt) {
				if (wakeup > 0 && (global_wakeup > wakeup || global_wakeup == 0)) {
					global_wakeup = wakeup;
					now = ship_systemtimemillis();
					while (!qt && (now < wakeup) && processor_alive) {
						COND_WAITUNTIL_MS(processor_tasks_cond, processor_tasks_lock, 
								  wakeup - now + 10);
							
						now = ship_systemtimemillis();
						qt = ship_list_first(processor_tasks);
					}
					if (global_wakeup == wakeup)
						global_wakeup = 0;
				} else {
					COND_WAIT(processor_tasks_cond, processor_tasks_lock);
				}
				if (processor_alive) {
					qt = ship_list_pop(processor_tasks);
				}
			}
		}

		if (qt)
			ship_list_add(being_processed_tasks, qt);
		LOCK_RELEASE(processor_tasks_lock);
			
                if (processor_alive && qt) {

                        /* process tq. should return 0 on processed, < 0 on error, 1 on
                           'pending' (do not delete the data yet!) */                        

			ship_lock(completed_tasks);
			task_in_process++;
			ship_unlock(completed_tasks);
				
                        LOG_VDEBUG("processing an event...\n");
                        if (qt->func)
                                qt->status_code = qt->func(qt->data, &(qt->wait_for), qt->wait_for_code);

			/* debugging: check that we do not have any restricts any more!
			   ..that would mean an un-released lock */
			ship_check_restricts();
			
                        LOG_VDEBUG("event processed with return value %d\n", qt->status_code);
                        if (qt->status_code == 1) {
				processor_task_t *tqt = 0;
				
				/* check if the task this is waiting for has already completed */
				ship_lock(completed_tasks);
				if (qt->wait_for) {
					if ((tqt = ship_list_find(completed_tasks, qt->wait_for))) {
						qt->wait_for_code = tqt->status_code;
					} else {
						/* check nr.2: check also that the task is a valid one! */
						LOCK_ACQ(processor_tasks_lock);
						if (!ship_list_find(processor_tasks, qt->wait_for) &&
						    !ship_list_find(queued_tasks, qt->wait_for) &&
						    !ship_list_find(being_processed_tasks, qt->wait_for)) {
							LOG_ERROR("found an invalid task-dependency (waiting for %08x)!\n",
								  qt->wait_for);
							
							qt->wait_for_code = -10;
							tqt = (void*)1; /* just something */
						}
						LOCK_RELEASE(processor_tasks_lock);
					}
				}
				
				/* queue or execute */
				if (tqt) {
					SYNCHRONIZE(processor_tasks_lock, ship_list_add(processor_tasks, qt));
				} else {
					qt->created = ship_systemtimemillis();
					SYNCHRONIZE(processor_tasks_lock, ship_list_add(queued_tasks, qt));
				}
				ship_unlock(completed_tasks);
                        } else {
				/* do the finalization first! */
                                if (qt->cb_processor_complete)
                                        qt->cb_processor_complete(qt->data, qt->status_code);

                                /* go through queued events, check for wait_for:s */
				ship_lock(completed_tasks);
				SYNCHRONIZE(processor_tasks_lock, {
                                        for (i=0; i < ship_list_length(queued_tasks); i++) {
                                                processor_task_t *tqt;
                                                
                                                tqt = ship_list_get(queued_tasks, i);
                                                if (tqt->wait_for == qt){
                                                        ship_list_remove(queued_tasks, tqt);
                                                        ship_list_add(processor_tasks, tqt);
							tqt->wait_for_code = qt->status_code;
                                                        i--;
                                                }
                                        }
                                });
                                
				qt->cb_processor_complete = NULL;
                                qt->data = NULL;
				ship_list_add(completed_tasks, qt);
				ship_unlock(completed_tasks);
			}

			/* empty the stack of already-completed tasks if there are no in-progress tasks */
			ship_lock(completed_tasks);
			task_in_process--;
			if (task_in_process == 0) {
				while (ship_list_first(completed_tasks)) {
					processor_tasks_free(ship_list_pop(completed_tasks));
				}
			}
			ship_unlock(completed_tasks);
                }

		if (qt)
			ship_list_remove(being_processed_tasks, qt);
        }
}


/* wrapper around the workers */
static void*
processor_worker_runner(void *data)
{
	processor_worker_t *w = data;
	LOG_INFO("worker [%s] alive\n", w->name);
	w->start_func(w);
	LOG_INFO("worker [%s] died\n", w->name);
	return NULL;
}

int
processor_create_worker(const char *type, void (*func)(processor_worker_t*), void *data,
			void (*kill_func)(processor_worker_t*))
{
	processor_worker_t *w = NULL;
	int ret = -1;
	
	ASSERT_TRUE(w = mallocz(sizeof(*w)), err);
	sprintf(w->name, "%s-%d", type, ship_list_length(processor_workers));
	w->thread = &w->thread_data;
	w->data = data;
	w->kill_func = kill_func;
	w->start_func = func;
	
	LOG_DEBUG("trying to create worker [%s]..\n", w->name);
	ASSERT_ZERO(THREAD_RUN(w->thread, processor_worker_runner, (void*)w), err);
	ship_list_add(processor_workers, w);
	w = 0;
	ret = 0;
 err:
	freez(w);
	return ret;
}

int 
processor_run()
{
        int i, ret = -1;
#ifndef CONFIG_START_GTK
	struct processor_worker_s main_w = { .thread = 0, .name = "main-0" };
#endif

	USER_ERROR("proxy initialized ok\n");
        
        /* set up signal blocking */
        signal(SIGHUP, processor_signal_handler);
        signal(SIGINT, processor_signal_handler);
        signal(SIGQUIT, processor_signal_handler);
        signal(SIGTERM, processor_signal_handler);
        signal(SIGPIPE, processor_signal_handler);
	signal(SIGCHLD, processor_signal_handler);

        /* if more than 1 thread, create those */
        for (i=0; i < worker_threads-1; i++) {
		ASSERT_ZERO(processor_create_worker("worker", processor_thread_run, NULL, NULL), err);
        }

#ifdef CONFIG_PYTHON_ENABLED
	ASSERT_ZERO(pymod_start_plugins(), err);
#endif
        
#ifdef CONFIG_START_GTK
        LOG_INFO("processor [%s] dedicated to gtk\n", "main-0");
	gtk_main();
	gdk_threads_leave();
#elif CONFIG_PYTHON_ENABLED
	if (processor_config_is_true(processor_get_config(), P2PSHIP_CONF_START_SHELL))
		pymod_shell();
	else
		processor_thread_run(&main_w);
#else
	processor_thread_run(&main_w);
#endif
	ret = 0;
 err:
	if (processor_alive)
		processor_shutdown();
        return ret;
}

int 
processor_event_receive(char *event, void *data, 
			void (*func) (char *event, void *data, void *eventdata))
{
	processor_event_receiver_t* evt = processor_event_new(event, data, func);
	if (evt && event_receivers) {
		ship_list_add(event_receivers, evt);
		LOG_DEBUG("added receiver for event(s) %s\n", event);
		return 0;
	} else
		return -1;
}

void 
processor_event_deregister(char *event, void *data, 
			   void (*func) (char *event, void *data, void *eventdata))
{
	/* this should be better sync'd with the events_generate_do function */
	/*
	void *ptr = 0, *last = 0;
	processor_event_receiver_t* evt = 0;
	ship_list_sync(event_receivers, {
		while (evt = ship_list_next(event_receivers, &ptr)) {
			if (!strcmp(evt->event, event) && evt->data == data &&
			    evt->func == func) {
				ship_list_remove(event_receivers, evt);
				processor_event_free(evt);
				ptr = last;
			} else
				last = ptr;
		}
	});
	*/
}

static int 
processor_event_generate_do(void *data, processor_task_t **wait, int wait_for_code)
{
	void *ptr = 0;
	processor_event_receiver_t* evt = 0;
	char *event;  void *eventdata;
	void **d2 = (void**)data;
	ship_list_t *targets = ship_list_new();
	event = d2[0]; eventdata = d2[1];
	
	ship_lock(event_receivers);
	while (targets && (evt = ship_list_next(event_receivers, &ptr))) {
		/* simple wildcard-ish matching for now */
		if (!strcmp(evt->event, event) ||
		    (strlen(evt->event) && evt->event[strlen(evt->event)-1] == '*' &&
		     !strncmp(evt->event, event, strlen(evt->event)-1))) {
			ship_list_add(targets, evt);
		}
	}
	ship_unlock(event_receivers);
	
	/* a bit dangerous, but luckily no one dereigsters these listeners */
	ptr = 0;
	while (targets && (evt = ship_list_next(targets, &ptr))) {
		evt->func(event, evt->data, eventdata);
	}
	if (d2[2]) {
		void (*callback) (char *event, void *eventdata) = d2[2];
		callback(event, eventdata);
	}
	freez_arr(d2, 1);
	ship_list_free(targets);
	return 0;
}

void 
processor_event_generate(char *event, void *eventdata, void (*callback) (char *event, void *eventdata))
{
	void **d2 = 0;
	
	/* we should do this async! */
	LOG_DEBUG("generating event %s\n", event);
	ASSERT_TRUE(d2 = mallocz(sizeof(void*) * 3), err);
	ASSERT_TRUE(d2[0] = strdup(event), err);
	d2[1] = eventdata;
	d2[2] = callback;
	processor_tasks_add(processor_event_generate_do, d2, NULL);
	return;
 err:
	freez_arr(d2, 1);
}
			       

/******* the async fw **********/

/*
point of the async: to have tasks done synchronously, but without the
risk of having the thread getting stuck.
*/


static void
processor_to_task_free(processor_to_task_t *task)
{
	COND_FREE(task->cond);
}

static int
processor_to_task_init(processor_to_task_t* ret, int (*func) (void *param))
{
	COND_INIT(ret->cond);
	ASSERT_TRUE(ret->cond, err);
	ret->func = func;
	ret->valid = 1;
	return 0;
 err:
	return -1;
}

SHIP_DEFINE_TYPE(processor_to_task);

static int 
processor_to_cleanup_dead(void *data, processor_task_t **wait, int wait_for_code)
{
	pthread_t *t = (pthread_t *)data;
	t = ship_list_remove(dead_threads, t);
	THREAD_FREE(t);
	return 0;
}

static void*
processor_to_run(void *data)
{
	processor_to_thread_t *t = data;
	int validity_missed = 0;
	pthread_t *current_thread = t->thread;
	
	LOG_INFO("starting unstuck-thread %s\n", t->name);
	do {
		processor_to_task_t *task = 0;
		LOCK_ACQ(t->lock);
		t->idle = 1;
		if (t->running)
			task = ship_list_pop(t->task_queue);
		if (!task) {
			COND_WAIT(t->cond, t->lock);
			if (t->running)
				task = ship_list_pop(t->task_queue);
		}

		if (task)
			t->idle = 0;
		LOCK_RELEASE(t->lock);
		
		/* we have a ref on the task now! */
		validity_missed = 0;
		if (task) {
			task->ret = task->func(task->data);

			ship_lock(task);
			task->done = 1;
			if (!task->valid)
				validity_missed = 1;
			ship_unlock(task);
			COND_WAKEUP(task->cond, task->parent._ship_obj_lock.lock);
			ship_obj_unref(task);
		}
		
		/* if we miss the validify of one task, then quit this thread */
	} while (t->running && !validity_missed);
	LOG_INFO("exiting unstuck-thread %s\n", t->name);
	
	/* abort myself if we have been replaced */
 	if (validity_missed) {
		processor_tasks_add(processor_to_cleanup_dead, current_thread, NULL);
 	}
	
	return NULL;
}

/* initializes a new thread for some unstuckable set of tasks */
void *
processor_to_init(const char *name)
{
	processor_to_thread_t *ret = 0;

	ASSERT_TRUE(ret = mallocz(sizeof(processor_to_thread_t)), err);
	ASSERT_TRUE(ret->name = strdup(name), err);
	ASSERT_TRUE(ret->task_queue = ship_obj_list_new(), err);
	LOCK_INIT(ret->lock);
	COND_INIT(ret->cond);
	ASSERT_TRUE(ret->lock && ret->cond, err);
	ASSERT_TRUE(ret->cond, err);

	/* set it to be running now already */
	ship_lock(to_threads);
	ret->running = 1;
	ASSERT_TRUE(THREAD_INIT(ret->thread) && !THREAD_RUN(ret->thread, processor_to_run, ret), err);
	ship_list_add(to_threads, ret);
	ship_unlock(to_threads);
	return ret;
 err:
	if (ret)
		ret->running = 0;
	ship_unlock(to_threads);
	processor_to_free(ret);
	return NULL;
}

static void
processor_to_reinit(processor_to_thread_t *t)
{
	/* put the thread up for freeing after done (killing will result in memleak */
	//THREAD_FREE(t->thread);
	ship_list_add(dead_threads, t->thread);
	t->thread = 0;
	
	THREAD_INIT(t->thread);
	if (t->thread && t->running) {
		THREAD_RUN(t->thread, processor_to_run, t);
	}
}

static void
processor_to_free(void *d)
{
	processor_to_thread_t *t = d;
	if (!t)
		return;
	if (t->running) {
		t->running = 0;
		COND_WAKEUP(t->cond, t->lock);
		THREAD_JOIN(t->thread);
	}
	ship_list_remove(to_threads, t);
	freez(t->name);
	//ship_obj_list_empty_with(t->task_queue, processor_to_task_free);
	ship_obj_list_free(t->task_queue);
	THREAD_FREE(t->thread);
	LOCK_FREE(t->lock);
	COND_FREE(t->cond);
	free(t);
}

/* executes a task that should not get stuck. all but the task func
   can be null. returns 0 if everything went well, an error code
   otherwise. */
int
processor_to(void *thread_id, 
	     int (*func) (void *param),
	     void (*cleanup) (void *param, int to_ret, int func_ret),
	     void *param,
	     int *function_ret,
	     int timeout_ms)
{
	processor_to_thread_t *t = thread_id;
	processor_to_task_t *task = 0;
	int ret = PROCESSOR_TO_ERROR;
	unsigned long now, done;
	
	/* create task packet, add to thread's queue */
	ASSERT_TRUE(task = (processor_to_task_t *)ship_obj_new(TYPE_processor_to_task, func), err);
	task->data = param;
	ship_obj_list_add(t->task_queue, task);

	/* wake up thread */
	COND_WAKEUP(t->cond, t->lock);
	
	ship_lock(task);
	now = ship_systemtimemillis();
	done = now + timeout_ms;
	while (t->running && !task->done && done > now) {
		COND_WAITUNTIL_MS(task->cond, task->parent._ship_obj_lock.lock, done-now);
		now = ship_systemtimemillis();
	}
	ship_obj_list_remove(t->task_queue, task);
	task->valid = 0;
	
	if (task->done) {
		ret = PROCESSOR_TO_DONE;
		if (function_ret)
			*function_ret = task->ret;
	} else if (t->running) {
		ret = PROCESSOR_TO_STUCK;
		LOG_WARN("to thread '%s' is stuck! .. or taking too long to complete\n", t->name);
		processor_to_reinit(t);
	}
	ship_unlock(task);

	/* call the cleanup */
	if (cleanup)
		cleanup(param, ret, task->ret);
 err:
	ship_obj_unref(task);
	return ret;
}
