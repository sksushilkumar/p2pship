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
/**
 * pymod.c
 *
 * Module for Python scripting support in p2pship
 *
 * @author joakim.koskela@hiit.fi
 */

#include "ship_debug.h"
#include "ship_utils.h"

/* if we're using threaded intepreter instead of multiple ones. this
   clearly messes up the environments!! do not use. */
//#define THREADED_INTERPRETER 1
//#define NEW_KILL 1

#undef _POSIX_C_SOURCE
#include <Python.h>
#include "webconf.h"
#include "processor_config.h"
#include "processor.h"
#include "olclient.h"
#include "netio_http.h"
#include "ext_api.h"
#include "conn.h"
#include "netio.h"
#include "netio_http.h"
#ifdef CONFIG_MEDIA_ENABLED
#include "media.h"
#endif
#include "resourceman.h"
#include "ui.h"

static ship_ht_t *pymod_config_updaters = 0;
static ship_ht_t *pymod_http_servers = 0;

static ship_list_t *pymod_callback_handlers = 0;

/* whether still alive */
static int pymod_alive = 0;

/* dummy list for locking the gil */
static ship_list_t *pymod_gil_lock = NULL;

#define PYTHON_WORKER_TYPE "py-runner"

/* struct for storing meta information about running python scripts
 * modules.  These should be made into ship_objs.. */
typedef struct pymod_state_s {
	PyThreadState *tstate;
	char *name;
	char *file;
	PyThreadState *parent;
} pymod_state_t;

/* the list of states */
static ship_ht_t *pymod_states = NULL;

static PyObject *pymod_create_ident(ident_t *ident);
static PyObject *pymod_create_ship_obj(ship_obj_t *obj);


void
pymod_state_free(pymod_state_t *ret)
{
	if (ret) {
		freez(ret->name);
		freez(ret->file);
		freez(ret);
	}
}

static pymod_state_t *
pymod_state_new(const char *file, PyThreadState *state, PyThreadState *parent)
{
	pymod_state_t *ret = mallocz(sizeof(*ret));
	if ((ret->file = strdup(file)) &&
	    (ret->name = strdup(file))) {
		ret->tstate = state;
		ret->parent = parent;
		return ret;
	}
	pymod_state_free(ret);
	return NULL;
}


/* the registered ipc clients */
static ship_ht_t *pymod_ipc_handlers = NULL;

/* struct for storing IPC callbacks */
typedef struct pymod_ipc_handler_s {
	PyObject *callback;
	PyObject *callback2;
	char *name;

	PyThreadState *tstate;
} pymod_ipc_handler_t;

static void
pymod_ipc_free(void *ol)
{
	pymod_ipc_handler_t *h = (pymod_ipc_handler_t *)ol;
	if (h) {
		freez(h->name);
		Py_XDECREF(h->callback); 
		Py_XDECREF(h->callback2); 
		freez(h);
	}
}

static pymod_ipc_handler_t* pymod_ipc_new(const char *name, PyObject *callback, PyObject *callback2);

/* init the service registrations */
static ship_ht_t *pymod_default_services = 0;

/* struct for holding the python-based service handlers */
typedef struct pymod_service_s {
	service_t service;
	pymod_ipc_handler_t *handler;
} pymod_service_t;

/*
 * ol data
 */

/* the registered ol clients */
static ship_list_t *pymod_ol_clients = NULL;

/* struct for storing the callbacks */
typedef struct pymod_ol_handler_s {
	PyObject *put;
	PyObject *get;
	PyObject *remove, *close, *put_signed, *get_signed;
	char *name;

	PyThreadState *tstate;

	/* the olclient module */
	struct olclient_module* mod;
} pymod_ol_handler_t;

/* the active gets */
static ship_ht_t *pymod_ol_gets = NULL;

static int pymod_run_file(const char *file);

static void
pymod_ol_free(void *ol)
{
	pymod_ol_handler_t *h = (pymod_ol_handler_t *)ol;
	if (h) {
		freez(h->name);
		Py_XDECREF(h->put); 
		Py_XDECREF(h->get); 
		Py_XDECREF(h->remove); 
		Py_XDECREF(h->close); 
		Py_XDECREF(h->put_signed); 
		Py_XDECREF(h->get_signed);

		olclient_unregister_module(h->mod);
		olclient_module_free(h->mod);
		freez(h);
	}
}


//#define GILSTATE
#define RESTORESAVE

#ifdef GILSTATE
static PyGILState_STATE gstate;
#endif

/* used to be:
 * static void
 * pymod_tstate_return(PyThreadState *tstate)
 *
 * but tstate isn't used right now.
 */

static void
pymod_tstate_return()
{
	/* should we clear the error or invalidate the whole app? */
	if (PyErr_Occurred()) {
		LOG_WARN("The Python callback raised an Exception. Clearing\n");
		PyErr_Print();
		PyErr_Clear();
	}
	// gil
	//PyThreadState_Swap(NULL);

	// save & restore 
#ifdef RESTORESAVE
	PyEval_SaveThread();
#elif defined(GILSTATE)
	PyGILState_Release(gstate);
#endif
	//PyEval_ReleaseThread(tstate);

	// these combined are the same as releasethread
	//PyThreadState_Swap(NULL);
	//PyEval_ReleaseLock();

	ship_unlock(pymod_gil_lock);
}

static int
pymod_tstate_ok(PyThreadState *tstate)
{
	if (!Py_IsInitialized())
		return 0;

	/* we should have *no* locks at this stage! */
	ship_check_restricts();

	ship_wait("Getting Python GIL");
	
	ship_lock(pymod_gil_lock);
	
	// new try..
#ifdef RESTORESAVE
	PyEval_RestoreThread(tstate);
#elif defined(GILSTATE)
	gstate = PyGILState_Ensure();
#endif
	
#ifndef THREADED_INTERPRETER
	//PyThreadState_Get()->interp = tstate->interp;
#endif	
	/*
	//PyEval_RestoreThread(tstate);
	
	{
		PyThreadState *ts;
		ts = PyGILState_GetThisThreadState();
		       (unsigned int)ts, (unsigned int)tstate);
		
		if (!ts) {
			PyGILState_STATE gstate;
			gstate = PyGILState_Ensure(); // Is tis necessary?
			
			ts = PyGILState_GetThisThreadState();

			PyGILState_Release(gstate);


			
			
		}
	}

	PyEval_AcquireThread(tstate);
	*/


	//PyEval_AcquireLock();
	//PyThreadState_Swap(tstate);
	ship_complete();
	
	// check if the thread is alive!
	if (!PyThreadState_GetDict() || PyErr_Occurred()) {
		ship_unlock(pymod_gil_lock);
		return 0;
	}
	if (!pymod_alive) {
		ship_unlock(pymod_gil_lock);
		PyErr_SetString(PyExc_EnvironmentError, "p2pship proxy is closing");
		return 0;
	}
	return 1;
}

static pymod_state_t *
pymod_get_current_state()
{
	pymod_state_t *ret = (pymod_state_t *)ship_ht_get_ptr(pymod_states, PyThreadState_Get());
	if (!ret)
		LOG_DEBUG("No state found for 0x%08x\n", PyThreadState_Get());
	return ret;
}

/*
 *
 * MISC utility and common stuff
 *
 *
 */

static const char*
pymod_string_or_none(PyObject *obj)
{
	if (obj && PyString_Check(obj))
		return PyString_AsString(obj);
	return NULL;
}

static ident_t*
pymod_valid_ident_or_default(const char *local_aor)
{
	ident_t *ident = NULL;
	if (!local_aor || strlen(local_aor) == 0) {
		ASSERT_TRUE(ident = ident_get_default_ident(), err);
	} else {
		ASSERT_TRUE(ident = ident_find_by_aor(local_aor), err);
	}
 err:
	return ident;
}

static PyObject *
p2pship_reserve_state(PyObject *self, PyObject *args)
{
	PyEval_AcquireLock();
	Py_INCREF(Py_None);
	return Py_None;
}

static PyObject *
p2pship_release_state(PyObject *self, PyObject *args)
{
	PyEval_ReleaseLock();
	Py_INCREF(Py_None);
	return Py_None;
}


static int 
pymod_call_async_do(void *data, processor_task_t **wait, int wait_for_code)
{
	pymod_ipc_handler_t *h = data;
	PyObject *result = 0, *arglist = 0;
	
	ship_check_restricts();
	ASSERT_TRUE(pymod_tstate_ok(h->tstate), err);
	ASSERT_TRUE(arglist = Py_BuildValue("(O)", h->callback2), err);
	
	result = PyObject_CallObject(h->callback, arglist);
	Py_DECREF(arglist);
	ASSERT_TRUE(result, err);
	Py_DECREF(result);
 err:
	pymod_tstate_return();
	return 0;
}

static void
pymod_call_async_done(void *qt, int code)
{
	pymod_ipc_handler_t *h = qt;
	pymod_tstate_ok(h->tstate);
	pymod_ipc_free(h);
	pymod_tstate_return();
}

static PyObject *
p2pship_call_async(PyObject *self, PyObject *args)
{
	PyObject *func = 0, *data = 0;
	pymod_ipc_handler_t *h = 0;
	processor_task_t *task = NULL;
	
	if (!PyArg_ParseTuple(args, "OO:call_async", &func, &data))
		goto err;
	
	ASSERT_TRUE(h = pymod_ipc_new("safe_call", func, data), err);
	ASSERT_TRUE(task = processor_tasks_add(pymod_call_async_do, h,
					       pymod_call_async_done), err);
	
	Py_INCREF(Py_None);
	return Py_None;
 err:
	pymod_ipc_free(h);
	return NULL;
}


static int 
pymod_periodic(void* data)
{
	pymod_ipc_handler_t *h = (pymod_ipc_handler_t *)data;
	PyObject *result = 0, *arglist = 0;
	int ret = 0;
	
	ship_check_restricts();
	ASSERT_TRUE(pymod_tstate_ok(h->tstate), err);

	ASSERT_TRUE(arglist = Py_BuildValue("(O)", h->callback2), err);
	result = PyObject_CallObject(h->callback, arglist);
	Py_DECREF(arglist);
	ASSERT_TRUE(result, err);
	if (PyBool_Check(result) && (PyInt_AsLong(result) == 0)) {
		ret = -1;
	}
	Py_DECREF(result);
 err:
	pymod_tstate_return();
	return ret;
}

static PyObject *
p2pship_call_periodically(PyObject *self, PyObject *args)
{
	PyObject *func = 0, *data = 0;
	pymod_ipc_handler_t *h = 0;
	int period;
	
	if (!PyArg_ParseTuple(args, "OOi:call_periodically", &func, &data, &period))
		goto err;
	
	ASSERT_TRUE(h = pymod_ipc_new("periodic_call", func, data), err);
	ASSERT_ZERO(processor_tasks_add_periodic(pymod_periodic, h, period), err);
	Py_INCREF(Py_None);
	return Py_None;
 err:
	pymod_ipc_free(h);
	return NULL;
}

/* changes the name of the application */
static PyObject *
p2pship_set_name(PyObject *self, PyObject *args)
{
	const char *str = 0;
	pymod_state_t *state = NULL;

	if (!PyArg_ParseTuple(args, "s", &str))
		return NULL;
	
	if ((state = pymod_get_current_state())) {
		freez(state->name);
		state->name = strdup(str);
	}
	Py_INCREF(Py_None);
	return Py_None;
}

/* gets the name of the application */
static PyObject *
p2pship_get_name(PyObject *self, PyObject *args)
{
	pymod_state_t *state = NULL;
	PyObject *ret = 0;
	
	if ((state = pymod_get_current_state())) {
		ret = Py_BuildValue("s", state->name);
		return ret;
	}
	Py_INCREF(Py_None);
	return Py_None;
}

/* gets the name of the file */
static PyObject *
p2pship_get_file(PyObject *self, PyObject *args)
{
	pymod_state_t *state = NULL;
	PyObject *ret = 0;
	
	if ((state = pymod_get_current_state())) {
		ret = Py_BuildValue("s", state->file);
		return ret;
	}
	Py_INCREF(Py_None);
	return Py_None;
}

/* gets the data directory reserved for the script */
static PyObject *
p2pship_get_datadir(PyObject *self, PyObject *args)
{
	pymod_state_t *state = NULL;
	PyObject *ret = 0;
	char *dir = NULL;
	char *datadir = NULL;
	char *pos = NULL;

	ASSERT_TRUE(state = pymod_get_current_state(), err);
		
	ASSERT_TRUE(datadir = processor_config_string(processor_get_config(), P2PSHIP_CONF_PYTHON_DATA_DIR), err);
	ASSERT_TRUE(dir = mallocz(strlen(datadir) + strlen(state->file) + 10), err);
	strcpy(dir, datadir);
		
	if (!(pos = strrchr(state->file, '/'))) {
		strcat(dir, "/");
		pos = state->file;
	}
	strcat(dir, pos);
	strcat(dir, "_data");
		
	/* create data dir: datadir/scriptname/ ? */
		
	ASSERT_ZERO(ship_ensure_dir(dir), err);

	ret = Py_BuildValue("s", dir);
	goto end;
 err:
	freez(dir);
	ret = Py_None;
 end:
	LOG_WARN("Please check the Python data dir configuration (%s)\n", processor_config_string(processor_get_config(), P2PSHIP_CONF_PYTHON_DATA_DIR));
	Py_INCREF(Py_None);
	return ret;
}


/* logging */
static PyObject *
p2pship_log(PyObject *self, PyObject *args)
{
	const char *str = 0;
	int level = 0;
	pymod_state_t *state = NULL;
	
	if (!PyArg_ParseTuple(args, "is", &level, &str))
		return NULL;
	
	if ((state = pymod_get_current_state())) {
		LOG_CUSTOM(level, "PythonApp(%s): %s", state->name, str);
	} else {
		LOG_CUSTOM(level, "PythonApp(UNKNOWN): %s", str);
	}
	Py_INCREF(Py_None);
	return Py_None;
}

/* the p2pship extensions to the python environment */
static PyObject *
p2pship_get_json(PyObject *self, PyObject *args)
{
	const char *confname = 0;
	PyObject *ret = 0;
	char *json = 0;
	
	if (!PyArg_ParseTuple(args, "s", &confname))
		return NULL;
	
	if (!(json = webconf_get_json(confname)))
		return NULL;

	ret = Py_BuildValue("s", json);
	freez(json);
	return ret;
}

/**
 *
 * IPC
 *
 */

static pymod_ipc_handler_t*
pymod_ipc_new(const char *name, PyObject *callback, PyObject *callback2)
{
	pymod_ipc_handler_t*h = NULL;
	ASSERT_TRUE(PyCallable_Check(callback), call_err);
	ASSERT_TRUE(!callback2 || PyCallable_Check(callback), call_err);
	ASSERT_TRUE(h = mallocz(sizeof(*h)), mem_err);
	ASSERT_TRUE(h->name = strdup(name), mem_err);

	h->callback = callback;
	Py_XINCREF(h->callback);
	if (callback2) {
		h->callback2 = callback2;
		Py_XINCREF(h->callback2);
	}

	h->tstate = PyThreadState_Get();
	return h;
 mem_err:
	PyErr_SetString(PyExc_MemoryError, "Memory depleted");
	goto err;
 call_err:
	PyErr_SetString(PyExc_StandardError, "Callback required");
 err:
	pymod_ipc_free(h);
	return NULL;
}

static PyObject *
p2pship_register_ipc_handler(PyObject *self, PyObject *args)
{
	PyObject *callback = 0;
	char *name = 0;
	pymod_ipc_handler_t *h = 0;

	if (!PyArg_ParseTuple(args, "sO:register_ipc_handler", &name, &callback))
		goto err;

	ASSERT_ZERO(ship_ht_get_string(pymod_ipc_handlers, name), err);
	LOG_DEBUG("registering ipc handler for %s..\n", name);
	ASSERT_TRUE(h = pymod_ipc_new(name, callback, NULL), err);
	ship_ht_put_string(pymod_ipc_handlers, h->name, h);
	
	LOG_DEBUG("registered ipc handler for %s done\n", name);
	Py_INCREF(Py_None);
	return Py_None;
 err:
	return NULL;
}

static PyObject *
p2pship_call_ipc_handler(PyObject *self, PyObject *args)
{
	PyObject *data = 0;
	PyObject *arglist;
	PyObject *result;
	char *name = 0;
	pymod_ipc_handler_t *h = 0;
	const char *error;
	PyThreadState *oldstate = 0;
	char id[32];

	error = "Invalid parameters";
	if (!PyArg_ParseTuple(args, "sO:call_ipc_handler", &name, &data))
		goto err;

	LOG_DEBUG("calling ipc handler for %s..\n", name);

	error = "Unknown IPC handler";
	ASSERT_TRUE(h = ship_ht_get_string(pymod_ipc_handlers, name), err);

	error = "Error executing IPC";
	oldstate = PyThreadState_Get();
	sprintf(id, "0x%08x", (unsigned int)oldstate);
	ASSERT_TRUE(arglist = Py_BuildValue("(ssO)", name, id, data), err);

	PyThreadState_Swap(h->tstate);
	result = PyObject_CallObject(h->callback, arglist);
	PyThreadState_Swap(oldstate);

	Py_DECREF(arglist);
	ASSERT_TRUE(result, err);
	
	LOG_VDEBUG("calling ipc handler for %s done\n", name);
	return result;
 err:
	PyErr_SetString(PyExc_StandardError, error);
	return NULL;
}

/**
 *
 * Config 
 *
 */
#define pymod_config_key_prefix "python_app_"

static const char*
pymod_strip_config_key(const char *key)
{
	if (strlen(key) > strlen(pymod_config_key_prefix))
		return &key[strlen(pymod_config_key_prefix)];
	return key;
}

static char*
pymod_get_config_key(const char *key)
{
  	char *k2 = NULL;
	if ((k2 = mallocz(strlen(key) + strlen(pymod_config_key_prefix) + 2))) {
		sprintf(k2, pymod_config_key_prefix "%s", key);
	} else {
		PyErr_SetString(PyExc_MemoryError, "Memory depleted");
	}
	return k2;
}

static PyObject *
p2pship_config_create(PyObject *self, PyObject *args)
{
	const char *key = 0, *description = 0, *type = 0, *value = 0;
  	char *k2 = NULL;
	PyObject *ret = NULL;

	if (!PyArg_ParseTuple(args, "ssss", &key, &description, &type, &value))
		goto err;
	
	if (!(k2 = pymod_get_config_key(key)))
		goto err;

	if (processor_config_create_key(processor_get_config(), k2, description, type, value)) {
		PyErr_SetString(PyExc_StandardError, "Could not create key");
		goto err;
	}

	Py_INCREF(Py_None);
	ret = Py_None;
 err:
	freez(k2);
	return ret;
}

static PyObject *
p2pship_config_set(PyObject *self, PyObject *args)
{
	const char *key = 0, *value;
 	char *k2 = NULL;
	PyObject *ret = NULL;
	
	if (!PyArg_ParseTuple(args, "ss", &key, &value))
		goto err;
	
	if (!(k2 = pymod_get_config_key(key)))
		goto err;
	
	if (processor_config_set_string(processor_get_config(), k2, (char *)value)) {
		PyErr_SetString(PyExc_StandardError, "Could not set key");
		goto err;
	}
	
	Py_INCREF(Py_None);
	ret = Py_None;
 err:
	freez(k2);
	return ret;
}

static PyObject *
p2pship_config_save(PyObject *self, PyObject *args)
{
	PyObject *ret = NULL;
	processor_config_t *conf = processor_get_config();

	processor_config_save(conf, processor_config_string(conf, P2PSHIP_CONF_CONF_FILE));
	
	Py_INCREF(Py_None);
	ret = Py_None;
	return ret;
}


static PyObject *
p2pship_config_get(PyObject *self, PyObject *args)
{
	const char *key = 0;
 	char *k2 = NULL;
	char *value = 0;
	PyObject *ret = NULL;
	
	if (!PyArg_ParseTuple(args, "s", &key))
		goto err;

	if (!(k2 = pymod_get_config_key(key)))
		goto err;
	
	if (!(value = processor_config_string(processor_get_config(), k2))) {
		PyErr_SetString(PyExc_StandardError, "Could not find key");
		goto err;
	}
	
	if (!(ret = Py_BuildValue("s", value))) {
		PyErr_SetString(PyExc_MemoryError, "Memory depleted");
		goto err;
	}

 err:
	freez(k2);
	return ret;
}

static void 
pymod_config_update(processor_config_t *c, char *k, char *v)
{
	pymod_ipc_handler_t *h = 0;
	PyObject *result = 0, *arglist = 0;

	if ((h = ship_ht_get_string(pymod_config_updaters, k))) {
		// call the function..
		ship_check_restricts();
		ASSERT_TRUE(pymod_tstate_ok(h->tstate), err);
		ASSERT_TRUE(arglist = Py_BuildValue("(ss)", pymod_strip_config_key(k), v), err);

		result = PyObject_CallObject(h->callback, arglist);
		Py_DECREF(arglist);
		ASSERT_TRUE(result, err);
		Py_DECREF(result);
	err:
		pymod_tstate_return();
	}
}

static PyObject *
p2pship_config_set_update(PyObject *self, PyObject *args)
{
	const char *key = 0;
 	char *k2 = NULL;
	pymod_ipc_handler_t *h = 0;
	PyObject *func = NULL;
	
	if (!PyArg_ParseTuple(args, "sO:config_set_update", &key, &func))
		goto err;

	if (!(k2 = pymod_get_config_key(key)))
		goto err;

	ASSERT_TRUE(h = pymod_ipc_new(k2, func, NULL), err);

	/* remove old handler, put this one in */
	pymod_ipc_free(ship_ht_get_string(pymod_config_updaters, k2));
	ship_ht_put_string(pymod_config_updaters, k2, h);
	processor_config_set_dynamic_update(processor_get_config(), k2, pymod_config_update);

	freez(k2);
	Py_INCREF(Py_None);
	return Py_None;
 err:
	freez(k2);
	return NULL;
}

/**
 *
 * the service handling, packet transmission
 *
 */

static int pymod_service_data_received(char *data, int data_len, 
				       ident_t *target, char *source, 
				       service_type_t service_type);
static void pymod_service_service_closed(service_type_t service_type, ident_t *ident, void *pkg);

static char *
p2pship_service_create_id(const char *aor, const service_type_t t)
{
	char *ret = NULL;
	ASSERT_TRUE(ret = mallocz(strlen(aor) + 12), err);
	sprintf(ret, "%s:%d", aor, t);
 err:
	return ret;
}

static void
pymod_service_free(void *p)
{
	pymod_service_t *s = (pymod_service_t *)p;
	if (s) {
		if (s->handler)
			pymod_ipc_free(s->handler);
		free(s);
	}
}

static pymod_service_t *
pymod_service_new(pymod_ipc_handler_t *ipc)
{
	pymod_service_t *ret = 0;
	ASSERT_TRUE(ret = mallocz(sizeof(*ret)), err);

	ret->service.data_received = pymod_service_data_received;
	ret->service.service_closed = pymod_service_service_closed;
	ret->service.service_handler_id = ipc->name;
	ret->handler = ipc;
	return ret;
 err:
	pymod_service_free(ret);
	return NULL;
}


/* data received from ..far away. */
static int 
pymod_service_data_received(char *data, int data_len, 
			    ident_t *target, char *source, 
			    service_type_t service_type)
{
	/* find the service holder .. */
	pymod_service_t *s = 0;
	PyObject *arglist = NULL, *result = NULL;
	char *id = NULL;
	
	/* check first if we have a registered one for this */
	ASSERT_TRUE(pymod_default_services, err);
	ASSERT_TRUE(id = p2pship_service_create_id(target->sip_aor, service_type), err);
	s = ship_ht_get_string(pymod_default_services, id);
	/* maybe not, demand that the user uses real aors! */
	/*
	if (!s) {
		freez(id);
		ASSERT_TRUE(id = p2pship_service_create_id("@", service_type), err);
		s = ship_ht_get_string(pymod_default_services, id);
	}
	*/
	if (!s)
		s = ship_ht_get_int(pymod_default_services, service_type);
	if (!s) {
		LOG_ERROR("Got a packet for some sort of ident (%s) that we really don't know about!\n", target->sip_aor);
		goto err;
	}
	
	ship_unlock(target);
	ship_check_restricts();
	ASSERT_TRUE(pymod_tstate_ok(s->handler->tstate), err2);
	ASSERT_TRUE(arglist = Py_BuildValue("(s#ssi)", data, data_len, target->sip_aor, source, service_type), err2);
	result = PyObject_CallObject(s->handler->callback, arglist);
 err2:
	Py_XDECREF(arglist);
	Py_XDECREF(result);
	pymod_tstate_return();
	ship_lock(target);
 err:
	freez(id);
	return 0;
}

/* this notifies the service handler that the service is being closed */
static void
pymod_service_service_closed(service_type_t service_type, ident_t *ident, void *pkg)
{
	pymod_service_t *s = 0;
	PyObject *arglist = NULL, *result = NULL;
	char *id = NULL;

	ASSERT_TRUE(pymod_default_services, err);

	/* check first if we have a registered one for this */
	ASSERT_TRUE(id = p2pship_service_create_id(ident->sip_aor, service_type), err);
	s = ship_ht_remove_string(pymod_default_services, id);
	if (!s)
		s = ship_ht_remove_int(pymod_default_services, service_type);
	if (!s)
		goto err;
		
	ship_unlock(ident);
	ship_check_restricts();
	ASSERT_TRUE(pymod_tstate_ok(s->handler->tstate), err2);

	ASSERT_TRUE(arglist = Py_BuildValue("(is)", service_type, ident->sip_aor), err2);
	result = PyObject_CallObject(s->handler->callback2, arglist);
 err2:
	Py_XDECREF(arglist);
	Py_XDECREF(result);
	pymod_tstate_return();
	ship_lock(ident);
 err:
	pymod_service_free(s);
	freez(id);
}

static PyObject *
p2pship_service_register_default(PyObject *self, PyObject *args)
{
	pymod_service_t *s = 0;
	pymod_ipc_handler_t *ipc = 0;
	service_type_t t = 0;
	PyObject *callback = 0, *callback2 = 0;
	char name[32];
	
	if (!PyArg_ParseTuple(args, "iOO:service_register_default", &t, &callback, &callback2))
		goto parm_err;

	/* todo: we should lock things up here first! */

	/* create an unique-enough name */
	sprintf(name, "py_service_%08x", 0);
	ASSERT_TRUE(ipc = pymod_ipc_new(name, callback, callback2), err);

	/* use the old one? ok.. */
	if ((s = ship_ht_get_int(pymod_default_services, t))) {
		pymod_ipc_free(s->handler);
		s->handler = ipc;
		s->service.service_handler_id = ipc->name;
	} else {
		ASSERT_TRUE(s = pymod_service_new(ipc), err);
		ASSERT_ZERO(ident_register_default_service(t, &(s->service)), err);
		ship_ht_put_int(pymod_default_services, t, s);
	}

	/* create an unique-enough name */
	sprintf(s->handler->name, "py_service_%08x", (unsigned int)s);
	
	Py_INCREF(Py_None);
	return Py_None;
 parm_err:
	return NULL;
 err:
	if (s)
		pymod_service_free(s);
	else
		pymod_ipc_free(ipc);
	PyErr_SetString(PyExc_EnvironmentError, "Error"); // todo: check that all errors are ok
	return NULL;
		
}

static PyObject *
p2pship_service_register(PyObject *self, PyObject *args)
{
	pymod_service_t *s = 0;
	pymod_ipc_handler_t *ipc = 0;
	service_type_t t = 0;
	PyObject *callback = 0, *callback2 = 0;
	char name[32];
	char *aor = NULL, *id = 0;
	
	if (!PyArg_ParseTuple(args, "siOO:service_service_update_registration", &aor, &t, &callback, &callback2))
		goto parm_err;
	
	ASSERT_TRUE(id = p2pship_service_create_id(aor, t), err);

	/* create an unique-enough name */
	sprintf(name, "py_service_%08x", 0);
	ASSERT_TRUE(ipc = pymod_ipc_new(name, callback, callback2), err);

	/* use the old one? ok.. */
	if ((s = ship_ht_get_string(pymod_default_services, id))) {
		pymod_ipc_free(s->handler);
		s->handler = ipc;
		s->service.service_handler_id = ipc->name;
	} else {
		ASSERT_TRUE(s = pymod_service_new(ipc), err);
		ASSERT_TRUE(ident_process_register(aor, t, &(s->service), NULL, -1, NULL) == 200, err);
		ship_ht_put_string(pymod_default_services, id, s);
	}

	/* create an unique-enough name */
	sprintf(s->handler->name, "py_service_%08x", (unsigned int)s);
	
	Py_INCREF(Py_None);
	freez(id);
	return Py_None;
 parm_err:
	return NULL;
 err:
	if (s)
		pymod_service_free(s);
	else
		pymod_ipc_free(ipc);
	PyErr_SetString(PyExc_EnvironmentError, "Error"); // todo: check that all errors are ok
	freez(id);
	return NULL;
}

static PyObject *
p2pship_service_send(PyObject *self, PyObject *args)
{
	char *from, *to, *data;
	int t;
	PyObject *ret = 0;
		
	if (!PyArg_ParseTuple(args, "ssis:service_send", &to, &from, &t, &data))
		goto err;
	
	/* dtn: todo: other sends so we can set flags etc */

	if (conn_send_default(to, from, t, data, strlen(data), NULL, NULL)) {
		LOG_WARN("Could not send type %i packet from %s to %s\n", 
			 t, from, to);
		PyErr_SetString(PyExc_EnvironmentError, "Error sending!");
		goto err;
	}
	
	ret = Py_None;
 err:
	Py_XINCREF(ret);
	return ret;
}

static PyObject *
p2pship_send_packet(PyObject *self, PyObject *args)
{

	PyErr_SetString(PyExc_EnvironmentError, "Not implemented");
	return NULL;
}

/*
 * event handling
 *
 */

static PyObject *
pymod_pack_to_py(ship_pack_t *pack)
{
	PyObject *ret = NULL, *part = NULL;
	ship_obj_t *obj = NULL;
	int elm;
	char t;
	
	ASSERT_TRUE(ret = PyList_New(0), err);
	
	for (elm = 0; (t = ship_pack_type(pack, elm)); elm++) {
		char *str = NULL;
		int i;
		long l;

		switch (t) {
		case 'i':
			ship_unpack_keep_one(elm, pack, &i);
			ASSERT_TRUE(part = PyInt_FromLong(i), err);
			break;
		case 'l':
			ship_unpack_keep_one(elm, pack, &l);
			ASSERT_TRUE(part = PyInt_FromLong(l), err);
			break;
		case 'm':
			ASSERT_TRUE(part = PyString_FromString("m"), err);
			break;
		case 's':
			ship_unpack_keep_one(elm, pack, &str);
			ASSERT_TRUE(part = PyString_FromString(str), err);
			break;
		case 'I':
			ship_unpack_keep_one(elm, pack, &obj);
			ASSERT_TRUE(part = pymod_create_ident((ident_t*)obj), err);
			break;
		case 'O':
		case 'C':
			ship_unpack_keep_one(elm, pack, &obj);
			ASSERT_TRUE(part = pymod_create_ship_obj(obj), err);
			break;
		default:
		case 'p':
			/* none? */
			part = Py_None;
			Py_INCREF(part);
			break;
		}

		ship_obj_unref(obj);
		obj = NULL;
		
		if (part) {
			ASSERT_ZERO(PyList_Append(ret, part), err);
			part = NULL;
		}
	}

	return ret;
 err:
	ship_obj_unref(obj);
	Py_XDECREF(ret);
	Py_XDECREF(part);
	return NULL;
}

/********* evets ***********/

static void
pymod_event_receiver(char *event, void *data, ship_pack_t *eventdata)
{
	pymod_ipc_handler_t *h = 0;
	PyObject *param = NULL, *arglist, *result;

	h = (pymod_ipc_handler_t *)data;
	
	ship_check_restricts();
	ASSERT_TRUE(pymod_tstate_ok(h->tstate), err);
	if (eventdata) {
		ASSERT_TRUE(param = pymod_pack_to_py(eventdata), err);
	} else {
		param = Py_None;
		Py_INCREF(param);
	}
	
	if (h->callback2) {
		ASSERT_TRUE(arglist = Py_BuildValue("(sOO)", event, param, h->callback2), err);
	} else {
		ASSERT_TRUE(arglist = Py_BuildValue("(sO)", event, param), err);
	}
	
	result = PyObject_CallObject(h->callback, arglist);
	Py_DECREF(arglist);
	ASSERT_TRUE(result, err);
	Py_DECREF(result);
 err:
	Py_XDECREF(param);
	pymod_tstate_return();
}

/* 
 * Receive events.
 * @param event, callback
 * @callback event, parameters ..
 */
static PyObject *
p2pship_event_receive(PyObject *self, PyObject *args)
{
	char *event = NULL;
	PyObject *func = 0, *data = 0;
	pymod_ipc_handler_t *h = 0;
	
	if (!PyArg_ParseTuple(args, "sO|O", &event, &func, &data))
		goto err;
	
	ASSERT_TRUE(h = pymod_ipc_new("event_receiver", func, data), err);
	ASSERT_ZERO(processor_event_receive(event, h, pymod_event_receiver), err);
	Py_INCREF(Py_None);
	return Py_None;
err:
	pymod_ipc_free(h);
	PyErr_SetString(PyExc_EnvironmentError, "Could not register");
	return NULL;
}

static PyObject *
p2pship_event_generate(PyObject *self, PyObject *args)
{
	PyErr_SetString(PyExc_EnvironmentError, "Not implemented");
	return NULL;
}

/**
 *
 * HTTP server
 *
 */
static void
p2pship_http_create_ref(char *ref, netio_http_conn_t *conn, extapi_http_req_t *req)
{
	if (req)
		sprintf(ref, "p:%s", req->id);
	else
		sprintf(ref, "s:%s", conn->tracking_id);
}

static int
p2pship_http_get_ref(const char *ref, netio_http_conn_t **conn, extapi_http_req_t **req)
{
	if (str_startswith(ref, "p:")) {
		*req = extapi_get_http_req(&ref[2]);
	} else if (str_startswith(ref, "s:")) {
		*conn = netio_http_get_conn_by_id(&ref[2]);
	}
	if (*conn || *req)
		return 0;
	return -1;
}

static PyObject *
p2pship_http_send(PyObject *self, PyObject *args)
{
	const char *ref = 0;
	const char *data = 0;
	extapi_http_req_t *req = NULL;
	netio_http_conn_t *conn = 0;
	
	// todo: test me

	if (!PyArg_ParseTuple(args, "ss:http_send", &ref, &data))
		goto err;

	ASSERT_ZERO(p2pship_http_get_ref(ref, &conn, &req), err);
	if (req)
		extapi_http_data_return(req, data, strlen(data));
	else if (conn) {
		netio_send(conn->socket, data, strlen(data));
		ship_unlock(conn);
	}
	Py_INCREF(Py_None);
	return Py_None;
err:
	PyErr_SetString(PyExc_EnvironmentError, "Socket closed");
	return NULL;
}

static PyObject *
p2pship_http_close(PyObject *self, PyObject *args)
{
	const char *ref = 0;
	
	if (!PyArg_ParseTuple(args, "s:http_close", &ref))
		goto err;
	
	
	// if on the 'handling stack' still, then do nothing!
	// netio_http_conn_close(conn);

err:
	PyErr_SetString(PyExc_EnvironmentError, "Not implemented");
	return NULL;
}

static PyObject *
p2pship_http_respond(PyObject *self, PyObject *args)
{
	const char *ref, *code_str, *content_type, *body;
	int code, body_len;
	netio_http_conn_t *conn = 0;
	extapi_http_req_t *req = NULL;
	
	if (!PyArg_ParseTuple(args, "sisss#:http_respond", 
			      &ref, &code, &code_str, &content_type, &body, &body_len))
		goto err;
	
	ASSERT_ZERO(p2pship_http_get_ref(ref, &conn, &req), err);
	if (req) {
		char *msg = 0;
		int msglen = 0;
		if (!netio_http_create_response(code, (char*)code_str, 
						(char*)content_type,
						(char*)body, body_len,
						&msg, &msglen)) {
			extapi_http_data_return(req, msg, msglen);
		} else {
			LOG_ERROR("Could not create response packet!\n");
		}
		extapi_http_data_return(req, "", 0); // to finish the req off..
	} else {
		netio_http_respond(conn, 
				   code, (char*)code_str, 
				   (char*)content_type,
				   (char*)body, body_len);
		ship_unlock(conn);
	}
	Py_INCREF(Py_None);
	return Py_None;
 err:
	PyErr_SetString(PyExc_EnvironmentError, "Socket closed");
	return NULL;
}

static int pymod_http_process_req2(netio_http_conn_t *conn, void *pkg, extapi_http_req_t *req);

/* callback for incoming http connections */
static int
pymod_http_process_req(netio_http_conn_t *conn, void *pkg)
{
	return pymod_http_process_req2(conn, pkg, NULL);
}

static int
pymod_http_process_req2(netio_http_conn_t *conn, void *pkg, extapi_http_req_t *req)
{
	pymod_ipc_handler_t *h = (pymod_ipc_handler_t *)pkg;
	int funcret = -1;
	ship_list_t *l = 0;
	char *k = 0, *v = 0;
	PyObject *arglist = 0, *params = 0, *headers = 0, *result = 0, *key = 0, *val = 0;
	addr_t addr;
	char *astr = 0;
	char ref[32];
	
	/*
        (self.ref,
         self.body,
         self.url,
         self.original_url,
         self.url_extras,
         self.http_version,
         self.remote_host,
         plist,
         hlist) = req
	*/


	/* build parameters.. */

	ASSERT_TRUE(params = Py_BuildValue("{}"), err);
	ASSERT_TRUE(l = netio_http_conn_get_param_keys(conn), err);
	while ((k = ship_list_pop(l))) {
		if ((v = netio_http_conn_get_param(conn, k))) {
			ASSERT_TRUE(key = Py_BuildValue("s", k), err);
			ASSERT_TRUE(val = Py_BuildValue("s", v), err);
			ASSERT_TRUE(PyObject_SetItem(params, key, val) != -1, err);
			key = 0; val = 0;
		}
		free(k);
	}
	ship_list_free(l);
	l = 0;

	ASSERT_TRUE(headers = Py_BuildValue("{}"), err);
	ASSERT_TRUE(l = netio_http_conn_get_header_keys(conn), err);
	while ((k = ship_list_pop(l))) {
		if ((v = netio_http_get_header(conn, k))) {
			ASSERT_TRUE(key = Py_BuildValue("s", k), err);
			ASSERT_TRUE(val = Py_BuildValue("s", v), err);
			ASSERT_TRUE(PyObject_SetItem(headers, key, val) != -1, err);
			key = 0; val = 0;
		}
		free(k);
	}
	ship_list_free(l);
	l = 0;

	if (req)
		astr = combine_str(req->from_aor, "");
	else if (!ident_addr_socket_to_addr(conn->socket, &addr))
		ident_addr_addr_to_str(&addr, &astr);
		
	p2pship_http_create_ref(ref, conn, req);
	ASSERT_TRUE(arglist = Py_BuildValue("([ssssssssOO])", ref, &conn->buf[conn->header_len],
					    conn->method, conn->url, conn->original_url,
					    conn->url_extras, conn->http_version, (astr? astr : "remote:0000"),
					    params, headers), err);
	params = 0; headers = 0;
	freez(astr);
	ASSERT_TRUE(astr = strdup(conn->tracking_id), err);
	ship_unlock(conn);
	ship_check_restricts();
	ASSERT_TRUE(pymod_tstate_ok(h->tstate), err2);

	result = PyObject_CallObject(h->callback, arglist);
	ASSERT_TRUE(result, err2);
	ASSERT_TRUE(PyInt_Check(result), err2);
	funcret = (int)PyInt_AsLong(result);
 err2:
	pymod_tstate_return();
	conn = netio_http_get_conn_by_id(astr); // dangerous.. should be ship_obj!!
 err:
	Py_XDECREF(val);
	Py_XDECREF(key);
	Py_XDECREF(result);
	Py_XDECREF(arglist);
	Py_XDECREF(params);
	Py_XDECREF(headers);
	ship_list_empty_free(l);
	ship_list_free(l);
	freez(astr);

	return funcret;
}

static PyObject *
p2pship_http_register(PyObject *self, PyObject *args)
	{
	const char *addr = 0;
	pymod_ipc_handler_t *h = 0;
	PyObject *func = NULL;
	int s = -1;
	
	if (!PyArg_ParseTuple(args, "Os:http_register", &func, &addr))
		goto err;

	LOG_DEBUG("Registering python http handler for %s\n", addr);
	ASSERT_TRUE(h = pymod_ipc_new(addr, func, NULL), err);
	
	if (strchr(addr, '@')) {
		char *tmp = 0, *pos = 0;
		if ((tmp = strdup(addr)))
			pos = strchr(tmp, ':');
		if (pos) {
			pos[0] = 0;
			s = extapi_register_p2phttp_handler(tmp, atoi(&pos[1]), NULL, -1,
							    pymod_http_process_req2, h);
			if (s/100 != 2)
				s = -1;
			else
				s = -2;
		}
		freez(tmp);
	} else {
		s = netio_http_server_create((char*)addr, pymod_http_process_req, h);
	}

	if (s != -1) {
		ship_ht_put_int(pymod_http_servers, s, h);
		h = 0;
		return PyInt_FromLong(s);
	} else {
		PyErr_SetString(PyExc_StandardError, "Could not bind address");
	}
 err:
	pymod_ipc_free(h);
	return NULL;
}

static PyObject *
p2pship_http_modif(PyObject *self, PyObject *args)
{
	const char *addr = 0;
	int handle = -1;

	if (!PyArg_ParseTuple(args, "is:http_modif", &handle, &addr))
		goto err;

	if (netio_http_server_modif(handle, (char*)addr)) {
		PyErr_SetString(PyExc_EnvironmentError, "Could not reassign server");
	}

	Py_INCREF(Py_None);
	return Py_None;
err:
	return NULL;
}

static PyObject *
p2pship_http_unregister(PyObject *self, PyObject *args)
{
	int handle = -1;

	// todo: test me!

	if (!PyArg_ParseTuple(args, "i:http_unregister", &handle))
		goto err;
	
	netio_http_server_close(handle);
	pymod_ipc_free(ship_ht_remove_int(pymod_http_servers, handle));
	Py_INCREF(Py_None);
	return Py_None;
 err:
	return NULL;
}

/**
 *
 *  the overlay storage handling 
 *
 **/
static int 
pymod_ol_put(char *key, char *data, int timeout, 
	     char *secret, int cached, struct olclient_module* mod) 
{ 
	/* calling put */
	pymod_ol_handler_t *h = (pymod_ol_handler_t*)mod->module_data;
	PyObject *arglist;
	PyObject *result;
	int ret = -1;
	
	ship_check_restricts();
	ASSERT_TRUE(pymod_tstate_ok(h->tstate), err);
	ASSERT_TRUE(arglist = Py_BuildValue("(ssis)", key, data, timeout, secret), err);
	result = PyObject_CallObject(h->put, arglist);
	Py_DECREF(arglist);
	ASSERT_TRUE(result, err);
	Py_DECREF(result);
	ret = 0;
 err:
	pymod_tstate_return();
	return ret;
}

static int 
pymod_ol_get(char *key, olclient_get_task_t *task) 
{
	pymod_ol_handler_t *h = (pymod_ol_handler_t*)task->mod->module_data;
	PyObject *arglist;
	PyObject *result;
	int ret = -1;
	/* pymod_ol_get_t *wait = NULL; */

	ship_check_restricts();
	ASSERT_TRUE(pymod_tstate_ok(h->tstate), err);
	ASSERT_TRUE(PyCallable_Check(h->get), err);

	ship_obj_ref(task);
	ship_ht_put_string(pymod_ol_gets, task->id, task);

	/* ASSERT_TRUE(wait = pymod_ol_get_new(task->callback, task->lookup, task->mod), err); */
	ASSERT_TRUE(arglist = Py_BuildValue("(ss)", key, task->id), err);
	result = PyObject_CallObject(h->get, arglist);
	Py_DECREF(arglist);
	ASSERT_TRUE(result, err);
	Py_DECREF(result);
 err:
	pymod_tstate_return();
	/* pymod_ol_get_free(wait); */
	return ret;
}

static int 
pymod_ol_remove(char *key, char* secret, struct olclient_module* mod) 
{ 
	pymod_ol_handler_t *h = (pymod_ol_handler_t*)mod->module_data;
	PyObject *arglist;
	PyObject *result;
	int ret = -1;
	
	ship_check_restricts();
	ASSERT_TRUE(pymod_tstate_ok(h->tstate), err);
	ASSERT_TRUE(arglist = Py_BuildValue("(ss)", key, secret), err);
	result = PyObject_CallObject(h->remove, arglist);
	Py_DECREF(arglist);
	ASSERT_TRUE(result, err);
	Py_DECREF(result);
	ret = 0;
 err:
	pymod_tstate_return();
	return ret;
}

static int 
pymod_ol_put_signed(char *key, char *data, ident_t *signer, 
		    int timeout, char *secret, int cached, struct olclient_module* mod) 
{ 
	return -1; 
}

static int 
pymod_ol_get_signed(char *key, olclient_signer_t *signer,
		    olclient_get_task_t *task)
{ 
	return -1; 
}

static 
void pymod_ol_close(struct olclient_module* mod)
{
	pymod_ol_handler_t *h = 0;
	PyObject *result;

	if (pymod_ol_clients)
		h = (pymod_ol_handler_t*)ship_list_remove(pymod_ol_clients, mod->module_data);

	ASSERT_TRUE(h, err);
	ship_check_restricts();
	ASSERT_TRUE(pymod_tstate_ok(h->tstate), err);
	result = PyObject_CallObject(h->close, NULL);
	ASSERT_TRUE(result, err);
	Py_DECREF(result);
 err:
	pymod_ol_free(h);
	pymod_tstate_return();
}


/* the struct, things needed for the interface. this template will be
   copied to create the instances. */
static struct olclient_module ol_python_module = {
	.get = pymod_ol_get,
	.remove = pymod_ol_remove,
	.put = pymod_ol_put,
	.put_signed = pymod_ol_put_signed,
	.get_signed = pymod_ol_get_signed,
	.close = pymod_ol_close,
};

/* python error

- set for the intepreter, return NULL or -1

PyErr_SetString()

- if subroutine sets (PyErr_Occured), then just return null/-1
- ..or if we want to clear the error, PyErr_Clear

*/

/* registers an handler. the handler functions should be set:
   
@param get
@param put
@param remove
@param close
@param name (just a string)
@param put_signed
@param get_signed

*/
static PyObject *
p2pship_register_ol_handler(PyObject *self, PyObject *args, PyObject *keywds)
{
	//PyObject *put = 0, *get = 0, *remove = 0, *close = 0, *put_signed = 0, *get_signed = 0;
	char *name = 0;
	pymod_ol_handler_t *h = NULL;
	static char *kwlist[] = { "name", "put", "get", "remove", "close", "put_signed", "get_signed", NULL};
	
	ASSERT_TRUE(h = mallocz(sizeof(*h)), mem_err);
	if (!PyArg_ParseTupleAndKeywords(args, keywds, "sOOOO|OO:register_ol_handler", kwlist,
					 &name, &h->put, &h->get, &h->remove, &h->close, &h->put_signed, &h->get_signed)) {
		goto err;
	}

	LOG_DEBUG("registering %s..\n", name);
	LOG_DEBUG("callable: put %x, get %x, rm %x, close %x, ps %x, gs %x\n", 
		  PyCallable_Check(h->put), PyCallable_Check(h->get), PyCallable_Check(h->remove), 
		  PyCallable_Check(h->close), PyCallable_Check(h->put_signed), PyCallable_Check(h->get_signed));

	Py_XINCREF(h->put);
	Py_XINCREF(h->get);
	Py_XINCREF(h->remove);
	Py_XINCREF(h->close);
	Py_XINCREF(h->put_signed);
	Py_XINCREF(h->get_signed);
	
	h->tstate = PyThreadState_Get();
	ASSERT_TRUE(h->name = strdup(name), mem_err);
	ASSERT_TRUE(h->mod = olclient_module_new(ol_python_module, name, h), mem_err);
	ship_list_add(pymod_ol_clients, h);

	/* these should probably be locked first .. */
	h->mod->put_signed = (PyCallable_Check(h->put_signed)? pymod_ol_put_signed : NULL);
	h->mod->get_signed = (PyCallable_Check(h->get_signed)? pymod_ol_get_signed : NULL);
	ASSERT_ZERO(olclient_register_module(h->mod), err);
	
	Py_INCREF(Py_None);
	return Py_None;
 mem_err:
	PyErr_SetString(PyExc_MemoryError, "Memory depleted");
 err:
	pymod_ol_free(h);
	return NULL;
}	

/* the p2pship extensions to the python environment */
static PyObject *
p2pship_ol_data_got(PyObject *self, PyObject *args)
{
	char *id = 0, *data = 0;
	int code = -1;
	olclient_get_task_t *task = 0;
	
	if (!PyArg_ParseTuple(args, "si|s", &id, &code, &data))
		return NULL;
	
	ship_lock(pymod_ol_gets);
	if ((task = ship_ht_get_string(pymod_ol_gets, id))) {
		if (task->callback) {
			task->callback((data? strdup(data):NULL), code, task);
			if (code < 1) {
				task->callback = NULL;
				ship_ht_remove_string(pymod_ol_gets, task->id);
				ship_obj_unref(task);
			}
		}
	}
	ship_unlock(pymod_ol_gets);
	
	Py_INCREF(Py_None);
	return Py_None;
}

/* checks whether we are alive still! */
static PyObject *
p2pship_alive(PyObject *self, PyObject *args)
{
	return Py_BuildValue("b", pymod_alive);
}

#ifdef CONFIG_SIP_ENABLED
#include "sipp.h"

/**
 * 
 * SIP message processing, client handlers
 *
 */

static int
pymod_sipp_client_handler(ident_t *ident, const char *remote_aor, addr_t *contact_addr, char **buf, int *len,
			  void *data)
{
	int ret = -1;
	char *addr = 0;
	pymod_ipc_handler_t *h = (pymod_ipc_handler_t*)data;
	PyObject *arglist = 0;
	PyObject *result = 0;
	
	ident_addr_addr_to_str(contact_addr, &addr);

	ship_unlock(ident);
	ship_check_restricts();
	ASSERT_TRUE(pymod_tstate_ok(h->tstate), err);
		
	ASSERT_TRUE(arglist = Py_BuildValue("(ssss#)", ident->sip_aor, remote_aor, addr, *buf, *len), err);

	result = PyObject_CallObject(h->callback, arglist);
	ASSERT_TRUE(result, err);

	if (PyString_Check(result)) {
		char *nbuf = 0;
		int nlen = 0;
		if (PyString_AsStringAndSize(result, &nbuf, &nlen) != -1) {
			freez(addr);
			ASSERT_TRUE(addr = mallocz(nlen+1), err);
			memcpy(addr, nbuf, nlen);
			freez(*buf);
			*buf = addr;
			*len = nlen;
			addr = 0;
			ret = 1; /* forward the new message */
		} else
			ret = -1; /* forward the old message */
	} else
		ret = 0; /* done with it, do NOT forward the message to the UA! */

 err:
	Py_XDECREF(arglist);
	Py_XDECREF(result);
	freez(addr);
	pymod_tstate_return();
	ship_lock(ident);
	return ret;
}


static int
pymod_sipp_request_handler(sipp_request_t *req, const char *remote_aor,
			   int *response_code, void *data)
{
	int ret = -1, retval = -1, retmsglen = -1;
	pymod_ipc_handler_t *h = (pymod_ipc_handler_t*)data;
	PyObject *arglist = 0, *result = 0;
	char *buf = 0;
	size_t len;
	const char *retmsg = NULL;
	char *aor = NULL;
	
	if (req->ident)
		aor = req->ident->sip_aor;
	else
		aor = req->local_aor;

	ship_unlock(req->ident);
	ship_check_restricts();
	ASSERT_TRUE(pymod_tstate_ok(h->tstate), err);

	ASSERT_ZERO(sipp_sip_to_str(req->evt->sip, &buf, &len), err);
	ASSERT_TRUE(arglist = Py_BuildValue("(sss#iii)", aor, remote_aor, buf, len, req->remote_msg, req->internally_generated, *response_code), err);
	result = PyObject_CallObject(h->callback, arglist);
	ASSERT_TRUE(result, err);

	/* return value can be one of:
	   - int : the return code (< 1000 = don't forward, code % 1000 => the return code
	   - string : replace the message with it
	   - tuple (int, string) : as above
	*/

	if (PyString_Check(result)) {
		retmsg = PyString_AsString(result);
		retmsglen = strlen(retmsg);
	} else if (PyInt_Check(result)) {
		retval = (int)PyInt_AsLong(result);
	} else if (PyTuple_Check(result) && PyArg_ParseTuple(result, "s#i", &retmsg, &retmsglen, &retval)) {
		/* pass */
	}

	ret = 1; /* continue.. */
	if (retmsg) {
		osip_event_t *evt = 0;

		ASSERT_TRUE(evt = osip_parse(retmsg, retmsglen), sip_err);
		ASSERT_TRUE(evt->sip, sip_err);
		
		osip_event_free(req->evt);
		req->evt = evt;
		ret = 0; /* done! */
		evt = NULL;
	sip_err:
		if (evt)
			osip_event_free(evt);
	}
	
	if (retval > -1) {
		*response_code = retval;
		ret = 0; /* done! */
	}
	
 err:
	freez(buf);
	Py_XDECREF(arglist);
	Py_XDECREF(result);
	pymod_tstate_return();
	ship_lock(req->ident);
	return ret;
}


static PyObject *
p2pship_sip_route_as_local(PyObject *self, PyObject *args)
{
	char *msg;
	int len = 0, filter = -1;
	PyObject *ret = 0;
	addr_t addr;
	
	if (!PyArg_ParseTuple(args, "s#|i:sip_route_as_local", &msg, &len, &filter))
		goto err;

	/* if nothing indicated, do not filter! */
	if (filter != 1)
		filter = 0;
	
	bzero(&addr, sizeof(addr));
	sipp_inject_local_message(msg, len, filter);
	ret = Py_None;
 err:
	Py_XINCREF(ret);
	return ret;
}

static PyObject *
p2pship_sip_route_as_remote(PyObject *self, PyObject *args)
{
	char *msg, *local_aor, *remote_aor;
	int len = 0, filter = -1;
	PyObject *ret = 0; //, *bypass = 0;
	ident_t *ident = 0;
	
	if (!PyArg_ParseTuple(args, "sss#|i:sip_route_as_remote", &local_aor, &remote_aor, &msg, &len, &filter))
		goto end;
	
	/* if nothing indicated, do not filter! */
	if (filter != 1)
		filter = 0;

	LOG_DEBUG("route as remote from %s (remote) to %s (local)\n", remote_aor, local_aor);
	/* get the ident to whom we should route this message */
	ASSERT_TRUE(ident = ident_find_by_aor(local_aor), err);
	ASSERT_ZERO(sipp_inject_remote_message(msg, len, ident, remote_aor, filter), err);
	ret = Py_None;
	goto end;
 err:
	PyErr_SetString(PyExc_StandardError, "System error");
 end:
	ship_obj_unlockref(ident);
	Py_XINCREF(ret);
	return ret;
}


static PyObject *
p2pship_register_sip_client_handler(PyObject *self, PyObject *args)
{
	PyObject *callback = 0;
	char *name = 0;
	int priority = 0;
	pymod_ipc_handler_t *h = 0;

	if (!PyArg_ParseTuple(args, "sO|i:register_sip_client_handler", &name, &callback, &priority))
		goto err;

	LOG_DEBUG("registering sip client handler for %s..\n", name);
	ASSERT_TRUE(h = pymod_ipc_new(name, callback, NULL), err);
	ship_list_add(pymod_callback_handlers, h);
	sipp_register_hook(pymod_sipp_client_handler, NULL, h, priority);

	LOG_DEBUG("registered sip client handler for %s done\n", name);
	Py_INCREF(Py_None);
	return Py_None;
 err:
	return NULL;
}	


static PyObject *
p2pship_register_sip_request_handler(PyObject *self, PyObject *args)
{
	PyObject *callback = 0;
	char *name = 0;
	int priority = 0;
	pymod_ipc_handler_t *h = 0;

	if (!PyArg_ParseTuple(args, "sO|i:register_sip_request_handler", &name, &callback, &priority))
		goto err;

	LOG_DEBUG("registering sip request handler for %s..\n", name);
	ASSERT_TRUE(h = pymod_ipc_new(name, callback, NULL), err);
	ship_list_add(pymod_callback_handlers, h);
	sipp_register_hook(NULL, pymod_sipp_request_handler, h, priority);

	LOG_DEBUG("registered sip request handler for %s done\n", name);
	Py_INCREF(Py_None);
	return Py_None;
 err:
	return NULL;
}

/**
 * returns the local SIP proxy's contact address for the given user.
 * The default if None
 */
static PyObject *
p2pship_sip_get_local_contact(PyObject *self, PyObject *args)
{
	char *aor = 0, *str = 0;
	addr_t addr;
	ident_t *ident = 0;
	PyObject *ret = 0;

	if (!PyArg_ParseTuple(args, "|s:sip_get_local_contact", &aor)) {
		goto end;
	}

	if (aor && strlen(aor)) {
		ASSERT_TRUE(ident = ident_find_by_aor(aor), err);
	}
	bzero(&addr, sizeof(addr));
	sipp_get_addr_to_ua_or_default(ident, &addr);
	ASSERT_ZERO(ident_addr_addr_to_str(&addr, &str), err);
	ASSERT_TRUE(ret = Py_BuildValue("s", str), err);
	goto end;
 err:
	PyErr_SetString(PyExc_StandardError, "System error");
 end:
	ship_obj_unlockref(ident);
	freez(str);
	Py_XINCREF(ret);
	return ret;
}

#include "access_control.h"

static int
pymod_ac_filter(ac_sip_t *asip, void *data)
{
	PyObject *arglist = 0, *result = 0;
	pymod_ipc_handler_t *h = (pymod_ipc_handler_t *)data;
	char *msg = NULL;
	int msglen = -1;
	
	ASSERT_ZERO(sipp_sip_to_str(asip->req->evt->sip, &msg, (unsigned int*)&msglen), err);
	
	ship_check_restricts();
	ASSERT_TRUE(pymod_tstate_ok(h->tstate), err);
	ASSERT_TRUE(arglist = Py_BuildValue("(sssssiii)", msg, asip->req->local_aor, asip->req->remote_aor, asip->from, asip->to, 
					    asip->verdict, asip->req->remote_msg, asip->req->internally_generated), err);
	
	result = PyObject_CallObject(h->callback, arglist);
	Py_DECREF(arglist);
	ASSERT_TRUE(result, err);

	if (PyInt_Check(result))
	    asip->verdict = (int)PyInt_AsLong(result);
	Py_DECREF(result);
 err:
	freez(msg);
	pymod_tstate_return();
	return 1;
}

static PyObject *
p2pship_ac_add_filter(PyObject *self, PyObject *args)
{
	PyObject *ret = 0, *callback = 0, *data = 0;
	pymod_ipc_handler_t *ipc = NULL;
	
	if (!PyArg_ParseTuple(args, "O|O:ac_add_filter", &callback, &data)) {
		goto end;
	}
	
	ASSERT_TRUE(ipc = pymod_ipc_new("message filter", callback, data), err);
	ASSERT_ZERO(ac_packetfilter_add(pymod_ac_filter, ipc, 0), err);
	
	ret = Py_None;
	goto end;
 err:
	PyErr_SetString(PyExc_StandardError, "System error");
	pymod_ipc_free(ipc);
 end:
	Py_XINCREF(ret);
	return ret;
}

#endif


/**
 *
 * small, inefficient persistent storage
 *
 */
static PyObject *
p2pship_db_get(PyObject *self, PyObject *args)
{
	const char *appid = 0, *table = 0, *key = 0;
	PyObject *ret = NULL;

	if (!PyArg_ParseTuple(args, "sss", &appid, &table, &key))
		goto err;
	
	LOG_HL("should get %s/%s: %s\n", appid, table, key);

	Py_INCREF(Py_None);
	ret = Py_None;
 err:
	return ret;
}	

static PyObject *
p2pship_db_set(PyObject *self, PyObject *args)
{
	const char *appid = 0, *table = 0, *key = 0, *value = 0;
	PyObject *ret = NULL;

	if (!PyArg_ParseTuple(args, "ssss", &appid, &table, &key, &value))
		goto err;
	
	LOG_HL("should set %s/%s: %s to %s\n", appid, table, key, value);

	Py_INCREF(Py_None);
	ret = Py_None;
 err:
	return ret;
}	

static PyObject *
p2pship_db_del(PyObject *self, PyObject *args)
{
	const char *appid = 0, *table = 0, *key = 0;
	PyObject *ret = NULL;

	if (!PyArg_ParseTuple(args, "sss", &appid, &table, &key))
		goto err;
	
	LOG_HL("should del %s/%s: %s\n", appid, table, key);

	Py_INCREF(Py_None);
	ret = Py_None;
 err:
	return ret;
}	

static PyObject *
p2pship_db_get_keys(PyObject *self, PyObject *args)
{
	const char *appid = 0, *table = 0;
	PyObject *ret = NULL;

	if (!PyArg_ParseTuple(args, "ss", &appid, &table))
		goto err;
	
	LOG_HL("should get keys for %s/%s\n", appid, table);

	Py_INCREF(Py_None);
	ret = Py_None;
 err:
	return ret;
}	

static PyObject *
p2pship_db_get_values(PyObject *self, PyObject *args)
{
	const char *appid = 0, *table = 0;
	PyObject *ret = NULL;

	if (!PyArg_ParseTuple(args, "ss", &appid, &table))
		goto err;
	
	LOG_HL("should get values for %s/%s\n", appid, table);

	Py_INCREF(Py_None);
	ret = Py_None;
 err:
	return ret;
}	

/*
 * identities
 *
 */

static PyObject *
p2pship_get_idents(PyObject *self, PyObject *args)
{
	PyObject *ret = NULL, *str = 0;
	ship_obj_list_t *idents = 0;
	void *ptr = 0;
	ident_t *ident = 0;
	
	ASSERT_TRUE(idents = ident_get_identities(), err);
	ship_lock(idents);
	ASSERT_TRUE(ret = PyList_New(0), err);

	while ((ident = ship_list_next(idents, &ptr))) {
		ASSERT_TRUE(str = PyString_FromString(ident->sip_aor), err);
		ASSERT_ZERO(PyList_Append(ret, str), err);
		str = NULL;
	}
	goto end;
 err:
	Py_XDECREF(str);
	Py_XDECREF(ret);
	Py_INCREF(Py_None);
	ret = Py_None;
 end:
	ship_unlock(idents);
	return ret;
}	


//#pragma GCC diagnostic push
//#pragma GCC diagnostic ignore "-fno-strict-aliasing"

static PyObject *
pymod_create_ship_obj(ship_obj_t *obj)
{
	PyObject *ret = NULL, *str = NULL;
	

	ASSERT_TRUE(ret = PyDict_New(), err);
	ASSERT_TRUE(str = PyString_FromString(obj->_ship_obj_type.obj_name), err);
	ASSERT_ZERO(PyDict_SetItemString(ret, "name", str), err);
	str = NULL;

	ASSERT_TRUE(str = PyInt_FromLong(obj->_ship_obj_type.obj_size), err);
	ASSERT_ZERO(PyDict_SetItemString(ret, "size", str), err);
	str = NULL;
	
	return ret;
 err:
	Py_XDECREF(str);
	Py_XDECREF(ret);
	return NULL;
}

static PyObject *
pymod_create_ident(ident_t *ident)
{
	PyObject *ret = NULL, *str = NULL, *bud = NULL, *buds = NULL;
	BIO *bio = NULL;
	char *cert = NULL;
	int bufsize;
	void *ptr = 0;
	buddy_t *buddy = 0;

	ASSERT_TRUE(ret = PyDict_New(), err);
	ASSERT_TRUE(str = PyString_FromString(zdefault(ident->sip_aor, "")), err);
	ASSERT_ZERO(PyDict_SetItemString(ret, "aor", str), err);
	str = NULL;

	ASSERT_TRUE(str = PyString_FromString(zdefault(ident->username, "")), err);
	ASSERT_ZERO(PyDict_SetItemString(ret, "name", str), err);
	str = NULL;
	
	ASSERT_TRUE(str = PyString_FromString(zdefault(ident->password, "")), err);
	ASSERT_ZERO(PyDict_SetItemString(ret, "password", str), err);
	str = NULL;
	
	ASSERT_TRUE(str = PyString_FromString(zdefault(ident->status, "")), err);
	ASSERT_ZERO(PyDict_SetItemString(ret, "status", str), err);
	str = NULL;

	/* cert */
	ASSERT_TRUE(bio = BIO_new(BIO_s_mem()), err);
	ASSERT_TRUE(PEM_write_bio_X509(bio, ident->cert), err);
	ASSERT_TRUE(bufsize = BIO_get_mem_data(bio, &cert), err);
	//cert[bufsize] = 0;

	ASSERT_TRUE(str = PyString_FromStringAndSize(cert, bufsize), err);
	ASSERT_ZERO(PyDict_SetItemString(ret, "cert", str), err);
	str = NULL;

	/* key */
	BIO_free(bio);
	ASSERT_TRUE(bio = BIO_new(BIO_s_mem()), err);
	ASSERT_TRUE(PEM_write_bio_RSAPrivateKey(bio, ident->private_key, NULL, NULL, 0, NULL, NULL), err);
	ASSERT_TRUE(bufsize = BIO_get_mem_data(bio, &cert), err);
	//cert[bufsize] = 0;

	ASSERT_TRUE(str = PyString_FromStringAndSize(cert, bufsize), err);
	ASSERT_ZERO(PyDict_SetItemString(ret, "key", str), err);
	str = NULL;
	
	/* buddies */
	ASSERT_TRUE(buds = PyList_New(0), err);
	while ((buddy = ship_list_next(ident->buddy_list, &ptr))) {
		ASSERT_TRUE(bud = PyDict_New(), err);

		ASSERT_TRUE(str = PyString_FromString(zdefault(buddy->sip_aor, "")), err);
		ASSERT_ZERO(PyDict_SetItemString(bud, "aor", str), err);
		str = NULL;

		ASSERT_TRUE(str = PyString_FromString(zdefault(buddy->name, "")), err);
		ASSERT_ZERO(PyDict_SetItemString(bud, "name", str), err);
		str = NULL;

		ASSERT_TRUE(str = PyString_FromString(zdefault(buddy->shared_secret, "")), err);
		ASSERT_ZERO(PyDict_SetItemString(bud, "secret", str), err);
		str = NULL;

		if (buddy->cert) {
			BIO_free(bio);
			ASSERT_TRUE(bio = BIO_new(BIO_s_mem()), err);
			ASSERT_TRUE(PEM_write_bio_X509(bio, buddy->cert), err);
			ASSERT_TRUE(bufsize = BIO_get_mem_data(bio, &cert), err);
			//cert[bufsize] = 0;
			
			ASSERT_TRUE(str = PyString_FromStringAndSize(cert, bufsize), err);
			ASSERT_ZERO(PyDict_SetItemString(bud, "cert", str), err);
			str = NULL;
		}
		/* won't compile on maemo due to dereferencing of the _PyTrue_Struct */
		str = PyInt_FromLong((long)buddy->relationship);
		ASSERT_ZERO(PyDict_SetItemString(bud, "relationship", str), err);
		ASSERT_ZERO(PyList_Append(buds, bud), err);
		bud = NULL;
	}
	ASSERT_ZERO(PyDict_SetItemString(ret, "buddies", buds), err);
	buds = NULL;
	goto end;
 err:
	Py_XDECREF(str);
 	Py_XDECREF(ret);
 	Py_XDECREF(bud);
 	Py_XDECREF(buds);
	ret = NULL;
 end:
	if (bio) BIO_free(bio);
	return ret;
}

/* returns an identity object. if aor = null, then the default one */
static PyObject *
p2pship_get_ident(PyObject *self, PyObject *args)
{
	const char *aor = 0;
	PyObject *ret = NULL;
	ident_t *ident = 0;

	if (!PyArg_ParseTuple(args, "|s", &aor))
		goto err;

	ASSERT_TRUE(ident = pymod_valid_ident_or_default(aor), err);
	ASSERT_TRUE(ret = pymod_create_ident(ident), err);
	goto end;
 err:
	PyErr_SetString(PyExc_StandardError, "System error");
 end:
	if (!ret) {
		LOG_WARN("Could not find identity %s\n", aor);
	}
	ship_obj_unlockref(ident);
	return ret;
}	
//#pragma GCC diagnostic pop

/* returns a reg packet that .. is ref'd */
static PyObject *
pymod_create_reg(reg_package_t *reg)
{
	char *astr = 0;
	addr_t *addr = 0;
	PyObject *ret = NULL, *str = NULL, *l = NULL, *str2 = NULL;
	BIO *bio = NULL;
	char *cert = NULL;
	int bufsize;
	void *ptr = 0;
	char *key, *value;

	ASSERT_TRUE(ret = PyDict_New(), err);
	ASSERT_TRUE(str = PyString_FromString(zdefault(reg->sip_aor, "")), err);
	ASSERT_ZERO(PyDict_SetItemString(ret, "aor", str), err);
	str = NULL;

	ASSERT_TRUE(str = PyString_FromString(zdefault(reg->name, "")), err);
	ASSERT_ZERO(PyDict_SetItemString(ret, "name", str), err);
	str = NULL;
	
	ASSERT_TRUE(str = PyInt_FromLong((long)reg->created), err);
	ASSERT_ZERO(PyDict_SetItemString(ret, "created", str), err);
	str = NULL;

	ASSERT_TRUE(str = PyInt_FromLong((long)reg->valid), err);
	ASSERT_ZERO(PyDict_SetItemString(ret, "valid", str), err);
	str = NULL;

	ASSERT_TRUE(str = PyInt_FromLong((long)reg->imported), err);
	ASSERT_ZERO(PyDict_SetItemString(ret, "imported", str), err);
	str = NULL;

	if (ident_reg_is_valid(reg)) {
		str = PyInt_FromLong((long)1);
	} else {
		str = PyInt_FromLong((long)0);
	}
	ASSERT_ZERO(PyDict_SetItemString(ret, "is_valid", str), err);
	str = NULL;

	if (reg->need_update) {
		str = PyInt_FromLong((long)1);
	} else {
		str = PyInt_FromLong((long)0);
	}
	ASSERT_ZERO(PyDict_SetItemString(ret, "need_update", str), err);
	str = NULL;
	
	ASSERT_TRUE(str = PyString_FromString(zdefault(reg->status, "")), err);
	ASSERT_ZERO(PyDict_SetItemString(ret, "status", str), err);
	str = NULL;

	/* cert */
	ASSERT_TRUE(bio = BIO_new(BIO_s_mem()), err);
	ASSERT_TRUE(PEM_write_bio_X509(bio, reg->cert), err);
	ASSERT_TRUE(bufsize = BIO_get_mem_data(bio, &cert), err);
	//cert[bufsize] = 0;

	ASSERT_TRUE(str = PyString_FromStringAndSize(cert, bufsize), err);
	ASSERT_ZERO(PyDict_SetItemString(ret, "cert", str), err);
	str = NULL;
	
	/* the addresses */
	ASSERT_TRUE(l = PyList_New(0), err);
	while ((addr = ship_list_next(reg->ip_addr_list, &ptr))) {
		ASSERT_ZERO(ident_addr_addr_to_str(addr, &astr), err);
		ASSERT_TRUE(str = PyString_FromString(zdefault(astr, "")), err);
		freez(astr);
		
		ASSERT_ZERO(PyList_Append(l, str), err);
		str = NULL;
	}
	ASSERT_ZERO(PyDict_SetItemString(ret, "ip", l), err);
	
	ptr = NULL;
	ASSERT_TRUE(l = PyList_New(0), err);
	while ((addr = ship_list_next(reg->rvs_addr_list, &ptr))) {
		ASSERT_ZERO(ident_addr_addr_to_str(addr, &astr), err);
		ASSERT_TRUE(str = PyString_FromString(zdefault(astr, "")), err);
		freez(astr);
		
		ASSERT_ZERO(PyList_Append(l, str), err);
		str = NULL;
	}
	ASSERT_ZERO(PyDict_SetItemString(ret, "rvs", l), err);

	ptr = NULL;
	ASSERT_TRUE(l = PyList_New(0), err);
	while ((addr = ship_list_next(reg->hit_addr_list, &ptr))) {
		ASSERT_ZERO(ident_addr_addr_to_str(addr, &astr), err);
		ASSERT_TRUE(str = PyString_FromString(zdefault(astr, "")), err);
		freez(astr);
		
		ASSERT_ZERO(PyList_Append(l, str), err);
		str = NULL;
	}
	ASSERT_ZERO(PyDict_SetItemString(ret, "hit", l), err);

	/** app data **/
	ptr = NULL;
	ASSERT_TRUE(l = PyDict_New(), err);
	while ((value = ship_ht_next_with_key(reg->app_data, &ptr, &key))) {
		ASSERT_TRUE(str = PyString_FromString(value), err);
		
		ASSERT_ZERO(PyDict_SetItemString(l, key, str), err);
		str = NULL;
		str2 = NULL;
	}
	ASSERT_ZERO(PyDict_SetItemString(ret, "applications", l), err);

	goto end;
 err:
	Py_XDECREF(str);
	Py_XDECREF(str2);
 	Py_XDECREF(ret);
 	Py_XDECREF(l);
	ret = NULL;
 end:
	freez(astr);
	return ret;
}

static PyObject *
p2pship_import_reg(PyObject *self, PyObject *args)
{
	const char *regxml = 0;
	reg_package_t *reg = 0;
	PyObject *ret = NULL;
	
	if (!PyArg_ParseTuple(args, "s", &regxml))
		goto end;
	
	ASSERT_ZEROS(ident_reg_xml_to_struct(&reg, regxml), err, "Malformatted reg package '%s'!\n", regxml);
	ASSERT_TRUE(ret = pymod_create_reg(reg), err);
	if (ident_import_foreign_reg(reg)) {
		Py_XDECREF(ret);
		ret = Py_None;
		Py_XINCREF(ret);
	}
	goto end;
 err:
	PyErr_SetString(PyExc_StandardError, "System error");
 end:
	return ret;
}	

static PyObject *
p2pship_get_reg(PyObject *self, PyObject *args)
{
	char *local = 0, *remote = 0;
	reg_package_t *reg = 0;
	PyObject *ret = NULL, *callback = NULL;
	
	if (!PyArg_ParseTuple(args, "s|sO", &remote, &local, &callback))
		goto end;
	
	// todo: support for async!
	//ASSERT_ZERO(ident_lookup_registration(NULL, remote, &reg, NULL), err);

	if ((reg = ident_find_foreign_reg(remote))) {
		ASSERT_TRUE(ret = pymod_create_reg(reg), err);
	} else {
		ret = Py_None;
		Py_INCREF(ret);
	}
	goto end;
 err:
	PyErr_SetString(PyExc_StandardError, "System error");
 end:
	ship_unlock(reg);
	return ret;
}	


static PyObject *
p2pship_set_service_param(PyObject *self, PyObject *args)
{
	char *aor = 0, *key = 0, *value = 0;
	int service = 0;
	ident_t *ident = 0;
	PyObject *ret = NULL;
	
	if (!PyArg_ParseTuple(args, "siss", &aor, &service, &key, &value))
		goto end;
	
	ASSERT_TRUE(ident = pymod_valid_ident_or_default(aor), err);
	ASSERT_ZERO(ident_set_service_param(ident, service, key, value), err);
	
	ret = Py_None;
	Py_INCREF(ret);
	goto end;
 err:
	PyErr_SetString(PyExc_StandardError, "System error");
 end:
	ship_obj_unlockref(ident);
	return ret;
}	

static PyObject *
p2pship_remove_service_param(PyObject *self, PyObject *args)
{
	char *aor = 0, *key = 0;
	int service = 0;
	ident_t *ident = 0;
	PyObject *ret = NULL;
	
	if (!PyArg_ParseTuple(args, "sis", &aor, &service, &key))
		goto end;
	
	ASSERT_TRUE(ident = pymod_valid_ident_or_default(aor), err);
	ASSERT_ZERO(ident_remove_service_param(ident, service, key), err);
	
	ret = Py_None;
	Py_INCREF(ret);
	goto end;
 err:
	PyErr_SetString(PyExc_StandardError, "System error");
 end:
	ship_obj_unlockref(ident);
	return ret;
}	

static PyObject *
p2pship_get_service_param(PyObject *self, PyObject *args)
{
	char *aor = 0, *key = 0;
	int service = 0;
	ident_t *ident = 0;
	const char *value = 0;
	PyObject *ret = NULL;
	
	if (!PyArg_ParseTuple(args, "sis", &aor, &service, &key))
		goto end;
	
	ASSERT_TRUE(ident = pymod_valid_ident_or_default(aor), err);
	ASSERT_TRUE(value = ident_get_service_param(ident, service, key), err);
	ASSERT_TRUE(ret = PyString_FromString(value), err);
	goto end;
 err:
	PyErr_SetString(PyExc_StandardError, "System error");
 end:
	ship_obj_unlockref(ident);
	return ret;
}	



/*
 * ol-identity handling
 */

static void 
pymod_getsub_cb(char *key, char *data, char *signer, void *param, int status)
{
	pymod_ipc_handler_t *h = param;
	PyObject *result = 0, *arglist = 0;
	
	if (status < 0 || !data || !key)
		return;
	
	ship_check_restricts();
	ASSERT_TRUE(pymod_tstate_ok(h->tstate), err);
	if (h->callback2) {
		ASSERT_TRUE(arglist = Py_BuildValue("(sssO)", key, data, signer, h->callback2), err);
	} else {
		ASSERT_TRUE(arglist = Py_BuildValue("(sss)", key, data, signer), err);
	}
	
	result = PyObject_CallObject(h->callback, arglist);
	Py_DECREF(arglist);
	ASSERT_TRUE(result, err);
	Py_DECREF(result);
 err:
	if (status < 1) {
		pymod_ipc_free(h);	
	}
	pymod_tstate_return();
}

/* gets something. params: local ident aor, remote aor, data key, callback, callback data */
static PyObject *
p2pship_ol_ident_getsub(PyObject *self, PyObject *args, const int subscribe)
{
	const char *local_aor = 0, *remote_aor = 0, *key = 0;
	PyObject *callback = NULL, *ret = NULL, *data = NULL, *remote = NULL;
	pymod_ipc_handler_t *h = NULL;
	ident_t *ident = NULL;
	int handle = -1;
	
	if (!PyArg_ParseTuple(args, "sOsO|O", &local_aor, &remote, &key, &callback, &data))
		goto end;
	
	ASSERT_TRUE(ident = pymod_valid_ident_or_default(local_aor), err);
	
	ASSERT_TRUE(h = pymod_ipc_new("ident_get", callback, data), err);
	if ((remote_aor = pymod_string_or_none(remote))) {
		handle = ident_ol_getsub_for_buddy_by_aor(ident, remote_aor, key, h, pymod_getsub_cb, subscribe);
	} else {
		handle = ident_ol_getsub_for_all_buddies(ident, key, h, pymod_getsub_cb, subscribe);
	}
	ASSERT_TRUE(handle != -1, err);
	ASSERT_TRUE(ret = PyInt_FromLong(handle), err);
	goto end;
 err:
	PyErr_SetString(PyExc_StandardError, "System error");
	pymod_ipc_free(h);
 end:
	ship_obj_unlockref(ident);
	return ret;
}

static PyObject *
p2pship_ol_ident_get(PyObject *self, PyObject *args)
{
	return p2pship_ol_ident_getsub(self, args, 0);
}

static PyObject *
p2pship_ol_ident_subscribe(PyObject *self, PyObject *args)
{
	return p2pship_ol_ident_getsub(self, args, 1);
}

static PyObject*
p2pship_ol_cancel(PyObject *self, PyObject *args)
{
	PyObject *ret = NULL;
	int handle = -1;

	if (!PyArg_ParseTuple(args, "i", &handle))
		goto end;
	
	ASSERT_POSITIVE(handle, err);
	olclient_cancel(handle);

	Py_INCREF(Py_None);
	ret = Py_None;
	goto end;
 err:
	PyErr_SetString(PyExc_StandardError, "Invalid handle");
 end:
	return ret;
}

static PyObject *
p2pship_ol_ident_put(PyObject *self, PyObject *args)
{
	const char *local_aor = 0, *remote_aor = 0, *key = 0, *data = NULL;
	int timeout = 3600, require_priv = 0;
	ident_t *ident = NULL;
	PyObject *ret = NULL, *remote = NULL;
	
	if (!PyArg_ParseTuple(args, "sOss|ii", &local_aor, &remote, &key, &data, &timeout, &require_priv))
		goto end;
	
	ASSERT_TRUE(ident = pymod_valid_ident_or_default(local_aor), err);

	if ((remote_aor = pymod_string_or_none(remote))) {
		ASSERT_ZERO(ident_ol_put_for_buddy_by_aor(ident, remote_aor, key, data, timeout, require_priv), err);
	} else {
		ASSERT_ZERO(ident_ol_put_for_all_buddies(ident, key, data, timeout, require_priv), err);
	}
	
	Py_INCREF(Py_None);
	ret = Py_None;
	goto end;
 err:
	PyErr_SetString(PyExc_StandardError, "System error");
 end:
	ship_obj_unlockref(ident);
	return ret;
}

static PyObject *
p2pship_ol_ident_rm(PyObject *self, PyObject *args)
{
	const char *local_aor = 0, *remote_aor = 0, *key = 0;
	ident_t *ident = NULL;
	PyObject *ret = NULL, *remote = NULL;
	
	if (!PyArg_ParseTuple(args, "sOs", &local_aor, &remote, &key))
		goto end;
	
	ASSERT_TRUE(ident = pymod_valid_ident_or_default(local_aor), err);

	if ((remote_aor = pymod_string_or_none(remote))) {
		ASSERT_ZERO(ident_ol_remove_for_buddy_by_aor(ident, remote_aor, key), err);
	} else {
		ASSERT_ZERO(ident_ol_remove_for_all_buddies(ident, key), err);
	}

	Py_INCREF(Py_None);
	ret = Py_None;
	goto end;
 err:
	PyErr_SetString(PyExc_StandardError, "System error");
 end:
	ship_obj_unlockref(ident);
	return ret;
}

#ifdef CONFIG_MEDIA_ENABLED

static void
pymod_media_cb(const int handle, const char *msgtype, const char *data, void *userdata)
{
	pymod_ipc_handler_t *h = (pymod_ipc_handler_t*)userdata;
	PyObject *result = 0, *arglist = 0;
	
	ship_check_restricts();
	ASSERT_TRUE(pymod_tstate_ok(h->tstate), err);
	ASSERT_TRUE(arglist = Py_BuildValue("(iss)", handle, msgtype, data), err);
	
	result = PyObject_CallObject(h->callback, arglist);
	Py_DECREF(arglist);
	ASSERT_TRUE(result, err);
	Py_DECREF(result);
 err:
	if (!strcmp(msgtype, "destroy")) {
		pymod_ipc_free(userdata);
	}
	pymod_tstate_return();
}

/** media handling */
static PyObject *
p2pship_media_pipeline_parse(PyObject *self, PyObject *args)
{
	char *str = 0;
	PyObject *ret = NULL, *callback = NULL;
	int handle = -1;
	pymod_ipc_handler_t *userdata = NULL;
	PyThreadState *tstate = NULL;
	
	if (!PyArg_ParseTuple(args, "s|O", &str, &callback))
		goto end;

	if (callback) {
		ASSERT_TRUE(userdata = pymod_ipc_new("mediaobserver", callback, NULL), err);
	}
	
	// release GIL as otherwise we will end up in a deadlock!
	ASSERT_TRUE(tstate = PyThreadState_Get(), end);
	pymod_tstate_return();
	
	handle = media_parse_pipeline(str, (userdata? pymod_media_cb : NULL), userdata);
	ship_check_restricts();
	pymod_tstate_ok(tstate);

	ASSERT_POSITIVE(handle, err);
	ASSERT_TRUE(ret = PyInt_FromLong(handle), err);
	goto end;
 err:
	PyErr_SetString(PyExc_StandardError, "Error creating pipeline");
	pymod_ipc_free(userdata);
 end:
	return ret;
}	

static PyObject *
p2pship_media_pipeline_start(PyObject *self, PyObject *args)
{
	PyObject *ret = NULL;
	int handle = -1;
	PyThreadState *tstate = NULL;
	
	if (!PyArg_ParseTuple(args, "i", &handle))
		goto end;

	ASSERT_TRUE(tstate = PyThreadState_Get(), end);
	pymod_tstate_return();

	handle = media_pipeline_start(handle);
	ship_check_restricts();
	pymod_tstate_ok(tstate);

	ASSERT_ZERO(handle, err);

	ret = Py_None;
	Py_INCREF(ret);
	goto end;
 err:
	PyErr_SetString(PyExc_StandardError, "Error starting pipeline");
 end:
	return ret;
}	

static PyObject *
p2pship_media_pipeline_destroy(PyObject *self, PyObject *args)
{
	PyObject *ret = NULL;
	int handle = -1;
	PyThreadState *tstate = NULL;
	
	if (!PyArg_ParseTuple(args, "i", &handle))
		goto end;

	ASSERT_TRUE(tstate = PyThreadState_Get(), end);
	pymod_tstate_return();

	handle = media_pipeline_destroy(handle);
	ship_check_restricts();
	pymod_tstate_ok(tstate);
	ASSERT_ZERO(handle, err);
	ret = Py_None;
	Py_INCREF(ret);
	goto end;
 err:
	PyErr_SetString(PyExc_StandardError, "Error destroying pipeline");
 end:
	return ret;
}	

static PyObject *
p2pship_media_check_element(PyObject *self, PyObject *args)
{
	PyObject *ret = NULL;
	const char *elm = NULL;
	
	if (!PyArg_ParseTuple(args, "s", &elm))
		goto end;

	ret = PyInt_FromLong((long)media_check_element(elm));
 end:
	return ret;
}	

#endif


static PyObject*
p2pship_resourcefetch_store(PyObject *self, PyObject *args)
{
	PyObject *ret = NULL;
	char *filename = NULL, *recipient = NULL;
	char *id = NULL;
	int expire = 3600;
	
	if (!PyArg_ParseTuple(args, "s|is", &filename, &expire, &recipient))
		goto end;
	
	ASSERT_ZERO(resourcefetch_store(filename, expire, recipient, &id), err);
	ASSERT_TRUE(ret = PyString_FromString(id), err);
	goto end;
 err:
	PyErr_SetString(PyExc_StandardError, "Error storing resource");
 end:
	freez(id);
	return ret;
}	

static PyObject*
p2pship_resourcefetch_remove(PyObject *self, PyObject *args)
{
	PyObject *ret = NULL;
	char *id = NULL;
	
	if (!PyArg_ParseTuple(args, "s", &id))
		goto end;
	
	ASSERT_ZERO(resourcefetch_remove(id), err);
	ret = Py_None;
	Py_INCREF(ret);
	goto end;
 err:
	PyErr_SetString(PyExc_StandardError, "Error removing resource, not stored?");
 end:
	return ret;
}	

static void
p2pship_resourcefetch_get_cb(void *param, char *host, char *rid, char *data, int datalen)
{
	pymod_ipc_handler_t *h = (pymod_ipc_handler_t *)param;
	PyObject *arglist = NULL, *result = NULL;
	
	ship_check_restricts();
	ASSERT_TRUE(pymod_tstate_ok(h->tstate), err);
	if (h->callback2) {
		ASSERT_TRUE(arglist = Py_BuildValue("(sss#O)", host, rid, data, datalen, h->callback2), err);
	} else {
		ASSERT_TRUE(arglist = Py_BuildValue("(sss#)", host, rid, data, datalen), err);
	}
	result = PyObject_CallObject(h->callback, arglist);
	Py_DECREF(arglist);
	ASSERT_TRUE(result, err);
	Py_DECREF(result);
 err:
	pymod_ipc_free(h);
	pymod_tstate_return();
}

static PyObject*
p2pship_resourcefetch_get(PyObject *self, PyObject *args)
{
	PyObject *ret = NULL, *callback = NULL, *cbdata;
	char *id = NULL, *local = NULL, *remote = NULL;
	pymod_ipc_handler_t *h = NULL;
	
	/* remote, id, local, callback */
	if (!PyArg_ParseTuple(args, "sssO|O", &remote, &id, &local, &callback, &cbdata))
		goto end;
	
	ASSERT_TRUE(h = pymod_ipc_new("resourcefetch", callback, cbdata), err);
	ASSERT_ZERO(resourcefetch_get(remote, id, local, p2pship_resourcefetch_get_cb, h), err);
	ret = Py_None;
	Py_INCREF(ret);
	goto end;
 err:
	PyErr_SetString(PyExc_StandardError, "Error retrieving resource.");
	pymod_ipc_free(h);
 end:
	return ret;
}	

/**
 *
 * UI
 */

static PyObject*
p2pship_ui_popup(PyObject *self, PyObject *args)
{
	char *data = NULL;
	
	/* string only */
	if (!PyArg_ParseTuple(args, "s", &data))
		goto err;
	
	ui_popup(data);
	Py_INCREF(Py_None);
	return Py_None;
 err:
	return NULL;
}	

static PyObject*
p2pship_ui_query_simple(PyObject *self, PyObject *args)
{
	char *header = NULL, *body = NULL, *trueop = NULL, *falseop = NULL;
	PyObject *ret = NULL	;
	int val = -1;
	
	/* string only */
	if (!PyArg_ParseTuple(args, "ssss", &header, &body, &trueop, &falseop))
		goto end;
	
	val = ui_query_simple(header, body, trueop, falseop);
	ASSERT_TRUE(ret = PyInt_FromLong(val), err);
	return ret;
 err:
	PyErr_SetString(PyExc_StandardError, "Error creating return value.");
 end:
	return NULL;
}	

static PyObject*
p2pship_ui_query_three(PyObject *self, PyObject *args)
{
	char *header = NULL, *body = NULL, *oneop = NULL, *twoop = NULL, *threeop = NULL;
	PyObject *ret = NULL	;
	int val = -1;
	
	/* string only */
	if (!PyArg_ParseTuple(args, "sssss", &header, &body, &oneop, &twoop, &threeop))
		goto end;
	
	val = ui_query_three(header, body, oneop, twoop, threeop);
	ASSERT_TRUE(ret = PyInt_FromLong(val), err);
	return ret;
 err:
	PyErr_SetString(PyExc_StandardError, "Error creating return value.");
 end:
	return NULL;
}	

static PyObject*
p2pship_ui_query_filechooser(PyObject *self, PyObject *args)
{
	char *header = NULL, *title = NULL, *dir = NULL;
	PyObject *ret = NULL, *filetypes = NULL;
	char *filename = NULL;
	ship_list_t *ft = NULL;
	
	/* string only */
	if (!PyArg_ParseTuple(args, "sss|O", &header, &title, &dir, &filetypes))
		goto end;
	
	if (filetypes) {
		ssize_t s, i;

		ASSERT_TRUE(PyTuple_Check(filetypes), err);
		s = PyTuple_Size(filetypes);
		if (s > 0) {
			ASSERT_TRUE(ft = ship_list_new(), err);
			for (i = 0; i < s; i++) {
				char *val = NULL;
				
				PyObject *item = NULL;
				ASSERT_TRUE(item = PyTuple_GetItem(filetypes, i), err);
				ASSERT_TRUE(val = PyString_AsString(item), err);

				ship_list_add(ft, val);
			}
		}
	}

	if (!ui_query_filechooser(header, title, dir, ft, &filename)) {
		ASSERT_TRUE(ret = PyString_FromString(filename), err);
	} else {
		Py_INCREF(Py_None);
		ret = Py_None;
	}
	goto end;
 err:
	PyErr_SetString(PyExc_StandardError, "Error creating return value.");
 end:
	ship_list_free(ft);
	freez(filename);
	return ret;
}	


/* init the extensions */
static PyMethodDef p2pshipMethods[] = {
    {"get_json",  p2pship_get_json, METH_VARARGS, "Retrieves configuration data in json format."},
    {"alive",  p2pship_alive, METH_NOARGS, "Checks whether the procy is still running."},
    {"register_ol_handler",  (PyCFunction)p2pship_register_ol_handler, METH_VARARGS | METH_KEYWORDS, "Registers an overlay handler."},
    {"ol_data_got",  p2pship_ol_data_got, METH_VARARGS, "Receives data from the overlay handler."},

    // use of the overlay management - identity specific
    {"ol_ident_get",  p2pship_ol_ident_get, METH_VARARGS, "Gets overlay data according to identity policies."},
    {"ol_ident_subscribe",  p2pship_ol_ident_subscribe, METH_VARARGS, "Subscribes to overlay data according to identity policies."},
    {"ol_cancel",  p2pship_ol_cancel, METH_VARARGS, "Un-subscribes to overlay data."},
    {"ol_ident_put",  p2pship_ol_ident_put, METH_VARARGS, "Puts overlay data according to identity policies."},
    {"ol_ident_rm",  p2pship_ol_ident_rm, METH_VARARGS, "Removes overlay data according to identity policies."},

    {"register_ipc_handler",  p2pship_register_ipc_handler, METH_VARARGS, "Registers an IPC handler."},
    {"call_ipc_handler",  p2pship_call_ipc_handler, METH_VARARGS, "Calls an IPC handler."},

    {"log",  p2pship_log, METH_VARARGS, "Logs a message."},

    {"set_name",  p2pship_set_name, METH_VARARGS, "Sets the name of the application instance."},
    {"get_name",  p2pship_get_name, METH_VARARGS, "Gets the name of the application instance."},
    {"get_file",  p2pship_get_file, METH_VARARGS, "Gets the file from which the application was loaded."},
    {"get_datadir",  p2pship_get_datadir, METH_VARARGS, "Gets the script-specific data folder path."},

    {"config_create",  p2pship_config_create, METH_VARARGS, "Creates a new configuration key."},
    {"config_set",  p2pship_config_set, METH_VARARGS, "Sets a configuration value."},
    {"config_save",  p2pship_config_save, METH_VARARGS, "Saves the configuration."},
    {"config_get",  p2pship_config_get, METH_VARARGS, "Gets a configuration value."},
    {"config_set_update",  p2pship_config_set_update, METH_VARARGS, "Installs a dynamic update."},

    {"http_send",  p2pship_http_send, METH_VARARGS, "Sends responsedata on an HTTP socket."},
    {"http_close",  p2pship_http_close, METH_VARARGS, "Closes an HTTP socket."},
    {"http_respond",  p2pship_http_respond, METH_VARARGS, "Sends an response on an HTTP socket."},
    {"http_register",  p2pship_http_register, METH_VARARGS, "Registers an HTTP server."},
    {"http_modif",  p2pship_http_modif, METH_VARARGS, "Modifies an HTTP server registration."},
    {"http_unregister",  p2pship_http_unregister, METH_VARARGS, "Unregisters an HTTP server."},

    // service registration, packet transmission
    {"service_register_default",  p2pship_service_register_default, METH_VARARGS, "Registers a default service."},
    {"service_register",  p2pship_service_register, METH_VARARGS, "Registers a service handler."},
    {"service_send",  p2pship_service_send, METH_VARARGS, "Sends a service packet."},
    {"send_packet",  p2pship_send_packet, METH_VARARGS, "Sends a 'RAW' protocol packet."},

    /* event handling */
    {"event_receive",  p2pship_event_receive, METH_VARARGS, "Registers an event receiver."},
    {"event_generate",  p2pship_event_generate, METH_VARARGS, "Registers an event receiver."},

    {"db_get",  p2pship_db_get, METH_VARARGS, "Gets a persistent value."},
    {"db_set",  p2pship_db_set, METH_VARARGS, "Sets a persistent value."},
    {"db_del",  p2pship_db_del, METH_VARARGS, "Dels a persistent value."},
    {"db_get_keys",  p2pship_db_get_keys, METH_VARARGS, "Gets the keys for the persistent values."},
    {"db_get_values",  p2pship_db_get_values, METH_VARARGS, "Gets the values for the persistent values."},

    // identity handling
    {"get_idents",  p2pship_get_idents, METH_VARARGS, "Returns a list of the local identitie's aors."},
    {"get_ident",  p2pship_get_ident, METH_VARARGS, "Returns an identity object."},
    {"import_reg", p2pship_import_reg, METH_VARARGS, "Imports a registration packet XML."},
    {"get_reg", p2pship_get_reg, METH_VARARGS, "Requests a registration packet for a peer."},

    {"set_service_param", p2pship_set_service_param, METH_VARARGS, "Sets a service-related registration parameter."},
    {"get_service_param", p2pship_get_service_param, METH_VARARGS, "Gets a service-related registration parameter."},
    {"remove_service_param", p2pship_remove_service_param, METH_VARARGS, "Removes a service-related registration parameter."},

    // experimental
    {"reserve_state",  p2pship_reserve_state, METH_NOARGS, "Reserves the Python intepreter state."},
    {"release_state",  p2pship_release_state, METH_NOARGS, "Reserves the Python intepreter state."},
    {"call_async",  p2pship_call_async, METH_VARARGS, "Calls a function asynchronously."},
    {"call_periodically",  p2pship_call_periodically, METH_VARARGS, "Calls a function periodically."},

    // resourcefetch
    {"resourcefetch_store",  p2pship_resourcefetch_store, METH_VARARGS, "Stores a file for P2P resource fetch."},
    {"resourcefetch_remove",  p2pship_resourcefetch_remove, METH_VARARGS, "Removes a file from P2P resource fetch."},
    {"resourcefetch_get",  p2pship_resourcefetch_get, METH_VARARGS, "Retrieves a resource using P2P fetch."},

#ifdef CONFIG_SIP_ENABLED
    {"register_sip_request_handler",  p2pship_register_sip_request_handler, METH_VARARGS, "Registers a SIP request handler"},
    {"register_sip_client_handler",  p2pship_register_sip_client_handler, METH_VARARGS, "Registers a SIP client handler"},
    {"sip_route_as_local",  p2pship_sip_route_as_local, METH_VARARGS, "Routes a SIP message as if originated from local."},
    {"sip_route_as_remote",  p2pship_sip_route_as_remote, METH_VARARGS, "Routes a SIP message as if originated from remote."},
    {"sip_get_local_contact",  p2pship_sip_get_local_contact, METH_VARARGS, "Returns the local proxy address, as seen by the user."},

    {"ac_add_filter",  p2pship_ac_add_filter, METH_VARARGS, "Adds a message filter."},
    // {"ac_remove_filter",  p2pship_ac_remove_filter, METH_VARARGS, "Removes a message filter."},

#endif

#ifdef CONFIG_MEDIA_ENABLED
    {"media_pipeline_parse",  p2pship_media_pipeline_parse, METH_VARARGS, "Creates a media pipeline from the given gstreamer text line."},
    {"media_pipeline_start",  p2pship_media_pipeline_start, METH_VARARGS, "Starts the given media object."},
    {"media_pipeline_destroy",  p2pship_media_pipeline_destroy, METH_VARARGS, "Destroys the given media object."},
    {"media_check_element",  p2pship_media_check_element, METH_VARARGS, "Checks support for a media element."},
#endif
    
    /* ui */
    {"ui_popup",  p2pship_ui_popup, METH_VARARGS, "A popup."},
    {"ui_query_simple",  p2pship_ui_query_simple, METH_VARARGS, "A simple 2-options query."},
    {"ui_query_three",  p2pship_ui_query_three, METH_VARARGS, "A 3-options query."},

    {"ui_query_filechooser",  p2pship_ui_query_filechooser, METH_VARARGS, "A file selection dialog."},


    // file management operations. These are included to allow some
    // file access while being in the Python restricted mode
    /*
    {"open", p2pship_open, METH_VARARGS, "Open a file for reading or writing."},
    {"write", p2pship_open, METH_VARARGS, "Open."},
    {"read", p2pship_open, METH_VARARGS, "Open."},

    {"mkstemp", p2pship_open, METH_VARARGS, "Open."},
    {"fullpath", p2pship_open, METH_VARARGS, "Returns the full path of the given script-specific filename."},
    */

    {NULL, NULL, 0, NULL}        /* Sentinel */
};

PyMODINIT_FUNC
initp2pship(void)
{
	PyObject *m;
	FILE *fp = NULL;
	char *fn = NULL;
	char *dir = NULL;
	ship_list_t *list = NULL;
	
	LOG_DEBUG("initializing python module p2pship..\n");
	if ((m = Py_InitModule("p2pship", p2pshipMethods)) == NULL)
	    return;

	PyRun_SimpleString("import sys\nsys.argv = [ 'nothing.py' ]\n");

	ASSERT_TRUE(dir = processor_config_string(processor_get_config(), P2PSHIP_CONF_PYTHON_LIB_DIR), err);
	ASSERT_TRUE(list = ship_list_dir(dir, "*.py", 1), err);
	while ((fn = ship_list_pop(list))) {
		if ((fp = fopen(fn, "r"))) {
			LOG_DEBUG("loading python library '%s'..\n", fn);
			PyRun_SimpleFile(fp, fn);
			fclose(fp);
			fp = NULL;
		}
		freez(fn);
	}
 err:
	ship_list_empty_free(list);
	ship_list_free(list);
	return;
}

static PyThreadState * mainThreadState = NULL;

/* init */
static int
pymod_init(processor_config_t *config)
{
	int ret = -1;
	pymod_state_t *state = NULL;

	ASSERT_TRUE(pymod_gil_lock = ship_list_new(), err);
	ASSERT_TRUE(pymod_ol_clients = ship_list_new(), err);
	ASSERT_TRUE(pymod_ol_gets = ship_ht_new(), err);
	ASSERT_TRUE(pymod_ipc_handlers = ship_ht_new(), err);
	ASSERT_TRUE(pymod_states = ship_ht_new(), err);
	ASSERT_TRUE(pymod_config_updaters = ship_ht_new(), err);
	ASSERT_TRUE(pymod_http_servers = ship_ht_new(), err);
	ASSERT_TRUE(pymod_default_services = ship_ht_new(), err);
	ASSERT_TRUE(pymod_callback_handlers = ship_list_new(), err);

	/* http://www.linuxjournal.com/article/3641 */
	Py_InitializeEx(0);
	PyEval_InitThreads();
	initp2pship();

	/* get the main thread state */
	mainThreadState = PyThreadState_Get();
	if ((state = pymod_state_new("<shell>", mainThreadState, NULL)))
		ship_ht_put_ptr(pymod_states, state->tstate, state);

	pymod_alive = 1;
	PyEval_ReleaseLock();

	ret = 0;
 err:
	return ret;
}

static void
pymod_close()
{
	olclient_get_task_t *task = NULL;
	void *ptr = 0;
	
	/* we should kill all the threads here . */
	processor_kill_workers(PYTHON_WORKER_TYPE);
	PyEval_AcquireLock();
	PyThreadState_Swap(mainThreadState);
	PyThreadState_Clear(mainThreadState);

	//PyThreadState_Swap(NULL);
	//PyThreadState_Delete(mainThreadState); // can't del the main thread
	pymod_alive = 0;

	/* close the ol's */
	ship_list_empty_with(pymod_ol_clients, pymod_ol_free);
	ship_list_free(pymod_ol_clients);
	pymod_ol_clients = NULL;

	while ((task = ship_ht_pop(pymod_ol_gets))) {
		ship_obj_unref(task);
	}
	ship_ht_free(pymod_ol_gets);
	pymod_ol_gets = NULL;

	while ((ptr = ship_ht_pop(pymod_ipc_handlers)))
		pymod_ipc_free(ptr);
	ship_ht_free(pymod_ipc_handlers);

	while ((ptr = ship_ht_pop(pymod_config_updaters)))
		pymod_ipc_free(ptr);
	ship_ht_free(pymod_config_updaters);

	while ((ptr = ship_list_pop(pymod_callback_handlers)))
		pymod_ipc_free(ptr);
	ship_list_free(pymod_callback_handlers);

	// unregister these?
	while ((ptr = ship_ht_pop(pymod_http_servers)))
		pymod_ipc_free(ptr);
	ship_ht_free(pymod_http_servers);

	while ((ptr = ship_ht_pop(pymod_states)))
		pymod_state_free(ptr);
	ship_ht_free(pymod_states);
	pymod_states = NULL;

	while ((ptr = ship_ht_pop(pymod_default_services)))
		pymod_service_free(ptr);
	ship_ht_free(pymod_default_services);
	pymod_default_services = NULL;

	ship_list_free(pymod_gil_lock);

	if (Py_IsInitialized())
		Py_Finalize();
}

void 
pymod_shell()
{
	char *args[] = { "shell" };
	USER_PRINT("Starting shell\n");

	/* run shell on the main python thread state */
	PyEval_AcquireLock();
	PyThreadState_Swap(mainThreadState);

	Py_Main(1, args);

	PyThreadState_Swap(NULL);
	PyEval_ReleaseLock();
}

static void
pymod_thread_kill(processor_worker_t *w)
{
	pymod_alive = 0;
	if (w->extra) {
		PyThreadState *ts = (PyThreadState *)w->extra;

#ifdef NEW_KILL
		PyEval_AcquireThread(ts);
  		//PyEval_AcquireLock();
		PyErr_SetString(PyExc_EnvironmentError, "p2pship proxy is closing");
  		PyEval_ReleaseThread(ts);
   		//Py_EndInterpreter(ts);
   		PyThreadState_Swap(NULL);
		//PyThreadState_Clear(ts);
  		PyThreadState_Delete(ts);
#else
		pymod_tstate_ok(ts);
#endif
   		PyEval_ReleaseLock();
	}
}

static void
pymod_run_file_thread(processor_worker_t *w)
{
	//PyGILState_STATE gstate;
	char *fn = (char*)w->data;
	FILE *fp = 0;
	pymod_state_t *state = NULL;

	if ((fp = fopen(fn, "r"))) {
		PyThreadState *myThreadState = NULL;


		/* Create a local thread state for each new thread */
		PyEval_AcquireLock();

#ifdef THREADED_INTERPRETER
		myThreadState = PyThreadState_New(mainThreadState->interp);
		PyThreadState_Swap(myThreadState);
#else
		myThreadState = Py_NewInterpreter();
#endif
		w->extra = myThreadState;

		if ((state = pymod_state_new(fn, myThreadState, NULL)))
			ship_ht_put_ptr(pymod_states, state->tstate, state);

#ifndef THREADED_INTERPRETER
		initp2pship();
#endif
		PyRun_SimpleFile(fp, fn);
#ifndef NEW_KILL
		if (pymod_alive) {
			/* ended already? */
			LOG_DEBUG("EOF of '%s' detected, idling..\n", fn);
			
			PyRun_SimpleString("import time\nwhile True: time.sleep(0.2)\n");
			//PyRun_SimpleString("import signal\nsignal.pause()\n");
		}
  		PyEval_ReleaseThread(myThreadState);
		PyThreadState_Swap(NULL);
		//#ifndef THREADED_INTERPRETER
		//PyThreadState_Clear(myThreadState);
		PyThreadState_Delete(myThreadState);
		//#endif
#else

#ifdef RESTORESAVE
		PyEval_SaveThread();
#elif defined(GILSTATE)
		PyThreadState_Swap(NULL);
		PyThreadState_Delete(myThreadState);
#endif

#endif
		PyEval_ReleaseLock();

		fclose(fp);
	} else {
		LOG_ERROR("invalid file: %s\n", fn);
		processor_shutdown();
	}
	w->kill_func = NULL;
	freez(w->data);
}

/* calls to run a script from a file. starts a new thread for the
   application */
static int 
pymod_run_file(const char *file)
{
	int ret = -1, len = 0, i;
	char **tokens = 0;
	
	ASSERT_ZERO(ship_tokenize_trim(file, strlen(file), &tokens, &len, ','), err);
	for (i=0; i < len; i++) {
		LOG_DEBUG("running python file %s..\n", tokens[i]);
		ASSERT_ZERO(processor_create_worker(PYTHON_WORKER_TYPE, pymod_run_file_thread, tokens[i], pymod_thread_kill), err);
		tokens[i] = NULL;
	}
	ret = 0;
 err:
	ship_tokens_free(tokens, len);
	return ret;
}

/* calls to start the plugins */
int
pymod_start_plugins()
{
	char *file = 0;
	int ret = -1;
	char *dir = NULL;
	char *fn = NULL;
	ship_list_t *list = NULL;

	if (processor_config_is_false(processor_get_config(), P2PSHIP_CONF_STARTUP_SCRIPTS)) {
		LOG_INFO("skipping Python startup scripts\n");
	} else {
		/* load scripts */
		ASSERT_TRUE(dir = processor_config_string(processor_get_config(), P2PSHIP_CONF_PYTHON_SCRIPTS_DIR), err);
		ASSERT_TRUE(list = ship_list_dir(dir, "*.py", 1), err);
		while ((fn = ship_list_pop(list))) {
			ASSERT_ZERO(pymod_run_file(fn), err);
			freez(fn);
		}
	}

	if (!processor_config_get_string(processor_get_config(), P2PSHIP_CONF_RUN_SCRIPT, &file)) {
		ASSERT_ZERO(pymod_run_file(file), err);
	}

	ret = 0;
 err:
	ship_list_empty_free(list);
	ship_list_free(list);
	return ret;
}


/* the netio_man register */
static struct processor_module_s processor_module = 
{
	.init = pymod_init,
	.close = pymod_close,
	.name = "pymod",
	.depends = "ui",

};

/* register func */
void
pymod_register() {
	processor_register(&processor_module);
}
