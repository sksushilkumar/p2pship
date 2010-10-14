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

/* if we're using threaded intepreter instead of multiple ones */
//#define THREADED_INTERPRETER 1

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

static ship_ht_t *pymod_config_updaters = 0;
static ship_ht_t *pymod_http_servers = 0;

#ifdef CONFIG_SIP_ENABLED
static ship_ht_t *pymod_sipp_client_handlers = 0;
#endif

/* whether still alive */
static int pymod_alive = 0;

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


static void
pymod_tstate_return()
{
	/* should we clear the error or invalidate the whole app? */
	if (PyErr_Occurred()) {
		LOG_WARN("The Python callback raised an Exception. Clearing\n");
		PyErr_Print();
		PyErr_Clear();
	}
	PyThreadState_Swap(NULL);
	PyEval_ReleaseLock();
}

static int
pymod_tstate_ok(PyThreadState *tstate)
{
	if (!Py_IsInitialized())
		return 0;

	PyEval_AcquireLock();

	// check if the thread is alive!
	PyThreadState_Swap(tstate);
	if (!PyThreadState_GetDict() || PyErr_Occurred())
		return 0;
	if (!pymod_alive) {
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
		LOG_ERROR("No state found for 0x%08x\n", PyThreadState_Get());
	return ret;
}

/*
 *
 * MISC utility and common stuff
 *
 *
 */

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

/* logging */
static PyObject *
p2pship_log(PyObject *self, PyObject *args)
{
	const char *str = 0;
	int level = 0;
	pymod_state_t *state = NULL;
	
	if (!PyArg_ParseTuple(args, "is", &level, &str))
		return NULL;
	
	if ((state = pymod_get_current_state()))
		LOG_CUSTOM(level, "PythonApp(%s): %s", state->name, str);
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

static PyObject *
p2pship_get_data_dir(PyObject *self, PyObject *args)
{
	char *value = 0;
	PyObject *ret = NULL;
	
	if (!(value = processor_config_string(processor_get_config(), P2PSHIP_CONF_DATA_DIR))) {
		PyErr_SetString(PyExc_StandardError, "Error");
		goto err;
	}
	
	if (!(ret = Py_BuildValue("s", value))) {
		PyErr_SetString(PyExc_MemoryError, "Memory depleted");
		goto err;
	}
 err:
	return ret;
}

/**
 *
 * the service handling, packet transmission
 *
 */

/* data received from ..far away. */
static int 
pymod_service_data_received(char *data, int data_len, 
				ident_t *target, char *source, 
				service_type_t service_type)
{
	/* find the service holder .. */
	pymod_service_t *s = 0;
	PyObject *arglist, *result;

	s = ship_ht_get_int(pymod_default_services, service_type);
	if (!s)
		return -1;
	
	ASSERT_TRUE(pymod_tstate_ok(s->handler->tstate), err);
	ASSERT_TRUE(arglist = Py_BuildValue("(s#ssi)", data, data_len, target->sip_aor, source, service_type), err);
	result = PyObject_CallObject(s->handler->callback, arglist);
	Py_DECREF(arglist);
	ASSERT_TRUE(result, err);
	Py_DECREF(result);
 err:
	pymod_tstate_return();
	return 0;
}

/* this notifies the service handler that the service is being closed */
static void
pymod_service_service_closed(service_type_t service_type, ident_t *ident, void *pkg)
{
	/* find the service holder .. */
	
	// todo..
	// call on the callback

	// remove the service.
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
p2pship_service_update_registration(PyObject *self, PyObject *args)
{

	// find & remove current (if any)

	/* is this needed? .. perhaps.. */
/* 	int ident_process_register(char *aor, service_type_t service_type, service_t *service, */
/* 				   addr_t *addr, int expire, void *pkg) */

	PyErr_SetString(PyExc_EnvironmentError, "Not implemented");
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


/**
 *
 * HTTP server
 *
 */
static PyObject *
p2pship_http_send(PyObject *self, PyObject *args)
{
	int ref = -1;
	const char *data = 0;
	netio_http_conn_t *conn = 0;
	
	// todo: test me
	
	if (!PyArg_ParseTuple(args, "is:http_send", &ref, &data))
		goto err;

	ASSERT_TRUE(conn = netio_http_get_conn_by_socket(ref), err);
	netio_send(conn->socket, data, strlen(data));
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

static void
p2pship_http_create_ref(char *ref, netio_http_conn_t *conn, extapi_http_req_t *req)
{
	if (req)
		sprintf(ref, "p:%s", req->id);
	else
		sprintf(ref, "s:%d", conn->socket);
}

static int
p2pship_http_get_ref(const char *ref, extapi_http_req_t **req)
{
	if (str_startswith(ref, "p:")) {
		*req = extapi_get_http_req(&ref[2]);
	} else if (str_startswith(ref, "s:")) {
		return atoi(&ref[2]);
	}
	return -1;
}

static PyObject *
p2pship_http_respond(PyObject *self, PyObject *args)
{
	const char *ref, *code_str, *content_type, *body;
	int code, body_len, s;
	netio_http_conn_t *conn = 0;
	extapi_http_req_t *req = NULL;
	
	if (!PyArg_ParseTuple(args, "sisss#:http_respond", 
			      &ref, &code, &code_str, &content_type, &body, &body_len))
		goto err;
	
	s = p2pship_http_get_ref(ref, &req);
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
		ASSERT_TRUE(conn = netio_http_get_conn_by_socket(s), merr);
		netio_http_respond(conn, 
				   code, (char*)code_str, 
				   (char*)content_type,
				   (char*)body, body_len);
		ship_unlock(conn);
	}
	Py_INCREF(Py_None);
	return Py_None;
 merr:
	PyErr_SetString(PyExc_EnvironmentError, "Socket closed");
 err:
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

	ASSERT_TRUE(pymod_tstate_ok(h->tstate), err);

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
	ship_unlock(conn);
	result = PyObject_CallObject(h->callback, arglist);
	conn = netio_http_get_conn_by_socket(conn->socket); // dangerous.. should be ship_obj!!
	ASSERT_TRUE(result, err);
	ASSERT_TRUE(PyInt_Check(result), err);
	funcret = (int)PyInt_AsLong(result);
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

	pymod_tstate_return();
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
	int ret = -1;

	if (pymod_ol_clients)
		h = (pymod_ol_handler_t*)ship_list_remove(pymod_ol_clients, mod->module_data);

	ASSERT_TRUE(h, err);
	ASSERT_TRUE(pymod_tstate_ok(h->tstate), err);
	result = PyObject_CallObject(h->close, NULL);
	ASSERT_TRUE(result, err);
	Py_DECREF(result);
	ret = 0;
 err:
	pymod_tstate_return();
	pymod_ol_free(h);
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
			task->callback((data? strdup(data):NULL), code, task);//->lookup, wait->mod);
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
	PyObject *arglist;
	PyObject *result;
	
	ident_addr_addr_to_str(contact_addr, &addr);
		
	//ASSERT_TRUE(ship_ht_get(pymod_sipp_client_handlers, h), err);
	ASSERT_TRUE(pymod_tstate_ok(h->tstate), err);
	ASSERT_TRUE(arglist = Py_BuildValue("(ssss#)", ident->sip_aor, remote_aor, addr, *buf, *len), err);
	result = PyObject_CallObject(h->callback, arglist);
	Py_DECREF(arglist);
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
			ret = 1;
		} else
			ret = -1;
	} else
		ret = 0; /* done with it! */
	
	Py_DECREF(result);
 err:
	pymod_tstate_return();
	freez(addr);
	return ret;
}

static PyObject *
p2pship_register_sip_client_handler(PyObject *self, PyObject *args)
{
	PyObject *callback = 0;
	char *name = 0;
	pymod_ipc_handler_t *h = 0;

	if (!PyArg_ParseTuple(args, "sO:register_sip_client_handler", &name, &callback))
		goto err;

	ASSERT_ZERO(ship_ht_get_string(pymod_sipp_client_handlers, name), err);

	LOG_DEBUG("registering sip client handler for %s..\n", name);
	ASSERT_TRUE(h = pymod_ipc_new(name, callback, NULL), err);
	//pymod_ipc_free(ship_ht_get_string(pymod_sipp_client_handlers, name));
	ship_ht_put_string(pymod_sipp_client_handlers, name, h);
	sipp_register_client_handler(pymod_sipp_client_handler, h);

	LOG_DEBUG("registered sip client handler for %s done\n", name);
	Py_INCREF(Py_None);
	return Py_None;
 err:
	return NULL;
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
		Py_XDECREF(str);
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

/* returns an identity object. if aor = null, then the default one */
static PyObject *
p2pship_get_ident(PyObject *self, PyObject *args)
{
	const char *aor = 0;
	PyObject *ret = NULL, *str = NULL, *bud = NULL, *buds = NULL;
	ident_t *ident = 0;
	BIO *bio = NULL;
	char *cert = NULL;
	int bufsize;
	void *ptr = 0;
	buddy_t *buddy = 0;

	if (!PyArg_ParseTuple(args, "|s", &aor))
		goto err;
	
	if (!aor || strlen(aor) == 0) {
		ASSERT_TRUE(ident = ident_get_default_ident(), err);
	} else {
		ASSERT_TRUE(ident = ident_find_by_aor(aor), err);
	}
	
	ASSERT_TRUE(ret = PyDict_New(), err);
	ASSERT_TRUE(str = PyString_FromString(zdefault(ident->sip_aor, "")), err);
	ASSERT_ZERO(PyDict_SetItemString(ret, "aor", str), err);
	Py_XDECREF(str);

	ASSERT_TRUE(str = PyString_FromString(zdefault(ident->username, "")), err);
	ASSERT_ZERO(PyDict_SetItemString(ret, "name", str), err);
	Py_XDECREF(str);
	
	ASSERT_TRUE(str = PyString_FromString(zdefault(ident->password, "")), err);
	ASSERT_ZERO(PyDict_SetItemString(ret, "password", str), err);
	Py_XDECREF(str);
	
	ASSERT_TRUE(str = PyString_FromString(zdefault(ident->status, "")), err);
	ASSERT_ZERO(PyDict_SetItemString(ret, "status", str), err);
	Py_XDECREF(str);
	str = NULL;

	/* cert */
	ASSERT_TRUE(bio = BIO_new(BIO_s_mem()), err);
	ASSERT_TRUE(PEM_write_bio_X509(bio, ident->cert), err);
	ASSERT_TRUE(bufsize = BIO_get_mem_data(bio, &cert), err);
	cert[bufsize] = 0;

	ASSERT_TRUE(str = PyString_FromString(cert), err);
	ASSERT_ZERO(PyDict_SetItemString(ret, "cert", str), err);
	Py_XDECREF(str);
	str = NULL;

	/* key */
	BIO_free(bio);
	ASSERT_TRUE(bio = BIO_new(BIO_s_mem()), err);
	ASSERT_TRUE(PEM_write_bio_RSAPrivateKey(bio, ident->private_key, NULL, NULL, 0, NULL, NULL), err);
	ASSERT_TRUE(bufsize = BIO_get_mem_data(bio, &cert), err);
	cert[bufsize] = 0;

	ASSERT_TRUE(str = PyString_FromString(cert), err);
	ASSERT_ZERO(PyDict_SetItemString(ret, "key", str), err);
	Py_XDECREF(str);
	str = NULL;
	
	/* buddies */
	ASSERT_TRUE(buds = PyList_New(0), err);
	ASSERT_ZERO(PyDict_SetItemString(ret, "buddies", buds), err);
	while ((buddy = ship_list_next(ident->buddy_list, &ptr))) {
		ASSERT_TRUE(bud = PyDict_New(), err);

		ASSERT_TRUE(str = PyString_FromString(zdefault(buddy->sip_aor, "")), err);
		ASSERT_ZERO(PyDict_SetItemString(bud, "aor", str), err);
		Py_XDECREF(str);

		ASSERT_TRUE(str = PyString_FromString(zdefault(buddy->name, "")), err);
		ASSERT_ZERO(PyDict_SetItemString(bud, "name", str), err);
		Py_XDECREF(str);

		ASSERT_TRUE(str = PyString_FromString(zdefault(buddy->shared_secret, "")), err);
		ASSERT_ZERO(PyDict_SetItemString(bud, "secret", str), err);
		Py_XDECREF(str);
		str = NULL;

		if (buddy->cert) {
			BIO_free(bio);
			ASSERT_TRUE(bio = BIO_new(BIO_s_mem()), err);
			ASSERT_TRUE(PEM_write_bio_X509(bio, buddy->cert), err);
			ASSERT_TRUE(bufsize = BIO_get_mem_data(bio, &cert), err);
			cert[bufsize] = 0;
			
			ASSERT_TRUE(str = PyString_FromString(cert), err);
			ASSERT_ZERO(PyDict_SetItemString(bud, "cert", str), err);
			Py_XDECREF(str);
			str = NULL;
		}
#ifdef CONFIG_BLOOMBUDDIES_ENABLED
		if (buddy->is_friend)
			str = Py_True;
		else
			str = Py_False;
		ASSERT_ZERO(PyDict_SetItemString(bud, "friend", str), err);
#endif		

		ASSERT_ZERO(PyList_Append(buds, bud), err);
		Py_XDECREF(bud);
	}
	Py_XDECREF(buds);
	goto end;
 err:
	Py_XDECREF(str);
 	Py_XDECREF(ret);
 	Py_XDECREF(bud);
 	Py_XDECREF(buds);
	Py_INCREF(Py_None);
	ret = Py_None;
 end:
	if (bio) BIO_free(bio);
	ship_obj_unlockref(ident);
	return ret;
}	



/* init the extensions */
static PyMethodDef p2pshipMethods[] = {
    {"get_json",  p2pship_get_json, METH_VARARGS, "Retrieves configuration data in json format."},
    {"alive",  p2pship_alive, METH_NOARGS, "Checks whether the procy is still running."},
    {"register_ol_handler",  (PyCFunction)p2pship_register_ol_handler, METH_VARARGS | METH_KEYWORDS, "Registers an overlay handler."},
    {"ol_data_got",  p2pship_ol_data_got, METH_VARARGS, "Receives data from the overlay handler."},
    {"get_data_dir",  p2pship_get_data_dir, METH_VARARGS, "Gets the default data directory."},

    {"register_ipc_handler",  p2pship_register_ipc_handler, METH_VARARGS, "Registers an IPC handler."},
    {"call_ipc_handler",  p2pship_call_ipc_handler, METH_VARARGS, "Calls an IPC handler."},

    {"log",  p2pship_log, METH_VARARGS, "Logs a message."},

    {"set_name",  p2pship_set_name, METH_VARARGS, "Sets the name of the application instance."},
    {"get_name",  p2pship_get_name, METH_VARARGS, "Gets the name of the application instance."},

    {"config_create",  p2pship_config_create, METH_VARARGS, "Creates a new configuration key."},
    {"config_set",  p2pship_config_set, METH_VARARGS, "Sets a configuration value."},
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
    {"service_update_registration",  p2pship_service_update_registration, METH_VARARGS, "Registers a service handler."},
    {"service_send",  p2pship_service_send, METH_VARARGS, "Sends a service packet."},
    {"send_packet",  p2pship_send_packet, METH_VARARGS, "Sends a 'RAW' protocol packet."},

    {"db_get",  p2pship_db_get, METH_VARARGS, "Gets a persistent value."},
    {"db_set",  p2pship_db_set, METH_VARARGS, "Sets a persistent value."},
    {"db_del",  p2pship_db_del, METH_VARARGS, "Dels a persistent value."},
    {"db_get_keys",  p2pship_db_get_keys, METH_VARARGS, "Gets the keys for the persistent values."},
    {"db_get_values",  p2pship_db_get_values, METH_VARARGS, "Gets the values for the persistent values."},

    // identity handling
    {"get_idents",  p2pship_get_idents, METH_VARARGS, "Returns a list of the local identitie's aors."},
    {"get_ident",  p2pship_get_ident, METH_VARARGS, "Returns an identity object."},

#ifdef CONFIG_SIP_ENABLED
    {"register_sip_client_handler",  p2pship_register_sip_client_handler, METH_VARARGS, "Registers a SIP client handler"},
#endif

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
	char *dir = NULL;
	ship_list_t *list = NULL;
	char *fn = NULL;
	pymod_state_t *state = NULL;

	ASSERT_TRUE(pymod_ol_clients = ship_list_new(), err);
	ASSERT_TRUE(pymod_ol_gets = ship_ht_new(), err);
	ASSERT_TRUE(pymod_ipc_handlers = ship_ht_new(), err);
	ASSERT_TRUE(pymod_states = ship_ht_new(), err);
	ASSERT_TRUE(pymod_config_updaters = ship_ht_new(), err);
	ASSERT_TRUE(pymod_http_servers = ship_ht_new(), err);
	ASSERT_TRUE(pymod_default_services = ship_ht_new(), err);
#ifdef CONFIG_SIP_ENABLED
	ASSERT_TRUE(pymod_sipp_client_handlers = ship_ht_new(), err);
#endif
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

	/* load scripts */
	ASSERT_TRUE(dir = processor_config_string(processor_get_config(), P2PSHIP_CONF_PYTHON_SCRIPTS_DIR), err);
	ASSERT_TRUE(list = ship_list_dir(dir, "*.py", 1), err);
	while ((fn = ship_list_pop(list))) {
		ASSERT_ZERO(pymod_run_file(fn), err);
		freez(fn);
	}
	ret = 0;
 err:
	ship_list_empty_free(list);
	ship_list_free(list);
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
	Py_Finalize();
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

#ifdef CONFIG_SIP_ENABLED
	while ((ptr = ship_ht_pop(pymod_sipp_client_handlers)))
		pymod_ipc_free(ptr);
	ship_ht_free(pymod_sipp_client_handlers);
#endif
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

}

void 
pymod_shell()
{
	char *args[] = { };
	USER_PRINT("Starting shell\n");

	/* run shell on the main python thread state */
	PyEval_AcquireLock();
	PyThreadState_Swap(mainThreadState);

	Py_Main(0, args);

	PyThreadState_Swap(NULL);
	PyEval_ReleaseLock();
}

static void
pymod_thread_kill(processor_worker_t *w)
{
	pymod_alive = 0;
	if (w->extra) {
		PyThreadState *ts = (PyThreadState *)w->extra;
		/*
  		PyEval_AcquireLock();

  		PyThreadState_Clear(ts);
  		PyThreadState_Delete(ts);
   		//PyThreadState_Swap(ts);

		//PyRun_SimpleString("exit(0)\n");
   		//Py_EndInterpreter(ts);
   		PyEval_ReleaseLock();
		*/


		pymod_tstate_ok(ts);
   		PyEval_ReleaseLock();
	}
}

static void
pymod_run_file_thread(processor_worker_t *w)
{
	char *fn = (char*)w->data;
	FILE *fp = 0;
	pymod_state_t *state = NULL;

	if ((fp = fopen(fn, "r"))) {
		PyThreadState *myThreadState = NULL;
		//PyInterpreterState *mainInterpreterState = NULL;

		/* Create a local thread state for each new thread */
		PyEval_AcquireLock();

#ifdef THREADED_INTERPRETER
		//mainInterpreterState = mainThreadState->interp;
		myThreadState = PyThreadState_New(mainThreadState->interp); //mainInterpreterState);
		PyThreadState_Swap(myThreadState);
		//PyEval_InitThreads();

#else
		myThreadState = Py_NewInterpreter();
#endif
		w->extra = myThreadState;

		if ((state = pymod_state_new(fn, myThreadState, NULL)))
			ship_ht_put_ptr(pymod_states, state->tstate, state);

		initp2pship();
		PyRun_SimpleFile(fp, fn);
		if (pymod_alive) {
			/* ended already? */
			LOG_DEBUG("EOF of '%s' detected, idling..\n", fn);
			PyRun_SimpleString("import time\nwhile True: time.sleep(0.2)\n");
			//PyRun_SimpleString("import signal\nsignal.pause()\n");
		}
		PyThreadState_Swap(NULL);
		//#ifndef THREADED_INTERPRETER
		PyThreadState_Clear(myThreadState);
		PyThreadState_Delete(myThreadState);
		//#endif
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

	/* check first the run-script */
	if (!processor_config_get_string(processor_get_config(), P2PSHIP_CONF_RUN_SCRIPT, &file)) {
		ASSERT_ZERO(pymod_run_file(file), err);
	}

	ret = 0;
 err:
	return ret;
}


/* the netio_man register */
static struct processor_module_s processor_module = 
{
	.init = pymod_init,
	.close = pymod_close,
	.name = "pymod",
	.depends = "",
};

/* register func */
void
pymod_register() {
	processor_register(&processor_module);
}
