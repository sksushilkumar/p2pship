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
#define _GNU_SOURCE
#include "ship_utils.h"
#include <gst/gst.h>

#include "ship_debug.h"
#include "processor.h"
#include "media.h"

/* the elements */
static ship_ht_t *elements = 0;
static int element_count = 1;

struct media_player_s {

	GstElement *player;
	media_observer_cb callback;
	void *userdata;
	int handle;
};

#if 0

/* a source / sink media element */
typedef struct media_element_s {
	
	/* type .. source / sink */
	int type;

	
	/* the bin */
	GstBin *bin;

	/* To what this is (possible) connected */
	ship_list_t *peers;
	
	/* the player this belongs to */
	GstElement *player;

} media_element_t;


static void
media_element_free(media_element_t *elm)
{
	void *ptr = NULL;
	if (!elm)
		return;

	if (elm->bin) {
		gst_object_unref(GST_OBJECT(elm->bin));
	}

	
}

static media_element_t*
media_element_new()
{
	media_element_t* ret = NULL;
	ASSERT_TRUE(ret = mallocz(sizeof(media_element_t)), err);
	ASSERT_TRUE(ret->bin = gst_bin_new(NULL), err);
	ASSERT_TRUE(ret->peers = ship_list_new(), err);
	return ret;
 err:
	media_element_free(ret);
	return NULL;
}

/* creates a udp source element either from a socket or port */
static media_element_t*
media_element_new_udpsrc(const int port, const int socket)
{
	media_element_t* ret = NULL;
	ASSERT_TRUE(ret = media_element_new(), err);
	
#define MEDIA_CAPS "application/x-rtp,media=(string)audio,clock-rate=(int)8000,encoding-name=(string)PCMA"

	if (socket == -1) {
		// socket = ... 
		
	}
	
	/*
        source = self.make_element("udpsrc")
        source.set_property("caps", gst.Caps(caps))
        source.set_property("sockfd", self.sock.fileno())
        
        rtpbin = self.make_element("gstrtpbin")
        rtpdepay = self.make_element("rtppcmadepay")

        alawdec = self.make_element('alawdec')
        aconv = self.make_element('audioconvert')

        asample = self.make_element('audioresample')
        capsfilter = self.make_element('capsfilter')
        capsfilter.set_property('caps', gst.caps_from_string('audio/x-raw-int,channels=1,rate=8000'))
        
        rtpbin.connect("pad-added", self.pad_added, rtpdepay);
        gst.element_link_many(source, rtpbin)
        gst.element_link_many(rtpdepay, alawdec, aconv, asample, capsfilter, self._source)
	*/
 err:
	media_element_free(ret);
	return ret;
}

#endif

/* checks whether an element exists */
int
media_check_element(const char *name)
{
	GstElementFactory *factory = NULL;
	
	if ((factory = gst_element_factory_find(name))) {
		gst_object_unref(GST_OBJECT(factory));
		return 1;
	} else {
		return 0;
	}
}

static GstElement*
media_get_element(const int handle)
{
	GstElement *e = NULL;
	struct media_player_s *s = (struct media_player_s *)ship_ht_get_int(elements, handle);
	if (s)
		e = s->player;
	return e;
}

static GstElement*
media_remove_element(const int handle)
{
	GstElement *e = NULL;
	struct media_player_s *s = (struct media_player_s *)ship_ht_remove_int(elements, handle);
	if (s) {
		e = s->player;
		if (s->callback) {
			s->callback(s->handle, "destroy", NULL, s->userdata);
		}
		freez(s);
	}
	return e;
}

static int
media_store_element(GstElement *e, media_observer_cb callback, void *userdata, struct media_player_s **callstr)
{
	int ret = -1;
	struct media_player_s *s = NULL;
	
	ASSERT_TRUE(s = (struct media_player_s *)mallocz(sizeof(struct media_player_s)), err);
	ship_lock(elements);
	ret = element_count++;
	s->player = e;
	s->callback = callback;
	s->userdata = userdata;
	s->handle = ret;
	ship_ht_put_int(elements, ret, s);
	ship_unlock(elements);
 err:
	if (callstr)
		*callstr = s;
	return ret;
}


/* receiver of bus message signals */
static void
media_bus_message_cb(GstBus *bus,
		     GstMessage *message,
		     gpointer user_data)
{
	const gchar* name = NULL;
	GError* error = NULL;
	char *data = NULL;
	gchar* debugs;

	LOG_DEBUG("Got message\n");
	name = GST_MESSAGE_TYPE_NAME(message);
	LOG_DEBUG("\tmessage type: %s\n", name);

	if (GST_MESSAGE_TYPE(message) == GST_MESSAGE_ERROR) {
		gst_message_parse_error(message, &error, &debugs);
		LOG_WARN("Gstreamer error message: %s\n", name);
		LOG_WARN("\tmessage: %s\n", error->message);
		LOG_WARN("\tdebugs: %s\n", debugs);
	
		data = error->message;
		free(debugs);
	}
	
	if (user_data) {
		struct media_player_s *s = (struct media_player_s *)user_data;
		if (ship_ht_has_value(elements, s)) {
			if (s->callback) {
				s->callback(s->handle, name, data, s->userdata);
			}
		}
	}

	if (error)
		g_error_free(error);
}

/* creates a player from the given gst pipeline string. returns a
   handle to it. < 0 on errors / problems. */
int
media_parse_pipeline(const char *pipeline, media_observer_cb callback, void *userdata)
{
	int ret = -1;
	struct media_player_s *s = NULL;
	GstElement *e = NULL;
	GstBus *bus = NULL;
	
	LOG_DEBUG("launching pipeline: '%s'\n", pipeline);
	ASSERT_TRUE(e = gst_parse_launch(pipeline, NULL), err);
	ret = media_store_element(e, callback, userdata, &s);
	
	/* add observer */
	if (!callback)
		s = NULL;

	if (callback) {
		ASSERT_TRUE(bus = gst_element_get_bus(e), err);
		gst_bus_add_signal_watch(bus);
		g_signal_connect(G_OBJECT(bus), "message", 
				 G_CALLBACK(media_bus_message_cb), s);
		gst_object_unref(GST_OBJECT(bus));
	}
 err:
	return ret;
}

int
media_pipeline_start(const int handle)
{
	int ret = -1;
	GstElement *e = NULL;

	ASSERT_TRUE(e = media_get_element(handle), err);
	ASSERT_TRUE(gst_element_set_state(e, GST_STATE_PLAYING), err);
	ret = 0;
 err:
	return ret;
}

int
media_pipeline_stop(const int handle)
{
	int ret = -1;
	GstElement *e = NULL;

	ASSERT_TRUE(e = media_get_element(handle), err);
	ASSERT_TRUE(gst_element_set_state(e, GST_STATE_NULL), err);
	ret = 0;
 err:
	return ret;
}

int
media_pipeline_destroy(const int handle)
{
	int ret = -1;
	GstElement *e = NULL;

	ASSERT_TRUE(e = media_remove_element(handle), err);
	gst_element_set_state(e, GST_STATE_NULL);
	gst_object_unref(GST_OBJECT(e));
	ret = 0;
 err:
	return ret;
}


/**
 * initializes the media handling extensions
 */
static int
media_init(processor_config_t *config)
{
	int ret = -1;
	guint major, minor, micro, nano;
	GError *err = NULL;
	
	ASSERT_TRUE(elements = ship_ht_new(), err);
	//gst_init(NULL, NULL);
	if (!gst_init_check(NULL, NULL, &err)) {
		LOG_ERROR("Gstreamer error message: %s\n", err->message);
		ASSERT_TRUE(0, err);
	}
	
	gst_version(&major, &minor, &micro, &nano);
	LOG_INFO("Using gstreamer %d.%d.%d/%d\n", major, minor, micro, nano); 

	/* no, do not check these!
	  ASSERT_TRUES(media_check_element("liveadder"), err, "Missing liveadder gstreamer plugin!\n");
	*/

	ret = 0;
 err:
	return ret;
}

static void
media_close()
{
	struct media_player_s *s = NULL;
	gst_deinit();
	
	while ((s = (struct media_player_s *)ship_ht_pop(elements))) {
		if (s->callback)
			s->callback(s->handle, "destroy", NULL, s->userdata);
		gst_element_set_state(s->player, GST_STATE_NULL);
		gst_object_unref(GST_OBJECT(s->player));
		freez(s);
	}
	ship_ht_free(elements);
}


/* the media register */
static struct processor_module_s processor_module = 
{
	.init = media_init,
	.close = media_close,
	.name = "media",
	.depends = "",
};

/* register func */
void
media_register() {
	processor_register(&processor_module);
}


#include "media.h"
