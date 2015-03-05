#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <ctype.h>
#include <stdarg.h>
#include <assert.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>

#include <errno.h>
#include <netdb.h>

#include <dictionary.h>
#include <iniparser.h>
#include <linked_list.h>

#include <kxml.h>

#include "kmgmt.h"

#undef DEBUG

#ifdef DEBUG
#define DBG(x...) do { \
	fprintf (stderr, x); \
} while (0)
#else
#define DBG(x...)
#endif

/* default server port */
#define KMGMT_PORT_DEFAULT 50015

/* each message is separated by MSG_SEPARATOR */
#define MSG_SEPARATOR	"-----\r\n\r\n\0"
static char msg_separator[] = MSG_SEPARATOR;
static char *credential = NULL;

int kmgmt_errno = 0; 

#ifdef HAVE_KMGMT
static void kmgmt_start_server (ushort *kmgmt_port);
static void agent_handler (kmgmt_agent_t *agent);
static void queue_kmgmt_msg (kmgmt_agent_t *agent, kmgmt_msg_t *msg);
static int kmgmt_handle_message (kmgmt_agent_t *agent, kmgmt_msg_t *msg);

static list _agent_list;
static pthread_mutex_t _agent_list_lock;

static kmgmt_module_t	_modules[KMOD_MAX];

static pthread_t server_thread;
static ushort kmgmt_port;

static int _kmgmt_init = 0;
#define IS_INIT		(_kmgmt_init == 1)

#ifdef DEBUG
static time_t dtime;
#endif /* DEBUG */

/**
 * initializes the management protocol.
 * 
 * @param	conf 
 * @return  none
 */
void kmgmt_init (dictionary *conf)
{
	char *kmgmt_port_str;
	char *cred_str;

	if ((cred_str = iniparser_getstring(conf, "KENS:kmgmt_cred", "KENS")) != NULL)
	{
		if (strlen(cred_str) == 4)
		{
			credential = strdup(cred_str);
		}
	}

	if ((kmgmt_port_str = iniparser_getstring(conf, "KENS:kmgmt_port", "KENS")) != NULL)
	{
		kmgmt_port = atoi (kmgmt_port_str);
		_kmgmt_init = 1;
	}

	if (!IS_INIT)
		return;

	pthread_mutex_init (&_agent_list_lock, NULL);
	_agent_list = list_open ();

	/*memset (_modules, 0, sizeof(kmgmt_module_t) * KMOD_MAX);*/

#ifdef DEBUG
	time(&dtime);
#endif /* DEBUG */

	pthread_create (&server_thread, NULL, &kmgmt_start_server,
			(void*)&kmgmt_port);
}

/**
 * kmgmt_dispatch() is called at kernel_dispatch() in kernel_main.c
 * at each call, queued requests from multiple agents are processed.
 * 
 * @param	none
 * @return  none
 */
void kmgmt_dispatch (void)
{
	/* iterate through queued messages from all agents */
	list_position agent_pos;
	list_position message_pos;

	kmgmt_agent_t *agent;
	kmgmt_msg_t *msg;

	pthread_mutex_lock (&_agent_list_lock);

	agent_pos = list_get_head_position (_agent_list);

#ifdef DEBUG
	{
		time_t now;
		time(&now);

		if (now > dtime + 1)
		{
			LOG_print(NULL, "kmgmt_dispatch at %s", ctime(&now));
			dtime = now;
		}
	}
#endif /* DEBUG */

	while (agent_pos != NULL)
	{
		agent = list_get_at (agent_pos);

		if (agent != NULL)
		{
			pthread_mutex_lock (&agent->message_lock);
			while ((msg = list_remove_head (agent->message_queue)) != NULL)
			{
				/* Process a received message from the agent */
				kmgmt_handle_message (agent, msg);
			}
			pthread_mutex_unlock (&agent->message_lock);
		}

		agent_pos = list_get_next_position (agent_pos);
	}

	pthread_mutex_unlock (&_agent_list_lock);

	return;
}

/**
 * shutdown the management protocol.
 * 
 * @param	none
 * @return  none
 */
void kmgmt_shutdown (void)
{
	kmgmt_agent_t *agent;

	pthread_mutex_lock (&_agent_list_lock);

	/* FIXME: not working well... */
	while ((agent = list_remove_head (_agent_list)) != NULL)
	{
		close (agent->socket);

		// wait for the thread to terminate.
		pthread_cancel (agent->thread);
		pthread_join (agent->thread, NULL);

		free (agent);
	}

	pthread_mutex_unlock (&_agent_list_lock);

	pthread_mutex_destroy (&_agent_list_lock);

	list_close (_agent_list);
}

/**
 * each module registers the handler by calling kmgmt_register()
 * 
 * @param	modid id of the module
 *			name name of the module
 *			handler handler for the request toward the module
 * @return  none
 */
void kmgmt_register (int modid, char *name, kmgmt_handler_t handler)
{
	kmgmt_module_t	*module;

	if (modid > KMOD_MAX)
		return;

	if (name == NULL || strlen(name) >= MODNAME_MAX)
		return;

	module = &_modules[modid];

	memset (module, 0, sizeof(kmgmt_module_t));

	module->modid = modid;
	strcpy (module->name, name);

	module->handler = handler;

	DBG ("kmgmt_register: %s(%d) is registered\n", 
			module->name, module->modid);

	return;
}

/**
 * get the module by module id.
 * 
 * @param	modid id of the module
 * @return  kmgmt_modul_t*
 */
static kmgmt_module_t *kmgmt_module_get (int modid)
{
	if (modid > KMOD_MAX)
		return NULL;

	return &_modules[modid];
}

/**
 * parse the received request and calls the appropriate module's handler.
 * results from the handler are, then, constructed into the response XML.
 * the response, is then, sent to the requesting agent.
 *
 * FIXME: must be separated later. it is for now "proof-of-concept" code. 
 * of course, you are more than welcome to fix it yourself.
 * 
 * @param	agent requesting agent
 *			msg request xml message
 * @return  0 for success
 */
static int kmgmt_handle_message (kmgmt_agent_t *agent, kmgmt_msg_t *msg)
{
	/* call the handler and get the result. */
	xmlDocPtr doc = NULL; 
	xmlNode *root_element = NULL;
	xmlNode *node1 = NULL;
	xmlNode *node2 = NULL;

	xmlTextWriterPtr writer = NULL;
	xmlBufferPtr buf = NULL;
	xmlChar *tmp = NULL;
	xmlChar *tmp2 = NULL;

	int command = KMGMT_MAX;
	char *command_str = NULL;
	int modid = KMOD_MAX;
	char *module_str = NULL;
	char *table = NULL;
	char *index = NULL;

	char rindex[KXML_INDEX_MAX]; /* arbitrary string */
	int rvalues;
	int ret;
	int rc;

	kmgmt_module_t *module;

	list params = NULL;
	kmgmt_param_t *pvalue;

	n_linked_list_t *rvalue_list = NULL;
	list rvalue_list_list = NULL; // list of lists.
	list_position list_pos;
	kmgmt_param_t *rvalue;

#define KXML_BUFSIZ		1024
	char buffer[KXML_BUFSIZ];

	/* (1) parse the XML message. */
		/*
		 * The document being in memory, it have no base per RFC 2396,
		 * and the "noname.xml" argument will serve as its base.
		 */
	doc = xmlReadMemory(msg->message, strlen(msg->message), "noname.xml", NULL, 0);
	if (doc == NULL) {
		DBG ("Failed to parse the message\n");
		return -EINVAL;
	}

	/* (2) locate some (needed) elements */
	root_element = xmlDocGetRootElement(doc);

	DBG ("kmgmt_handle_message: from %s\n", inet_ntoa(agent->ip.sin_addr.s_addr));

	if (strcmp(root_element->name, "request") != 0 &&
			strcmp(root_element->name, "response") != 0)
	{
		DBG ("Unknown Message <%s>\n", root_element->name);
		goto finish;
	}

	/* okay, run through children of the root element */
	for (node1 = root_element->children; node1; node1 = node1->next) {
		/*if (node1->type == XML_ELEMENT_NODE ||
				node1->type == XML_ATTRIBUTE_NODE ||
				node1->type == XML_TEXT_NODE) { */
		if (node1->type == XML_ELEMENT_NODE) 
		{
			xmlNode *params_root = NULL;
			char *content = NULL;

			DBG ("\t%s", node1->name);
			content = xmlNodeGetContent(node1);
			if (content != NULL)
				DBG (" - %s", content);
			DBG ("\n");

			if (!strcmp (node1->name, KXML_COMMAND))
			{
				if (strcmp (content, KXML_CMD_GET) == 0)
				{
					command = KMGMT_GET;
				}
				else if (strcmp (content, KXML_CMD_SET) == 0)
				{
					command = KMGMT_SET;
				}
				command_str = content;
			}
			else if (!strcmp (node1->name, KXML_MODULE))
			{
				if (strcmp (content, KXML_MOD_DATALINK) == 0)
					modid = KMOD_DATALINK;
				else if (strcmp (content, KXML_MOD_IP) == 0)
					modid = KMOD_IP;
				else if (strcmp (content, KXML_MOD_LOG) == 0)
					modid = KMOD_LOG;
				else if (strcmp (content, KXML_MOD_TCP) == 0)
					modid = KMOD_TCP;
				module_str = content;
			}
			else if (!strcmp (node1->name, KXML_TABLE))
			{
				table = content;
			}
			else if (!strcmp (node1->name, KXML_INDEX))
			{
				index = content;
			}
			else if (!strcmp (node1->name, KXML_PARAMETERS))
			{
				params = list_open ();

				for (node2 = node1->children; node2; node2 = node2->next) {
					if (node2->type == XML_ELEMENT_NODE)
					{
						char *content2 = NULL;

						DBG ("\t\t%s", node2->name);
						content2 = xmlNodeGetContent(node2);
						if (content2 != NULL)
							DBG (" - %s", content2);
						DBG ("\n");

						pvalue = malloc (sizeof(kmgmt_param_t));
						memset (pvalue, 0, sizeof(kmgmt_param_t));

						pvalue->param = malloc (strlen(node2->name) + 1);
						strcpy (pvalue->param, node2->name);

						if (content2 != NULL)
							pvalue->value = content2;

						list_add_tail (params, (void*)pvalue);
					}
				}
			}
		}
	}

	xmlFreeDoc(doc);
	doc = NULL;

	/* (3) check the validity */
	switch (command)
	{
		case KMGMT_GET:
			break;

		case KMGMT_SET:
			break;

		case KMGMT_MAX:
		default:
			DBG ("\tUnknown Command\n");
			goto finish;
	};
	
	if (modid == KMOD_MAX)
	{
		DBG ("\tUnknown Module\n");
		ret = FAILED;
		goto response;
	}

	if (params == NULL || list_get_count (params) <= 0)
	{
		DBG ("\tNo valid parameters\n");
		ret = FAILED;
		goto response;
	}

	/* (4) now process it */
	/*		i. get the proper handler and start response xml. */
	module = kmgmt_module_get (modid);

	if (module == NULL)
	{
		DBG ("\tHandler is not registered\n");
		goto finish;
	}

	/*		ii. call the handler until error or done is found */
	memset (rindex, 0, KXML_INDEX_MAX);
	rvalue_list_list = list_open ();

	ret = module->handler (modid, command, table, index, (char**)&rindex, 
			list_get_count(params), &rvalues, params, rvalue_list_list);

response:
	/* Create a new XML buffer, to which the XML document will be
	 * written */
	buf = xmlBufferCreate();
	if (buf == NULL) {
		printf("testXmlwriterMemory: Error creating the xml buffer\n");
		return;
	}

	/* Create a new XmlWriter for memory, with no compression.
	 * Remark: there is no compression for this kind of xmlTextWriter */
	writer = xmlNewTextWriterMemory(buf, 0);
	if (writer == NULL) {
		printf("testXmlwriterMemory: Error creating the xml writer\n");
		return;
	}

	rc = xmlTextWriterStartElement(writer, BAD_CAST "response");
	if (rc < 0) {
		printf
			("testXmlwriterMemory: Error at xmlTextWriterStartElement\n");
		return;
	}

	if (ret == FAILED)
	{
		sprintf (buffer, "%s", KXML_ERR_GENERAL);
	}
	else if (ret == DONE)
	{
		sprintf (buffer, "%s", KXML_ERR_SUCCESS);
	}
	else
	{
		DBG ("\tUnknown return code(%d) from the handler.\n", ret);
		goto finish;
	}

	tmp = ConvertInput(buffer, KXML_ENCODING);
	rc = xmlTextWriterWriteElement(writer, BAD_CAST "error", tmp);
	if (rc < 0) {
		DBG ("\tError at xmlTextWriterWriteElement for <error>\n");
		goto finish;
	}
	if (tmp != NULL) ConvertFree(tmp);

	strcpy (buffer, module_str);
	tmp = ConvertInput(buffer, KXML_ENCODING);
	rc = xmlTextWriterWriteElement(writer, BAD_CAST "module", tmp);
	if (rc < 0) {
		DBG ("\tError at xmlTextWriterWriteElement for <module>\n");
		goto finish;
	}
	if (tmp != NULL) ConvertFree(tmp);

	if (table != NULL)
	{
		strcpy (buffer, table);
		tmp = ConvertInput(buffer, KXML_ENCODING);
		rc = xmlTextWriterWriteElement(writer, BAD_CAST "table", tmp);
		if (rc < 0) {
			DBG ("\tError at xmlTextWriterWriteElement for <table>\n");
			goto finish;
		}
		if (tmp != NULL) ConvertFree(tmp);
	}

	if (ret == DONE && command == KMGMT_GET)
	{
		/* now put the actual values */
		if (rvalue_list_list != NULL)
		{
			while ((rvalue_list = list_remove_head (rvalue_list_list)) != NULL)
			{
				if (rvalue_list == NULL)
					continue;

				DBG ("\tInserting entry %s\n", rvalue_list->index?rvalue_list->index:"");

				rc = xmlTextWriterStartElement(writer, BAD_CAST "value");
				if (rc < 0) {
					DBG ("\tError at xmlTextWriterWriteElement for <value>\n");
					goto finish;
				}

				if (rvalue_list->index != NULL)
				{
					tmp = ConvertInput(rvalue_list->index, KXML_ENCODING);
					rc = xmlTextWriterWriteAttribute(writer, BAD_CAST "index", tmp);
					if (rc < 0) {
						DBG ("\tError at xmlTextWriterWriteAttribute for <value index>\n");
						goto finish;
					}
					if (tmp != NULL) ConvertFree(tmp);
				}

				while ((rvalue = list_remove_head (rvalue_list->l)) != NULL)
				{
					if (rvalue == NULL)
						continue;

					if (rvalue->param != NULL && rvalue->value != NULL)
					{
						tmp = ConvertInput(rvalue->param, KXML_ENCODING);
						tmp2 = ConvertInput(rvalue->value, KXML_ENCODING);
						rc = xmlTextWriterWriteElement(writer, tmp, tmp2);
						if (rc < 0) {
							DBG ("\tError at xmlTextWriterWriteElement for <%s>\n", rvalue->param);
							goto finish;
						}
						if (tmp != NULL) ConvertFree(tmp);
						if (tmp2 != NULL) ConvertFree(tmp2);
					}

					if (rvalue->param != NULL)
						free (rvalue->param);
					if (rvalue->value != NULL)
						free (rvalue->value);

					free (rvalue);
				}

				rc = xmlTextWriterEndElement(writer);
				if (rc < 0) {
					DBG ("\tError at xmlTextWriterEndElement for <value>\n");
					return;
				}

				list_close (rvalue_list->l);
				if (rvalue_list->index != NULL)
					free (rvalue_list->index);
				free (rvalue_list);
			}

			list_close (rvalue_list_list);
			rvalue_list_list = NULL;
		}
	}

	rc = xmlTextWriterEndElement(writer);
	if (rc < 0) {
		DBG ("\tError at xmlTextWriterEndElement for <response>\n");
		return;
	}

	xmlFreeTextWriter (writer);
	writer = NULL;

	if (send (agent->socket, (const void*)buf->content, buf->use, 0) == -1)
	{
		DBG ("\tUnable to send the buffer: %d - %s\n", errno, strerror(errno));
		goto finish;
	}

	if (send (agent->socket, (const void*)msg_separator, strlen(msg_separator), 0) == -1)
	{
		DBG ("\tUnable to send the separator: %d - %s\n", errno, strerror(errno));
		goto finish;
	}

	DBG ("\tResponse is sent\n");

finish:
	if (doc != NULL)
		xmlFreeDoc(doc);

	if (writer != NULL)
		xmlFreeTextWriter(writer);

	if (buf != NULL)
		xmlBufferFree (buf);

	if (command_str != NULL)
		xmlFree (command_str);

	if (module_str != NULL)
		xmlFree (module_str);

	if (table != NULL)
		xmlFree (table);

	if (index != NULL)
		xmlFree (index);

	/* clean up */
	/* free request parameter/value list */
	if (params != NULL)
	{
		while ((pvalue = list_remove_head (params)) != NULL)
		{
			if (pvalue == NULL)
				continue;

			if (pvalue->param != NULL)
				free (pvalue->param);

			/* this conditional should not be true under any circumstance. */
			if (pvalue->value != NULL)
				free (pvalue->value);

			free (pvalue);
		}
	}

	/* free response parameter/value list if any */
	if (rvalue_list_list != NULL)
	{
		while ((rvalue_list = list_remove_head (rvalue_list_list)) != NULL)
		{
			if (rvalue_list == NULL)
				continue;

			while ((rvalue = list_remove_head (rvalue_list->l)) != NULL)
			{
				if (rvalue == NULL)
					continue;

				if (rvalue->param != NULL)
					free (rvalue->param);

				if (rvalue->value != NULL)
				   free (rvalue->value);
				
				free (rvalue);
			}

			list_close (rvalue_list->l);
			if (rvalue_list->index != NULL)
				free (rvalue_list->index);
			free (rvalue_list);
		}
		
		list_close (rvalue_list_list);
	}

	return 0;
}

/**
 * this is a never-ending loop for accepting agents.
 * it spawns a thread for each agent.
 * 
 * @param	kmgmt_port the port number
 * @return  none
 */
static void kmgmt_start_server (ushort *kmgmt_port)
{
	int server_fd;
	ushort port = *kmgmt_port;
	int reuse = 1;

	struct sockaddr_in addr;

	int agent_fd;

	struct sockaddr_in agent_addr;
	size_t agent_addr_len = sizeof(struct sockaddr_in);

	kmgmt_agent_t *agent;

	server_fd = socket (AF_INET, SOCK_STREAM, 0);

	if (setsockopt (server_fd, SOL_SOCKET, SO_REUSEADDR, &reuse, sizeof(int)) == -1)
	{
		DBG ("Error: %d - %s\n", errno, strerror(errno));
		return;
	}

	memset (&addr, 0, sizeof(struct sockaddr_in));

	addr.sin_family = AF_INET;
	addr.sin_port = htons(port);

	if (bind (server_fd, (struct sockaddr*)&addr, sizeof(struct sockaddr_in)) != 0)
	{
		DBG ("Error: %d - %s\n", errno, strerror(errno));
		return;
	}

	if (listen(server_fd, 5) != 0)
	{
		DBG ("Error: %d - %s\n", errno, strerror(errno));
		return;
	}

	DBG ("KMGMT is listening on %s:%d.\n", inet_ntoa (addr.sin_addr.s_addr),
			ntohs(addr.sin_port));

	while (1)
	{
		if ((agent_fd = accept (server_fd, (struct sockaddr*)&agent_addr, 
						&agent_addr_len)) == -1)
		{
			DBG ("Error: %d - %s\n", errno, strerror(errno));

			if (errno != EINTR)
				break;
		}

		agent = malloc (sizeof(struct kmgmt_agent));
		memset (agent, 0, sizeof(struct kmgmt_agent));

		memcpy (&agent->ip, &agent_addr, sizeof(struct sockaddr_in));
		agent->socket = agent_fd;

		pthread_mutex_init (&agent->message_lock, NULL);
		agent->message_queue = list_open ();

		pthread_create (&agent->thread, NULL, &agent_handler, (void*)agent);
	}

	DBG ("kmgmt_start_server: finishing...\n");

	return;
}

/**
 * this function is a body of a thread for a single agnet.
 * it receives the message and queues them for later process.
 * 
 * @param	agent
 * @return  none
 */
#define AGENT_SOCKET_BUFSIZ	1024
static void agent_handler (kmgmt_agent_t *agent)
{
	int sd = agent->socket;

	char buffer[AGENT_SOCKET_BUFSIZ];
	int buffer_len = 0;
	int client_buffer_len = 0;

	kmgmt_msg_t *msg;

	char *token, *subtoken;
	char *buffer_pnt;

	list_position lpos;

	/*
	 * for the security purpose, agent must identify itself with
	 * 4-digit credential.
	 */
	if (credential != NULL)
	{
		char response[2]; 

		if ((buffer_len = read (sd, buffer, 4)) == 4)
		{
			if (strncmp (buffer, credential, 4) != 0)
			{
				DBG ("Wrong Credential is given\n");
				/* send 'NO' */
				response[0] = 'N';
				response[1] = 'O';

				write (sd, response, 2);
				goto finish;
			}
			else
			{
				/* send 'OK' */
				response[0] = 'O';
				response[1] = 'K';

				write (sd, response, 2);
			}
		}
	}

	pthread_mutex_lock (&_agent_list_lock);
	list_add_tail (_agent_list, (void*)agent);
	pthread_mutex_unlock (&_agent_list_lock);

	while (1)
	{
		if ((buffer_len = read (sd, buffer, AGENT_SOCKET_BUFSIZ))  <= 0)
		{
			perror ("read");
			break;
		}

		buffer[buffer_len] = 0;
		strncat (agent->buffer, buffer, buffer_len + 1);
		client_buffer_len = strlen(agent->buffer);

		buffer_pnt = agent->buffer;

		while ((token = strstr(buffer_pnt, msg_separator)) != NULL)
		{
			msg = malloc (sizeof(kmgmt_msg_t));
			msg->message = malloc (token - buffer_pnt + 1);

			memcpy (msg->message, buffer_pnt, token - buffer_pnt);
			msg->message[token - buffer_pnt] = 0;
			msg->message_len = strlen(msg->message);

			msg->agent = agent;

			DBG ("%s\n", msg->message);

			queue_kmgmt_msg (agent, msg);

			buffer_pnt = token + strlen(msg_separator);
		}

		if (buffer_pnt < agent->buffer + client_buffer_len)
		{
			// there are some remaining characters in the buffer, move it.
			memmove (agent->buffer, buffer_pnt, strlen(buffer_pnt));
			agent->buffer[agent->buffer + client_buffer_len - buffer_pnt] = 0;
		}
		else
		{
			agent->buffer[0] = 0;
		}
	}

finish:
	close (sd);

	if (errno != EINTR)
	{
		pthread_mutex_lock (&_agent_list_lock);
		list_remove (_agent_list, agent);
		pthread_mutex_unlock (&_agent_list_lock);

		pthread_mutex_lock (&agent->message_lock);
		lpos = list_get_head_position (agent->message_queue);
		while (lpos != NULL)
		{
			msg = list_get_at(lpos);
			if (msg != NULL)
			{
				free (msg->message);
				free (msg);
			}

			lpos = list_get_next_position (lpos); 
		}
		pthread_mutex_unlock (&agent->message_lock);

		free (agent);
	}

	DBG ("agent is cleared\n");

	return;
}

/**
 * agent uses this function to queue the message
 * 
 * @param	agent
 *			msg message for queue
 * @return  none
 */
static void queue_kmgmt_msg (kmgmt_agent_t *agent, kmgmt_msg_t *msg)
{
	pthread_mutex_lock (&agent->message_lock);
	list_add_tail (agent->message_queue, (void*)msg);
	pthread_mutex_unlock (&agent->message_lock);
}

#else /* !HAVE_KMGMT */
void kmgmt_init (dictionary *conf)
{
	DBG ("NOT IMPLEMENTED\n");
}

void kmgmt_dispatch (void)
{
	DBG ("NOT IMPLEMENTED\n");
}

void kmgmt_shutdown (void)
{
	DBG ("NOT IMPLEMENTED\n");
}

void kmgmt_register (int modid, char *name, kmgmt_handler_t handler)
{
}
#endif /* HAVE_KMGMT */
