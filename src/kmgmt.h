#ifndef _KMGMT_H_
#define _KMGMT_H_


/*
 * FIXME: actually, all "char"s should become "wchar"s.
 */

#define KXML_COMMAND	"command"
#define KXML_MODULE		"module"
#define KXML_TABLE		"table"
#define KXML_INDEX		"index"
#define KXML_PARAMETERS	"parameters"
#define KXML_VALUE		"value"

/* 
 * Module ID
 */
#define KXML_MOD_DATALINK	"datalink"
#define KXML_MOD_IP			"ip"
#define KXML_MOD_LOG		"log"
#define KXML_MOD_TCP		"tcp"
enum 
{
	KMOD_DATALINK	= 0, /* Datalink */
	KMOD_IP			= 1, /* KIP */
	KMOD_LOG		= 2, /* Log */
	KMOD_TCP		= 3, /* KTCP */
	KMOD_MAX		= 4, /* Unknown */
};

/*
 * Command
 */
#define KXML_CMD_GET	"get"
#define KXML_CMD_SET	"set"
enum
{
	KMGMT_GET		= 0,
	KMGMT_SET		= 1,
	KMGMT_MAX		= 2,
};

/*
 * Error code
 */
#define KXML_ERR_SUCCESS	"success"
#define KXML_ERR_GENERAL	"error"
enum
{
	KMGMT_ERR_SUCCESS	= 0,
	KMGMT_ERR_GENERAL	= 1,
	/* 
	 * TODO: error codes for specific cases
	 */
};

/*
 * Return code for handlers
 */
enum
{
	DONE			= 0,
	FAILED			= 1,
};

extern int kmgmt_errno; /* TODO */

/*
 * Index
 */
#define KXML_INDEX_MAX	1024

/* 
 * Handler: registered by each module.
 */
typedef int (*kmgmt_handler_t)(int modid, int cmd, char *table, char *index, 
		char **rindex, int nparam, int *nvalue, list params, list values);

/* 
 * Structures 
 */
typedef struct kmgmt_agent
{
	struct sockaddr_in ip;
	int socket;

	pthread_t thread;

	time_t last_act; // for forced-timeout.

	list message_queue; 
	pthread_mutex_t message_lock;

#define AGENT_BUFSIZ	4096
	char buffer[AGENT_BUFSIZ];
} kmgmt_agent_t;

typedef struct kmgmt_msg
{
	char *message;
	int message_len;

	kmgmt_agent_t *agent;
} kmgmt_msg_t;

typedef struct kmgmt_module
{
	int modid;

#define MODNAME_MAX		128
	char name[MODNAME_MAX];

	kmgmt_handler_t	handler;
} kmgmt_module_t;

typedef struct kmgmt_param
{
	/*
	 * TODO: type of the value should be defined.
	 */

	/* both are NULL-terminated character string. */
	char *param;
	char *value;
} kmgmt_param_t;

/* indexed linked list */
typedef struct n_linked_list 
{
	list l;
	char *index;
} n_linked_list_t;

/* 
 * Prototypes 
 */
extern void kmgmt_init (dictionary *conf);
extern void kmgmt_dispatch (void);
extern void kmgmt_shutdown (void);

extern void kmgmt_register (int modid, char *name, kmgmt_handler_t handler);

#endif /* _KMGMT_H_ */

