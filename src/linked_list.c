
#include "linked_list.h"
#include <stdlib.h>
#include <memory.h>

#if defined (HAVE_DMALLOC_H) && defined (HAVE_LIBDMALLOC)
#include "dmalloc.h"
#endif

struct list_node_t;

typedef struct list_body_t {
	int count;
	struct list_node_t *head;
	struct list_node_t *tail;
} list_body;

typedef struct list_node_t {
	list_body *body;
	struct list_node_t *prev;
	void *value;
	struct list_node_t *next;
} list_node;

list list_open()
{
	list_body *body;
	body = (list_body *)malloc(sizeof(list_body));
	memset(body, 0, sizeof(list_body));
	return body;
}

void list_close(list l)
{
	list_remove_all(l);
	free(l);
}

int list_get_count(list l)
{
	return ((list_body *)l)->count;
}

list_position list_add_head(list l, void *value)
{
	list_body *body;
	list_node *new_node;

	body = (list_body *)l;

	new_node = (list_node *)malloc(sizeof(list_node));
	new_node->body = body;
	new_node->value = value;

	if (body->head == NULL) {
		body->head = new_node;
		body->tail = new_node;
		new_node->prev = new_node->next = NULL;
	}
	else {
		body->head->prev = new_node;
		new_node->prev = NULL;
		new_node->next = body->head;
		body->head = new_node;
	}
	body->count ++;

	return (list_position)new_node;
}

list_position list_add_tail(list l, void *value)
{
	list_body *body;
	list_node *new_node;

	body = (list_body *)l;

	new_node = (list_node *)malloc(sizeof(list_node));
	new_node->body = body;
	new_node->value = value;

	if (body->head == NULL) {
		body->head = new_node;
		body->tail = new_node;
		new_node->prev = new_node->next = NULL;
	}
	else {
		body->tail->next = new_node;
		new_node->prev = body->tail;
		new_node->next = NULL;
		body->tail = new_node;
	}
	body->count ++;

	return (list_position)new_node;
}

list_position list_insert_before(list_position pos, void *value)
{
	list_node *node;
	list_node *new_node;

	node = (list_node *)pos;

	new_node = (list_node *)malloc(sizeof(list_node));
	new_node->body = node->body;
	new_node->value = value;

	new_node->prev = node->prev;
	new_node->next = node;
	node->prev = new_node;

	if (new_node->prev == NULL)
		new_node->body->head = new_node;
	else
		new_node->prev->next = new_node;
	new_node->body->count ++;

	return (list_position)new_node;
}

list_position list_insert_after(list_position pos, void *value)
{
	list_node *node;
	list_node *new_node;

	node = (list_node *)pos;

	new_node = (list_node *)malloc(sizeof(list_node));
	new_node->body = node->body;
	new_node->value = value;

	new_node->next = node->next;
	new_node->prev = node;
	node->next = new_node;

	if (new_node->next == NULL)
		new_node->body->tail = new_node;
	else
		new_node->next->prev = new_node;
	new_node->body->count ++;

	return (list_position)new_node;
}

list_position list_get_head_position(const list l)
{
	return (list_position)((list_body *)l)->head;
}

list_position list_get_tail_position(const list l)
{
	return (list_position)((list_body *)l)->tail;
}

list_position list_get_prev_position(const list_position pos)
{
	return (list_position)((list_node *)pos)->prev;
}

list_position list_get_next_position(const list_position pos)
{
	return (list_position)((list_node *)pos)->next;
}

list_position list_get_position(const list l, const void *value)
{
	list_node *node;

	for (node = ((list_body *)l)->head; node != NULL; node = node->next)
		if (node->value == value)
			break;

	return (list_position)node;
}

void *list_get_head(const list l)
{
	if (((list_body *)l)->head == NULL)
		return NULL;
	return ((list_body *)l)->head->value;
}

void *list_get_tail(const list l)
{
	if (((list_body *)l)->tail == NULL)
		return NULL;
	return ((list_body *)l)->tail->value;
}

void *list_get_at(const list_position pos)
{
	return ((list_node *)pos)->value;
}

void *list_get_prev(list_position *pos)
{
	void *value;

	value = ((list_node *)(*pos))->value;
	*pos = (list_position)(((list_node *)(*pos))->prev);
	return value;
}

void *list_get_next(list_position *pos)
{
	void *value;

	value = ((list_node *)(*pos))->value;
	*pos = (list_position)(((list_node *)(*pos))->next);
	return value;
}

void *list_remove_head(list l)
{
	list_body *body;
	list_node *removed_node;
	void *value;

	body = (list_body *)l;

	if (body->head == NULL)
		return NULL;

	removed_node = body->head;
	body->head = removed_node->next;
	if (body->head == NULL)
		body->tail = NULL;
	else
		body->head->prev = NULL;
	body->count --;

	value = removed_node->value;
	free(removed_node);
	return value;
}

void *list_remove_tail(list l)
{
	list_body *body;
	list_node *removed_node;
	void *value;

	body = (list_body *)l;

	if (body->tail == NULL)
		return NULL;

	removed_node = body->tail;
	body->tail = removed_node->prev;
	if (body->tail == NULL)
		body->head = NULL;
	else
		body->tail->next = NULL;
	body->count --;

	value = removed_node->value;
	free(removed_node);
	return value;
}

void *list_remove_at(list_position pos)
{
	list_node *removed_node;
	void *value;

	removed_node = (list_node *)pos;

	if (removed_node->prev == NULL)
		removed_node->body->head = removed_node->next;
	else
		removed_node->prev->next = removed_node->next;

	if (removed_node->next == NULL)
		removed_node->body->tail = removed_node->prev;
	else
		removed_node->next->prev = removed_node->prev;

	removed_node->body->count --;

	value = removed_node->value;
	free(removed_node);
	return value;
}

int list_remove(list l, void *value)
{
	int count;
	list_position pos;

	for (count = 0; (pos = list_get_position(l, value)) != NULL; count ++)
		list_remove_at(pos);

	return count;
}

void list_remove_all(list l)
{
	list_node *node;
	
	node = ((list_body *)l)->head;
	if (node != NULL) {
		for (node = node->next; node != NULL; node = node->next)
			free(node->prev);
		free(((list_body *)l)->tail);
	}

	memset(l, 0, sizeof(list_body));
	return;
}
