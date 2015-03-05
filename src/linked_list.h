
#ifndef __LINKED_LIST_H__
#define __LINKED_LIST_H__

typedef void * list;
typedef void * list_position;

#if defined(__cplusplus) || defined(c_plusplus)
extern "C" {
#endif

extern list list_open();
extern void list_close(list l);

extern int list_get_count(list l);

extern list_position list_add_head(list l, void *value);
extern list_position list_add_tail(list l, void *value);
extern list_position list_insert_before(list_position pos, void *value);
extern list_position list_insert_after(list_position pos, void *value);

extern list_position list_get_head_position(const list l);
extern list_position list_get_tail_position(const list l);
extern list_position list_get_prev_position(const list_position pos);
extern list_position list_get_next_position(const list_position pos);
extern list_position list_get_position(const list l, const void *value);

extern void *list_get_head(const list l);
extern void *list_get_tail(const list l);
extern void *list_get_at(const list_position pos);
extern void *list_get_prev(list_position *pos);
extern void *list_get_next(list_position *pos);

extern void *list_remove_head(list l);
extern void *list_remove_tail(list l);
extern void *list_remove_at(list_position pos);
extern int list_remove(list l, void *value);
extern void list_remove_all(list l);

#if defined(__cplusplus) || defined(c_plusplus)
}
#endif


#endif /*__LINKED_LIST_H__ */
