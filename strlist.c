#include <unistd.h>
#include <malloc.h>
#include <string.h>

#include "nstrl.h"
#include "strlist.h"

void add_to_strlist(char *name, strlist_t **list)
{
    strlist_t *item, *t;
    char *s;
    unsigned int len;

    if (!list || !name)
	return;

    len = strlen(name);
    if (!len)
	return;
    s = malloc(len + 1);
    if (!s)
	return;
    strlcpy(s, name, len + 1);

    item = malloc(sizeof (strlist_t));
    if (!item)
	goto out0;
    item->str = s;
    item->next = NULL;

    if (!*list) {
	*list = item;
	return;
    }
    for (t = *list; t->next; t = t->next)
	if (!t->next) {
	    t->next = item;
	    return;
	}

    free(item); /* should be impossible, but hey */
out0:
    free(s);
    return;
}

void free_strlist(strlist_t *head)
{
    strlist_t *p = head, *q = NULL;

    while (p != NULL) {
	free(p->str);
	q = p;
	p = q->next;
	free(q);
    }
}

void free_stritem(strlist_t **p)
{
    strlist_t *q;

    if (!p || !*p)
	return;

    q = (*p)->next;
    free((*p)->str);
    free(*p);
    *p = q;
}

