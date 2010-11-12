#ifndef NJK_STRLIST_H_
#define NJK_STRLIST_H_ 1

typedef struct 
{
    char *str;
    void *next;
} strlist_t;

void add_to_strlist(char *name, strlist_t **list);
void free_strlist(strlist_t *head);
void free_stritem(strlist_t **p);

#endif
