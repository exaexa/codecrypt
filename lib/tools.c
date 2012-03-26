
#include "tools.h"

#include <stdlib.h>

static void* (*malloc_func) (size_t) = NULL;
static void (*free_func) (void*) = NULL;

void* ccr_malloc (size_t s)
{
	if (malloc_func) return malloc_func (s);
	else return malloc (s);
}

void ccr_free (void*p)
{
	if (free_func) return free_func (p);
	else return free (p);
}

void ccr_set_internal_allocator (void* (*new_malloc) (size_t), void (*new_free) (void*) )
{
	malloc_func = new_malloc;
	free_func = new_free;
}
