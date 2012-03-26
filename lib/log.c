
#include "codecrypt.h"
#include "log.h"

static void (*global_log) (const char*) = NULL;

void ccr_set_log_func (void (*x) (const char*) )
{
	global_log = x;
}

void ccr_log (const char* fmt, ...)
{
	if (!global_log) return;
	//TODO
}
