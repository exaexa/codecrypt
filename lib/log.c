
#include "codecrypt.h"
#include "log.h"

typedef void(*)(const char*) logfunc;

static logfunc global_log=NULL;

//TODO export
void ccr_set_log_func(logfunc x) {
	global_log=x;
}

void ccr_log(const char*, ...) {

}
