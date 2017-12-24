#include <stdio.h>
#include <stdint.h>
#include <stdarg.h>
#include <pthread.h>
#include "minerlog.h"
#include <syslog.h>
#include <unistd.h>
#include <string.h>
#include <inttypes.h>
#include <alloca.h>


pthread_mutex_t LogMutex = PTHREAD_MUTEX_INITIALIZER;
static uint32_t LogLevel = LOG_INVALID;

void Log(uint32_t MsgLevel, char *Msg, ...)
{
	va_list args;
	va_list args2;
	char *syslogbuf;
	int sysloglen;

	time_t rawtime;
	char timebuf[128];

	struct tm *curtime;

	
	if(MsgLevel <= LogLevel && LogLevel != LOG_INVALID)
	{
		time(&rawtime);
		curtime = localtime(&rawtime);
		strftime(timebuf, 128, "[%H:%M:%S] ", curtime);
		
		pthread_mutex_lock(&LogMutex);
		
		va_start(args, Msg);

		va_copy(args2, args);

		sysloglen = vsnprintf(NULL, 0, Msg, args2) + 1;

		va_end(args2);

		syslogbuf = (char*) alloca(sysloglen);
		if (vsnprintf(syslogbuf, sysloglen, Msg, args) >= 0)
			syslog(LOG_INFO, "%s", syslogbuf);
	
		va_end(args);
		
		pthread_mutex_unlock(&LogMutex);
		printf("%s\n", syslogbuf);
	}
	
	return;
}

void InitLogging(uint32_t DesiredLogLevel)
{
	LogLevel = DesiredLogLevel;
	openlog("miner", LOG_PID|LOG_CONS, LOG_USER);
	return;
}
