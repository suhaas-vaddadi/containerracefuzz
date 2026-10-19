// Fixture for tests/sensor.rs: start helper threads in mode argv[1], then the
// main thread opens argv[2] (the watched checkpoint) and pauses forever.
//   block     one thread in pthread_cond_wait (futex) forever
//   spin      one thread spinning in user code
//   tick N    one thread in a nanosleep(N us) loop
//   pingpong  two threads bouncing a byte over pipes (always one running)
#include <fcntl.h>
#include <pthread.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

static pthread_mutex_t mu = PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t cv = PTHREAD_COND_INITIALIZER;
static int ping[2], pong[2];

static void *block(void *arg)
{
	pthread_mutex_lock(&mu);
	for (;;)
		pthread_cond_wait(&cv, &mu);
}

static void *spin(void *arg)
{
	for (volatile unsigned long i = 0;; i++)
		;
}

static void *tick(void *arg)
{
	long us = atol(arg);
	struct timespec ts = { us / 1000000, us % 1000000 * 1000 };

	for (;;)
		nanosleep(&ts, 0);
}

static void *pinger(void *arg)
{
	char c = 0;

	for (;;) {
		write(ping[1], &c, 1);
		read(pong[0], &c, 1);
	}
}

static void *ponger(void *arg)
{
	char c;

	for (;;) {
		read(ping[0], &c, 1);
		write(pong[1], &c, 1);
	}
}

int main(int argc, char **argv)
{
	const char *m = argv[1];
	pthread_t t;

	if (!strcmp(m, "pingpong")) {
		pipe(ping);
		pipe(pong);
		pthread_create(&t, 0, ponger, 0);
		pthread_create(&t, 0, pinger, 0);
	} else {
		pthread_create(&t, 0, !strcmp(m, "block") ? block : !strcmp(m, "spin") ? spin : tick,
			       argv[3]);
	}
	close(open(argv[2], O_RDONLY));
	pause();
}
