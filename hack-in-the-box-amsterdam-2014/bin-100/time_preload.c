#include <stdio.h>
#include <time.h>

static long fake_t = 0;

time_t time(time_t *t) {
	// printf("fake time(%ld)\n", fake_t);
	return(fake_t);
}

unsigned int sleep(unsigned int seconds) {
	// printf("fake sleep()\n");
	fake_t++;
}

