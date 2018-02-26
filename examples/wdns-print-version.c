#include <sys/types.h>
#include <sys/stat.h>
#include <stdio.h>
#include <stdlib.h>

#include <wdns.h>

int
main(int argc, char **argv) {

/* to do compile-time checking, do something like the following: */
#if WDNS_LIBRARY_VERSION_NUMBER > 9001
	printf("your install of libwdns supports compile-time versioning ");
	printf("(WDNS_LIBRARY_VERSION_NUMBER == %lu)\n",
			WDNS_LIBRARY_VERSION_NUMBER);
	/* to do run-time checking, do something like the following: */
	printf("libwdns run-time version is %d\n", wdns_get_version_number());

	/* and to emit a stringified version number, do this: */
	printf("this program was linked against libwdns version %s\n",
			wdns_get_version());
	return (EXIT_SUCCESS);
#else
	printf("your install of libwdns predates versioning, consider an upgrade\n");
	return (EXIT_SUCCESS);
#endif
}
