#include <sys/param.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include <err.h>

/* { for inet_pton */
#include <sys/types.h>
#include <sys/socket.h>
#include <arpa/inet.h>
/* } */

#include "aguri_tree.h"

/* FIXME: the following is incorrectly named print_tree in aguri_tree.h */
void tree_print(struct tree *tp);

static struct tree rfc1918;
/* FIXME - set lru_size the # of lines available on screen.
 *         This will insure that the output will fit.
 *         must be > 4.
 */
static int lru_size = 512;
static int ip_thresh = 10;	/* 10/1000 (1%) */

struct tree_node *
add_string(struct tree *tp, const char *ap, size_t len) {
   u_char key[MAX_KEYBYTES];
   if (len > 32) {
      len = 32;
   }
   inet_pton(AF_INET, ap, key);
   return tnode_addcount(tp, key, len, 1);
}

static int
my_tnode_print(struct tree_node *np, void *arg)
{
	int i;
	static char address[INET_ADDRSTRLEN];
	u_int64_t *total = arg;
#if 0
	if (np->tn_count == 0)
		return (0);
#endif
	for (i=0; i<np->tn_depth; i++)
		printf(" ");
	if (inet_ntop(AF_INET, np->tn_key, address, INET_ADDRSTRLEN)) {
	   printf("%.*s/%u", INET_ADDRSTRLEN, address, np->tn_prefixlen);
	}

	printf(": %llu (%.2f%%",
	       (ull)np->tn_count,
	       (double)np->tn_count/np->tn_tree->tr_count*100);
	if (np->tn_prefixlen != np->tn_tree->tr_keylen) {
		printf("/%.2f%%",
			(double)subtree_sum(np)/(*total)*100);
	}
	printf(")\n");
	return (0);
}

void
my_tree_print(struct tree *tp)
{
	tree_walk(tp, my_tnode_print, 0);
}

int
print_summary(void)
{
	u_int64_t thresh, total;

	total = rfc1918.tr_count;
	thresh = total * ip_thresh / 1000;

	tree_aggregate(&rfc1918, thresh);

	/* my_tree_print(&rfc1918); */
	tree_walk(&rfc1918, my_tnode_print, &total);

	fflush(stdout);
	return 0;
}

int
main(void) {
   /* FIXME - store IPv4 address in IPv6 tree under ::FFFF:0:0/96 as
    *         "::FFFF::x.y.z.w".
    *         See "IPv4-mapped IPv6 address": RFC4038, RFC4291, RFC5156 */
   tree_init(&rfc1918, 32, lru_size);
   add_string(&rfc1918, "10.0.0.0", 8);
#if 1
   add_string(&rfc1918, "172.16.0.0", 12);
   add_string(&rfc1918, "192.168.0.0", 16);
   add_string(&rfc1918, "192.168.0.1", 24);
   add_string(&rfc1918, "192.168.0.129", 32);
#endif
   print_summary();
   tree_destroy(&rfc1918);
   exit(EXIT_SUCCESS);
}
