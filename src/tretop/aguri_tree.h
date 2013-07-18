/* $Id: aguri_tree.h,v 1.3.1.3 2008/05/01 01:51:27 plonka Exp $ */
/*
 * Copyright (C) 2001-2003 WIDE Project.
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. Neither the name of the project nor the names of its contributors
 *    may be used to endorse or promote products derived from this software
 *    without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE PROJECT AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE PROJECT OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 *
 */

#include <sys/queue.h>

#define	MAX_KEYBYTES	16
#define	MAX_KEYBITS	(MAX_KEYBYTES * 8)

struct tree_node {
	struct	tree_node *tn_parent;		/* parent node */
	struct	tree_node *tn_left;		/* left child node */
	struct	tree_node *tn_right;		/* right child node */
	struct	tree *tn_tree;			/* back pointer to tree head */
	TAILQ_ENTRY(tree_node) tn_chain;	/* the LRU list entry */
	
	size_t	tn_prefixlen;			/* prefix length of the key */
	u_char	tn_key[MAX_KEYBYTES];		/* key value */

	u_char		tn_intree;
	short		tn_depth;		/* set in tree_walk */
	u_int64_t	tn_count;

	void *tn_user_data;
};

struct tree {
	struct	tree_node *tr_top;		/* top node of the tree */
	size_t	tr_keylen;			/* key size in bits */
	u_int	tr_nfree;			/* free node count */
	u_int	tr_ndyn;			/* dynamic alloc node count */

	/* tr_maxnodes: this is max node count, 0 means dynamic allocation. */
	u_int	tr_maxnodes;

	u_int64_t	tr_count;
#ifdef AGURI_STATS
	struct {
		u_int	hits;
		u_int	total;
		u_int	reclaimed;
	} tr_stats;
#endif	
	TAILQ_HEAD(_lru, tree_node)	tr_lru;	/* LRU list */
};

/*
 * cast u_int64_t to ull for printf, since type of u_int64_t
 * is architecture dependent
 */
typedef	unsigned long long	ull;


struct tree_node *
tnode_find_prefix(struct tree *tp, const void *key, size_t len);

struct tree_node *
tnode_find_exact(struct tree *tp, const void *key, size_t len);

void leaf_addcount(struct tree *tp, const void *key, u_int64_t cnt);
struct tree_node *tnode_addcount(struct tree *tp, const void *key,
				 size_t len, u_int64_t cnt);
void tree_init(struct tree *tp, size_t keylen, size_t maxnodes);
void tree_destroy(struct tree *tp);
int tree_walk(struct tree *tp,
	      int (*func)(struct tree_node *, void *),
	      void *arg);
int tree_aggregate(struct tree *tp, u_int64_t thresh);
void tree_resetcount(struct tree *tp);
void tree_print(struct tree *tp);

int subtree_walk(struct tree_node *top,
		 int (*func)(struct tree_node *, void *),
		 void *arg);
int subtree_postorderwalk(struct tree_node *top,
			  int (*func)(struct tree_node *, void *),
			  void *arg);
u_int64_t subtree_sum(struct tree_node *np);
void subtree_reduce(struct tree *tp, struct tree_node *np, int depth);
