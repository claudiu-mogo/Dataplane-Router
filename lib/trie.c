#include "trie.h"

/* create a default trie node. Usually entry will be NULL */
struct trie_node *create_node(struct route_table_entry *entry) {
    struct trie_node *node = (struct trie_node *) malloc (sizeof(struct trie_node));
    node->route_entry = entry;
    node->is_leaf = 0;
    node->left = node->right = NULL;
    return node;
}

/* insert a node containing relevant info at the mask_length level */
struct trie_node *insert_node(struct trie_node *root, struct route_table_entry *entry, uint32_t ip_address, int mask_length) {
    struct trie_node *save = root;
    int i;
	/* go down until the penultimate level */
    for (i = 0; i < mask_length - 1; i++) {
        if ((ip_address & 1) == 1) {
			/* go right in case of 1 byte in ip address */
            if (save->right == NULL)
                save->right = create_node(NULL);
            save = save->right;
        } else {
			/* go left in case of zero */
            if (save->left == NULL)
                save->left = create_node(NULL);
            save = save->left;
        }
        ip_address = ip_address >> 1;
    }

	/* we reached the desired level, create/modify a relevant child */
    if ((ip_address & 1) == 1) {
        if (save->right == NULL)
            save->right = create_node(entry);
        else
            save->right->route_entry = entry;
        save->right->is_leaf = 1;
    } else {
        if (save->left == NULL)
            save->left = create_node(entry);
        else
            save->left->route_entry = entry;
        save->left->is_leaf = 1;
    }
    return root;
}

/* just a function used for debugging */
void print_trie(struct trie_node *root) {
    if (root == NULL) {
        return;
    }
    struct trie_node *curr = root;
    if (curr->route_entry != NULL) {
        uint32_t pref = curr->route_entry->prefix;
        for (int i = 0; i < 32; i++) {
            printf("%d", pref & 1);
            pref = pref >> 1;
        }
        printf("\n");
    }
    //printf("%d \n", curr->route_entry->prefix);
    print_trie(curr->left);
    print_trie(curr->right);
}