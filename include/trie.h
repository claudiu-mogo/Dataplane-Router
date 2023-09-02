#include <string.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include "lib.h"

/* trie node structure, containing a pointer to the entry, 2 children (0 - left, 1 - right), and a boolean value is_leaf
 * is_leaf is 0 by default and 1 when it reached the end of the mask length (the afferent level)
 * Basically we put the route_table_entry when the sub-net prefix ended
 */
struct trie_node {
    struct route_table_entry *route_entry;
    struct trie_node *left;
    struct trie_node *right;
    int is_leaf;
};

struct trie_node *create_node(struct route_table_entry *entry);
struct trie_node *insert_node(struct trie_node *root, struct route_table_entry *entry, uint32_t ip_address, int mask_length);
void print_trie(struct trie_node *root);