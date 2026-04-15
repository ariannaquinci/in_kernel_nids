#include "algo-ac.h"
#ifdef __KERNEL__
#define STAMPA printk
#include <linux/slab.h>
#include <linux/string.h>
#include <linux/sort.h>
#define REQUEST_MM(x) kmalloc(x,GFP_KERNEL)
#define REALLOC_MM(x,y) krealloc(x,y,GFP_KERNEL)
#define FREE_MM(x) kfree(x)
#define SORT_MM(base, num, size, cmp) sort((base), (num), (size), (cmp), NULL)
#else
#include <string.h>
#include <unistd.h>
#include <stdlib.h>
#include <stdio.h>
#define STAMPA printf
#define REQUEST_MM(x) malloc(x)
#define REALLOC_MM(x,y) realloc(x,y)
#define FREE_MM(x) free(x)
#define SORT_MM(base, num, size, cmp) qsort((base), (num), (size), (cmp))
#endif
volatile int state_id=0;
static DFA_node *create_dfa_node(void){
	DFA_node *new_node = (DFA_node*) REQUEST_MM(sizeof(DFA_node));
	if (new_node ==NULL){
		STAMPA("errore critico\n");
		return NULL;
	}
	new_node->state_id = state_id++;
	new_node->visit_c=0;
	new_node->failure = NULL ;
	new_node->index=-1;
	new_node->end_of_word=0;
	for (int i = 0; i < ALPHABET_SIZE; i++)
    	{
        	new_node->link[i] = NULL;
    	}	
    	return new_node;
}
static void DFA_insert(DFA_node *root,const unsigned char * word,int index){
	DFA_node *node = root;
	for (int i = 0; word[i] != '\0'; i++)
	{
		if (node->link[word[i]] == NULL)
		{
	    		node->link[word[i]] = create_dfa_node();
		}
		node = node->link[word[i]];
	}
	node->end_of_word = 1;
	node->index = index;
}
static void DFA_create_failure_link(DFA_node * root){
    int queue_capacity = 10; // Initial queue capacity
    int queue_size = 0;
    DFA_node **queue = (DFA_node **)REQUEST_MM(queue_capacity * sizeof(DFA_node *));
    int front = 0, rear = 0;
    queue[rear++] = root;
    queue_size++;
    while (front < rear)
    {
        DFA_node *node = queue[front++];
        for (int i = 0; i < ALPHABET_SIZE; i++)
        {
            DFA_node *child = node->link[i];
            if (child && node == root)
            {
                child->failure = root;
            }
            else if (child)
            {
                DFA_node *failure = node->failure;
                while (failure && !failure->link[i])
                {
                    failure = failure->failure;
                }
                child->failure = failure ? failure->link[i] : root;
            }
            if (child)
            {
                if (queue_size == queue_capacity)
                {
                    queue_capacity *= 2;
                    queue = (DFA_node **)REALLOC_MM(queue, queue_capacity * sizeof(DFA_node *));
                }
                queue[rear++] = child;
                queue_size++;
            }
        }
    }
    FREE_MM(queue);
}

DFA_node * DFA_build(const void **dictionary,int size)
{
	DFA_node * root = create_dfa_node();
	if(root == NULL) return NULL;
	int max_lenght = 0;
	for(int i=0;i<size;i++){
		int word_size = strlen((const unsigned char *)dictionary[i]);
		if(word_size > max_lenght){max_lenght = word_size;}
		DFA_insert(root,dictionary[i],i);
	}
	DFA_create_failure_link(root);
	return root;
}

void DFA_free(DFA_node *node){
	if (node == NULL) return;
    	for (int i = 0; i < ALPHABET_SIZE ; i++)
    	{
    		if (node->link[i] != NULL) DFA_free(node->link[i]);
    	}
   	FREE_MM(node);
}
int DFA_exec(DFA_node* root, const unsigned char*byte,int **matchIndices){

    DFA_node *node = root;
    int len = strlen((char *)byte);
    int matchIndicesCapacity = 100; // Initial capacity
    int numMatches = 0;
    *matchIndices = (int *) REQUEST_MM(matchIndicesCapacity * sizeof(int));
    if(*matchIndices == NULL) return 0;
    for (int i = 0; i < len; i++)
    {
	while (node && !node->link[byte[i]])
      	{
            node = node->failure;
        }
        
	node = node ? node->link[byte[i]] : root;
        
	// **Incremento qui**
	if (node) __sync_fetch_and_add(&(node->visit_c),1);
	DFA_node *temp = node;
        while (temp && temp->end_of_word)
        {
	    if (numMatches == matchIndicesCapacity)
            {
                matchIndicesCapacity *= 2;
                *matchIndices = (int *) REALLOC_MM(*matchIndices, matchIndicesCapacity * sizeof(int));
            }
            (*matchIndices)[numMatches++] = temp->index;
	    temp = temp->failure;
        }
    }
    return numMatches;
}

static void collect_states(DFA_node *node, DFA_node **array, int *count, int max_count) {
    if (!node) return;
    // verifica se abbiamo già superato la capacità
    if (*count >= max_count) return;

    array[(*count)++] = node;

    for (int i = 0; i < ALPHABET_SIZE; i++) {
        if (node->link[i]) {
            collect_states(node->link[i], array, count, max_count);
        }
    }
}

// Comparator per qsort
static int compare_nodes(const void *a, const void *b) {
    DFA_node *na = *(DFA_node **)a;
    DFA_node *nb = *(DFA_node **)b;
    return na->visit_c - nb->visit_c;
}

// Funzione principale per stampare i visit_count in ordine di index
void DFA_debug(DFA_node *root) {
    if (!root) return;
    // massimo numero di stati stimato (puoi aumentare se necessario)
    int max_states = 10000;
    DFA_node **nodes = (DFA_node **)REQUEST_MM(sizeof(DFA_node *) * max_states);
    int count = 0;

    collect_states(root, nodes, &count, max_states);

    STAMPA("Numero totale stati: %d\n", count);

    // ordina per index
    SORT_MM(nodes, count, sizeof(DFA_node *), compare_nodes);

    int visite_totali=0;
    for (int i = 0; i < count; i++) {
        	
	    visite_totali += nodes[i]->visit_c;
	    STAMPA("Stato %d: visit_count = %d index=%d\n", nodes[i]->state_id, nodes[i]->visit_c,nodes[i]->index);
    }
    STAMPA("visite_totali %d\n",visite_totali);
    FREE_MM(nodes);
}
