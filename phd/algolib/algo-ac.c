#include "algo-ac.h"
#include <string.h>
#ifdef __KERNEL__
#define STAMPA printk
#include <linux/slab.h>
#define REQUEST_MM(x) kmalloc(x,GFP_KERNEL)
#define REALLOC_MM(x,y) krealloc(x,y,GFP_KERNEL)
#define FREE_MM(x) kfree(x)
#else
#include <unistd.h>
#include <stdlib.h>
#include <stdio.h>
#define STAMPA printf
#define REQUEST_MM(x) malloc(x)
#define REALLOC_MM(x,y) realloc(x,y)
#define FREE_MM(x) free(x)
#endif
volatile int state_id=0;
DFA_node * create_dfa_node(){
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
void DFA_insert(DFA_node *root,const unsigned char * word,int index){
	DFA_node *current = root;
	for (int i = 0; word[i] != '\0'; i++)
	{
		if (current->link[word[i]] == NULL)
		{
	    		current->link[word[i]] = create_dfa_node();
		}
		current = current->link[word[i]];
	}
	current->end_of_word = 1;
	current->index = index;
}
void DFA_create_failure_link(DFA_node * root){
    int queue_capacity = 10; // Initial queue capacity
    int queue_size = 0;
    DFA_node **queue = (DFA_node **)REQUEST_MM(queue_capacity * sizeof(DFA_node *));
    int front = 0, rear = 0;
    queue[rear++] = root;
    queue_size++;
    while (front < rear)
    {
        DFA_node *current = queue[front++];
        for (int i = 0; i < ALPHABET_SIZE; i++)
        {
            DFA_node *child = current->link[i];
            if (child && current == root)
            {
                child->failure = root;
            }
            else if (child)
            {
                DFA_node *failure = current->failure;
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
    free(queue);
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

void DFA_free(DFA_node *current){
	if (current == NULL) return;
    	for (int i = 0; i < ALPHABET_SIZE ; i++)
    	{
    		if (current->link[i] != NULL) DFA_free(current->link[i]);
    	}
   	free(current);
}
int DFA_exec(DFA_node* root, const unsigned char*byte,int **matchIndices){

    DFA_node *current = root;
    int len = strlen((char *)byte);
    int matchIndicesCapacity = 100; // Initial capacity
    int numMatches = 0;
    *matchIndices = (int *) malloc(matchIndicesCapacity * sizeof(int));
    if(*matchIndices == NULL) return 0;
    for (int i = 0; i < len; i++)
    {
	while (current && !current->link[byte[i]])
      	{
            current = current->failure;
        }
        
	current = current ? current->link[byte[i]] : root;
        
	// **Incremento qui**
	if (current) __sync_fetch_and_add(&(current->visit_c),1);
	DFA_node *temp = current;
        while (temp && temp->end_of_word)
        {
	    if (numMatches == matchIndicesCapacity)
            {
                matchIndicesCapacity *= 2;
                *matchIndices = (int *) realloc(*matchIndices, matchIndicesCapacity * sizeof(int));
            }
            (*matchIndices)[numMatches++] = temp->index;
	    temp = temp->failure;
        }
    }
    return numMatches;
}

void collect_states(DFA_node *node, DFA_node **array, int *count, int max_count) {
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
int compare_nodes(const void *a, const void *b) {
    DFA_node *na = *(DFA_node **)a;
    DFA_node *nb = *(DFA_node **)b;
    return na->visit_c - nb->visit_c;
}

// Funzione principale per stampare i visit_count in ordine di index
void DFA_debug(DFA_node *root) {
    if (!root) return;
    // massimo numero di stati stimato (puoi aumentare se necessario)
    int max_states = 10000;
    DFA_node **nodes = (DFA_node **)malloc(sizeof(DFA_node *) * max_states);
    int count = 0;

    collect_states(root, nodes, &count, max_states);

    STAMPA("Numero totale stati: %d\n", count);

    // ordina per index
    qsort(nodes, count, sizeof(DFA_node *), compare_nodes);

    int visite_totali=0;
    for (int i = 0; i < count; i++) {
        	
	    visite_totali += nodes[i]->visit_c;
	    STAMPA("Stato %d: visit_count = %d index=%d\n", nodes[i]->state_id, nodes[i]->visit_c,nodes[i]->index);
    }
    STAMPA("visite_totali %d\n",visite_totali);
    FREE_MM(nodes);
}

