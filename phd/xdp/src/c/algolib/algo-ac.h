#ifndef __ALGO_AC_H__
#define __ALGO_AC_H__

#define ALPHABET_SIZE 256
typedef struct DFA_node{
	struct DFA_node *link[ALPHABET_SIZE];	
	int index;
	int end_of_word;
	struct DFA_node *failure;
	int state_id;
	int visit_c;
}DFA_node;

typedef struct DFA_struct{
	DFA_node * root;	
	DFA_node ** hot_state;
	int hot_state_size;
}DFA_struct;

int DFA_exec(DFA_node*, const unsigned char*,int **);
void DFA_debug(DFA_node*);
DFA_struct * DFA_build(const void **,int,int *,int); //la size è opzionale maybe
void DFA_free(DFA_struct *);

#endif
