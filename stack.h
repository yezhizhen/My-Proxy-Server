#include <stdio.h>
#ifndef _STACK_H_
#define _STACK_H_
#define STACK_MAX 2048

struct Stack{
	int data[STACK_MAX];
	int size;
};
typedef struct Stack Stack;
 
void init_stack(Stack *st)
{
	st->size = STACK_MAX;
	for(int i=0; i< STACK_MAX; i++)
	{
		st->data[STACK_MAX-i-1] = i;
	}
}
 
int push(Stack *st, int val)
{
	if(st->size < STACK_MAX)
		st->data[st->size++] = val;
	else
	{
		printf("Stack overflow\n");
		return 0;
	}
	return 1;
}

int pop(Stack *st)
{
	if(st->size > 0)
	{
		return st->data[(st->size--)-1];
	}
	else
	{
		printf("Stack underflow\nResources used up by %d clients",STACK_MAX);
		return -1;
	}
	
}

#endif
