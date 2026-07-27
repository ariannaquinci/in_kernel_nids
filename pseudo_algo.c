global checkpoint;
global state result_state[NUM_CHUNK][NUM_HOTSTATE]; //questo dovrebbe diventare ((i,j),count)
global state hotState[NUM_HOTSTATE];
global count_global;

int researchState(state){
	for(i=0;i<NUM_HOTSTATE;i++){
		if(hotState[i]==state) return i;
	}
	return -1;
}

void deferred_analysis(i,j)
{
    count=0;
    chunk_inc=0;
    finalState = HotState[j];    
retry:
    chunk = chunks[i+chunk_inc];
    startState = finalState;	
    if (i < checkpoint)
        return;
    count += analyze(chunk, startState,finalState); //poi vediamo che fare con il count	
    index_hotstate=researchState(finalState);
    chunk_inc++;
    if(index_hotstate>=0 || chunck_inc+i == NUM_CHUNCK){ 
	    if (CAS(result_state[i][j],0,(chunk_inc,index_hotstate,count))){ //qui la cosa migliore sarebbe mettere direttamente un puntatore alla struttura <count,pointer>!!!
		    return;
	    }
	    count_global+=count;
	    checkpoint+=chuck_inc; //serve atomico (?) forse si
	    c=checkpoint;
	    if(c==NUM_CHUNK) {
		//"sono l'ultimo";
		break;	
	    }

	    while(!CAS(result_state[c][index_hotstate],0,1000)){
		(chuck_inc,index_hotstate,count_output) = result_state[c][index];  
		checkpoint+=chunk_inc;
		c=checkpoint;
		count_global+=count_output;i
		if(c==NUM_CHUNK) {
        	        break;
	            }

		}
	return;
    }
    goto retry;
    return;
}
