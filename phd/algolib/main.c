#include "algo-ac.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#define MAX_LINE_LENGTH 1024
#define MAX_PATTERNS 1000

// Funzione che legge file e popola patterns array
int load_patterns(const char *filename, char **patterns, int max_patterns) {
    FILE *file = fopen(filename, "r");
    if (!file) {
        perror("Errore apertura file");
        return -1;
    }

    char line[MAX_LINE_LENGTH];
    int count = 0;

    while (fgets(line, sizeof(line), file) && count < max_patterns) {
        // Rimuove newline alla fine della riga
        size_t len = strlen(line);
        if (len > 0 && (line[len - 1] == '\n' || line[len -1] == '\r')) {
            line[len - 1] = '\0';
            len--;
            if (len > 0 && line[len -1] == '\r') line[len -1] = '\0'; // per Windows CRLF
        }

        // Salva copia della linea nel dizionario
        patterns[count] = strdup(line);
        if (!patterns[count]) {
            perror("malloc");
            fclose(file);
            return -1;
        }

        count++;
    }

    fclose(file);
    return count;
}

int main(int argc,char**argv)
{

    if (argc < 2) {
        printf("Uso: %s <file_patterns>\n", argv[0]);
        return 1;
    }
    char **patterns;
    patterns = (char**) malloc(sizeof(char*)*MAX_PATTERNS);
    int num_patterns = load_patterns(argv[1], patterns, MAX_PATTERNS);
    if (num_patterns < 0) {
        fprintf(stderr, "Errore nel caricamento dei pattern\n");
        return 1;
    }    

    DFA_node *root = DFA_build(patterns, num_patterns);

    unsigned char *text = (unsigned char *)"\
	    Questa è la riga 1: testo normale senza pattern.\
Riga 2: LoginAttempt rilevato nel flusso.\
Riga 3: testo normale.\
Riga 4: BadUserAgent trovato qui.\
Riga 5: ancora testo normale.\
Riga 6: SQLInjection è presente in questa riga.\
Riga 7: testo normale.\
Riga 8: CrossSiteScript compare di nuovo.\
Riga 9: MalwareDownload rilevato.\
Riga 10: testo normale.\
Riga 11: PhishingLink appare qui.\
Riga 12: RansomwareDetect è visibile.\
Riga 13: ExploitKit e ShellcodePattern entrambi presenti.\
Riga 14: TrojanSignature qui.\
Riga 15: testo normale.\
Riga 16: LoginAttempt di nuovo.\
Riga 17: BadUserAgent ripetuto.\
Riga 18: SQLInjection ripresentato.\
Riga 19: CrossSiteScript.\
Riga 20: MalwareDownload.\
Riga 21: testo normale.\
Riga 22: PhishingLink.\
Riga 23: RansomwareDetect.\
Riga 24: ExploitKit.\
Riga 25: ShellcodePattern.\
Riga 26: TrojanSignature.\
Riga 27: LoginAttempt.\
Riga 28: BadUserAgent.\
Riga 29: SQLInjection.\
Riga 30: CrossSiteScript.\
Riga 196: PhishingLink.\
Riga 197: RansomwareDetect.\
Riga 198: ExploitKit.\
Riga 199: ShellcodePattern.\
Riga 200: TrojanSignature. Fine del test.";
        
    printf("text %s\n",text);
    printf("strlen(text)=%ld\n",strlen(text));
    int *matchIndices; // = (int *)malloc(num_patterns * sizeof(int));
    printf("match\n");
    int numMatches = DFA_exec(root, text,&matchIndices);
    printf("matches: %d\n",numMatches);
    for (int i = 0; i < numMatches; i++)
    {
	if(matchIndices[i]!=-1){
		printf("sto qua %d\n",matchIndices[i]);
        	printf("%s\n", patterns[matchIndices[i]]);
    	}
    }
    printf("numero di matching: %d\n",numMatches);
    DFA_debug(root);
    DFA_free(root);
    return 0;
}

