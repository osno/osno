#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>  // Per la funzione access()

#define NUM_EXCLUDED_MACHINES 3

// Definizione delle macchine escluse
const char* EXCLUDED_MACHINES[NUM_EXCLUDED_MACHINES] = {
    "zgemmalc", "zgemmash1", "zgemmah3", "zgemmah4", "zgemmah5", "zgemmah6", "zgemmah7", "zgemmah8", "zgemmah9", "zgemmah9se", "zgemmah9combo", "zgemmah9combose", "zgemmah10", "zgemmah11", "zgemmai55", "zgemmai55se", "zgemmai55plus", "zgemmah17", "zgemmahzero", "zgemmah9twin"
};

// Funzione per ottenere il nome della macchina corrente
char* get_current_machine() {
    FILE* fp = popen("uname -n", "r");
    if (fp == NULL) {
        perror("Errore nel comando uname");
        exit(1);
    }

    static char machine_name[256];
    if (fgets(machine_name, sizeof(machine_name), fp) == NULL) {
        perror("Errore nella lettura del nome della macchina");
        exit(1);
    }
    machine_name[strcspn(machine_name, "\n")] = 0;  // Rimuovere il newline finale
    fclose(fp);

    return machine_name;
}

// Funzione per verificare se la macchina è esclusa
int is_machine_excluded(const char* current_machine) {
    for (int i = 0; i < NUM_EXCLUDED_MACHINES; i++) {
        if (strcmp(EXCLUDED_MACHINES[i], current_machine) == 0) {
            return 1;  // La macchina è esclusa
        }
    }
    return 0;  // La macchina non è esclusa
}

// Funzione per configurare il sistema
void configure_system() {
    printf("Configurando il sistema...\n");
    // Qui aggiungi la logica di configurazione
}

// Funzione per avviare Enigma2
void start_enigma2() {
    printf("Avviando Enigma2...\n");
    // Comando per avviare Enigma2
    // Verifica se il file esiste
    if (access("/usr/bin/enigma2", F_OK) == 0) {
        system("/usr/bin/enigma2 --debug");
    } else {
        printf("Enigma2 non è installato o non trovato nel percorso.\n");
    }
}

// Funzione per eseguire altre operazioni generali
void other_operations() {
    printf("Esegui altre operazioni...\n");
}

// Funzione principale di avvio
void start_boot() {
    const char* current_machine = get_current_machine();
    printf("Inizializzazione per la macchina %s...\n", current_machine);

    if (is_machine_excluded(current_machine)) {
        printf("La macchina %s è esclusa dall'avvio completo.\n", current_machine);
        return;
    }

    configure_system();
    start_enigma2();
    other_operations();

    printf("Avvio completato.\n");
}

// Funzione di caricamento per il modulo
__attribute__((constructor)) void init() {
    start_boot();
}

