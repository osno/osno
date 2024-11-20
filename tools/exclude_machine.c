#include <string.h>

// Funzione per verificare se una macchina è esclusa
int is_machine_excluded(const char *machine_name) {
    // Elenco delle macchine escluse
    const char *excluded_machines[] = {"zgemmalc", "zgemmash1", "zgemmah3", "zgemmah4", "zgemmah5", "zgemmah6", "zgemmah7", "zgemmah8", "zgemmah9", "zgemmah9se", "zgemmah9combo", "zgemmah9combose", "zgemmah10", "zgemmah11", "zgemmai55", "zgemmai55se", "zgemmai55plus", "zgemmah17", "zgemmahzero", "zgemmah9twin"};
    size_t excluded_count = sizeof(excluded_machines) / sizeof(excluded_machines[0]);

    for (size_t i = 0; i < excluded_count; ++i) {
        if (strcmp(machine_name, excluded_machines[i]) == 0) {
            return 1; // Macchina esclusa
        }
    }
    return 0; // Macchina permessa
}

