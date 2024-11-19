#include <string.h>

// Funzione per verificare se una macchina è esclusa
int is_machine_excluded(const char *machine_name) {
    // Elenco delle macchine escluse
    const char *excluded_machines[] = {"lc", "sh1", "h3", "h4", "h5", "h6", "h7", "h8", "h9", "h9se", "h9combo", "h9combose", "h10", "h11", "i55", "i55se", "i55plus", "h17", "hzero"};
    size_t excluded_count = sizeof(excluded_machines) / sizeof(excluded_machines[0]);

    for (size_t i = 0; i < excluded_count; ++i) {
        if (strcmp(machine_name, excluded_machines[i]) == 0) {
            return 1; // Macchina esclusa
        }
    }
    return 0; // Macchina permessa
}

