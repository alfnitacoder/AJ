/* webreg.h - RAM registry of installed webapps (the AJOS App Store client)
 *
 * Apps fetched with `appinstall <store-ip> <name>` are held here and served
 * by the HTTP layer BEFORE the boot-FAT webapp/ directory, so an install is
 * live instantly and survives until reboot (no FAT writes involved).
 */
#ifndef WEBREG_H
#define WEBREG_H

#define WEBREG_MAX 8
#define WEBREG_APPCAP 20480 /* 20KB per app script */

/* Install (or replace) an app script. name = route name (no path/ext).
 * text is copied into the registry. Returns slot index >= 0, or -1
 * (registry full / bad args). */
int webreg_install(const char *name, const char *text, int len);

/* Find an installed app. Returns 1 and fills *out_text/*out_len on hit. */
int webreg_lookup(const char *name, const char **out_text, int *out_len);

/* Number of installed apps. */
int webreg_count(void);

/* List installed app names into buf (one per line). Returns count written. */
int webreg_list(char *buf, int cap);

/* Remove one app (or all if name == 0). Returns 1 if something removed. */
int webreg_remove(const char *name);

#endif /* WEBREG_H */
