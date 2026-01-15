#ifndef TC_H
#define TC_H

/* Add root qdisc to interface */
int tc_add_root_qdisc(const char *ifname);

/* Delete root qdisc from interface */
int tc_del_root_qdisc(const char *ifname);

/* Class management */
int tc_add_class(const char *ifname,
                 int parent_major,
                 int class_minor);

int tc_del_class(const char *ifname,
                 int parent_major,
                 int class_minor);

#endif /* TC_H */

