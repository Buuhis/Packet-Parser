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

/* Filter + redirect */
int tc_add_redirect_filter(const char *ifname,
                           const char *dst_cidr,
                           int class_minor,
                           const char *out_ifname);

int tc_del_filters(const char *ifname);

#endif /* TC_H */

