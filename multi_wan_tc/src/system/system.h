#ifndef SYSTEM_H
#define SYSTEM_H

/* Enable IPv4 forwarding.
 * Returns 0 on success, -1 on error.
 */
int system_enable_ip_forward(void);

/* Read current IPv4 forwarding state.
 * Returns:
 *   1 = enabled
 *   0 = disabled
 *  -1 = error
 */
int system_get_ip_forward(void);

/* Add route: <cidr> dev <ifname> */
int system_add_route_dev(const char *cidr, const char *ifname);

/* Delete route: <cidr> dev <ifname> */
int system_del_route_dev(const char *cidr, const char *ifname);


#endif /* SYSTEM_H */

