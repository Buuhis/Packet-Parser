#ifndef __PQC_IPC_H__
#define __PQC_IPC_H__

int sig_pqc_handle_ipc_cli(int argc, char **argv);
void sig_pqc_start_ipc_server(void);
void sig_pqc_cleanup_ipc(void);
void sig_pqc_handle_gen_identity(void);

#endif
