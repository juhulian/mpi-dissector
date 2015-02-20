/* packet-mpi.c
 * Routines for Message Passing Interface (MPI) Protocol dissection
 * Copyright 2015, Julian Rilli julian@rilli.eu
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License along
 * with this program; if not, write to the Free Software Foundation, Inc.,
 * 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 */

/*
 * Try to dissect the Open MPI (http://www.open-mpi.org/) protocol ;-)
 */

#include "config.h"

#include <epan/packet.h>
#include <epan/conversation.h>
#include <epan/prefs.h>

#include "packet-mpi.h"

#define MPI_DEBUG 0

/* Initialize the protocol and registered fields */
static int proto_mpi = -1;

/* Global sample preference ("controls" display of numbers) */
static gboolean pref_little_endian = TRUE;
/*
 * #define MPI_TCP_PORT 1024
 * static guint tcp_port_pref = MPI_TCP_PORT;
 */
#define DEFAULT_MPI_PORT_RANGE "1024-65535"
static range_t *global_mpi_tcp_port_range;

/* mpi_abort with 5 bytes */
#define MPI_MIN_LENGTH 5 

/* Initialize the subtree pointers */
static gint ett_mpi = -1;
static gint ett_mpi_oob_hdr = -1;
static gint ett_mpi_oob_msg = -1;
static gint ett_mpi_base = -1;
static gint ett_mpi_common = -1;
static gint ett_mpi_common_flags = -1;
static gint ett_mpi_match = -1;
static gint ett_mpi_rndv = -1;
static gint ett_mpi_rget = -1;
static gint ett_mpi_frag = -1;
static gint ett_mpi_ack = -1;
static gint ett_mpi_rdma = -1;
static gint ett_mpi_fin = -1;
static gint ett_mpi_rndvrestartnotify = -1;

/* variables declaration */
static int hf_mpi_jobid = -1;
static int hf_mpi_vpid = -1;
static int hf_mpi_dst_vpid = -1;
static int hf_mpi_padding2 = -1;
static int hf_mpi_padding3 = -1;
static int hf_mpi_padding4 = -1;
static int hf_mpi_padding6 = -1;
static int hf_mpi_response_in = -1;
static int hf_mpi_response_to = -1;
static int hf_mpi_time = -1;
static int hf_mpi_src_req32_1 = -1;
static int hf_mpi_src_req32_2 = -1;
static int hf_mpi_src_req64 = -1;
static int hf_mpi_dst_req32_1 = -1;
static int hf_mpi_dst_req32_2 = -1;
static int hf_mpi_dst_req64 = -1;
static int hf_mpi_seg_cnt = -1;
static int hf_mpi_src_des32_1 = -1;
static int hf_mpi_src_des32_2 = -1;
static int hf_mpi_src_des64 = -1;

/* OOB header */
static int hf_mpi_oob_hdr_jobid_origin = -1;
static int hf_mpi_oob_hdr_vpid_origin = -1;
static int hf_mpi_oob_hdr_jobid_dst = -1;
static int hf_mpi_oob_hdr_vpid_dst = -1;
static int hf_mpi_oob_hdr_msg_type = -1;
static int hf_mpi_oob_hdr_rml_tag = -1;
static int hf_mpi_oob_hdr_nbytes = -1;
static int hf_mpi_oob_version = -1;
static int hf_mpi_oob_credential = -1;
static int hf_mpi_oob_data = -1;
static int hf_mpi_oob_iof_type = -1;
static int hf_mpi_oob_len = -1;
static int hf_mpi_oob_num_vals = -1;
static int hf_mpi_oob_odles_data_type = -1;
static int hf_mpi_oob_opal_data_type = -1;
static int hf_mpi_oob_orte_data_type = -1;
static int hf_mpi_oob_uri = -1;
static int hf_mpi_oob_nodename = -1;

/* BTL base header */
static int hf_mpi_base_hdr_base = -1;
static int hf_mpi_base_hdr_type = -1;
static int hf_mpi_base_hdr_count = -1;
static int hf_mpi_base_hdr_size = -1;

/* common header */
static int hf_mpi_common_hdr_type = -1;
static int hf_mpi_common_hdr_flags = -1;
static int hf_mpi_common_hdr_flags_ack = -1;
static int hf_mpi_common_hdr_flags_nbo = -1;
static int hf_mpi_common_hdr_flags_pin = -1;
static int hf_mpi_common_hdr_flags_contig = -1;
static int hf_mpi_common_hdr_flags_nordma = -1;
static int hf_mpi_common_hdr_flags_restart = -1;

/* match header */
static int hf_mpi_match_hdr_ctx = -1;
static int hf_mpi_match_hdr_src = -1;
static int hf_mpi_match_hdr_tag = -1;
static int hf_mpi_match_hdr_seq = -1;

/* rendezvous header */
static int hf_mpi_rndv_hdr_len = -1;
static int hf_mpi_rndv_hdr_restartseq = -1;

/* frag header */
static int hf_mpi_frag_hdr_frag_offset = -1;

/* ack header */
static int hf_mpi_ack_hdr_send_offset = -1;

/* rdma header */
static int hf_mpi_rdma_hdr_recv_req32_1 = -1;
static int hf_mpi_rdma_hdr_recv_req32_2 = -1;
static int hf_mpi_rdma_hdr_recv_req64 = -1;
static int hf_mpi_rdma_hdr_rdma_offset = -1;
static int hf_mpi_rdma_hdr_seg_addr32_1 = -1;
static int hf_mpi_rdma_hdr_seg_addr32_2 = -1;
static int hf_mpi_rdma_hdr_seg_addr64 = -1;
static int hf_mpi_rdma_hdr_seg_len = -1;

/* fin header */
static int hf_mpi_fin_hdr_fail = -1;
static int hf_mpi_fin_hdr_des32_1 = -1;
static int hf_mpi_fin_hdr_des32_2 = -1;
static int hf_mpi_fin_hdr_des64 = -1;

static const int *common_hdr_flags[] = {
    &hf_mpi_common_hdr_flags_ack,
    &hf_mpi_common_hdr_flags_nbo,
    &hf_mpi_common_hdr_flags_pin,
    &hf_mpi_common_hdr_flags_contig,
    &hf_mpi_common_hdr_flags_nordma,
    &hf_mpi_common_hdr_flags_restart,
    NULL
};

static const value_string msgtypenames[] = {
    { 0, "IDENT" },
    { 1, "PROBE" },
    { 2, "PING" },
    { 3, "USER" },
    { 0, NULL }
};

/* rml_types.h */
#define ORTE_RML_TAG_INVALID                 0
#define ORTE_RML_TAG_DAEMON                  1
#define ORTE_RML_TAG_IOF_HNP                 2
#define ORTE_RML_TAG_IOF_PROXY               3
#define ORTE_RML_TAG_XCAST_BARRIER           4
#define ORTE_RML_TAG_PLM                     5
#define ORTE_RML_TAG_PLM_PROXY               6
#define ORTE_RML_TAG_ERRMGR                  7
#define ORTE_RML_TAG_WIREUP                  8
#define ORTE_RML_TAG_RML_INFO_UPDATE         9
#define ORTE_RML_TAG_ORTED_CALLBACK         10
#define ORTE_RML_TAG_ROLLUP                 11
#define ORTE_RML_TAG_REPORT_REMOTE_LAUNCH   12
#define ORTE_RML_TAG_CKPT                   13
#define ORTE_RML_TAG_RML_ROUTE              14
#define ORTE_RML_TAG_XCAST                  15

#define ORTE_RML_TAG_UPDATE_ROUTE_ACK       19
#define ORTE_RML_TAG_SYNC                   20
/* For FileM Base */
#define ORTE_RML_TAG_FILEM_BASE             21
#define ORTE_RML_TAG_FILEM_BASE_RESP        22
/* For FileM RSH Component */
#define ORTE_RML_TAG_FILEM_RSH              23
/* For SnapC Framework */
#define ORTE_RML_TAG_SNAPC                  24
#define ORTE_RML_TAG_SNAPC_FULL             25
/* For tools */
#define ORTE_RML_TAG_TOOL                   26
/* support data store/lookup */
#define ORTE_RML_TAG_DATA_SERVER            27
#define ORTE_RML_TAG_DATA_CLIENT            28
/* timing related */
#define ORTE_RML_TAG_COLLECTIVE_TIMER       29
/* collectives */
#define ORTE_RML_TAG_COLLECTIVE             30
#define ORTE_RML_TAG_COLL_ID                31
#define ORTE_RML_TAG_DAEMON_COLL            32
#define ORTE_RML_TAG_COLL_ID_REQ            33
/* show help */
#define ORTE_RML_TAG_SHOW_HELP              34
/* debugger release */
#define ORTE_RML_TAG_DEBUGGER_RELEASE       35
/* bootstrap */
#define ORTE_RML_TAG_BOOTSTRAP              36
/* report a missed msg */
#define ORTE_RML_TAG_MISSED_MSG             37
/* tag for receiving ack of abort msg */
#define ORTE_RML_TAG_ABORT                  38
/* tag for receiving heartbeats */
#define ORTE_RML_TAG_HEARTBEAT              39
/* Process Migration Tool Tag */
#define ORTE_RML_TAG_MIGRATE                40
/* For SStore Framework */
#define ORTE_RML_TAG_SSTORE                 41
#define ORTE_RML_TAG_SSTORE_INTERNAL        42
#define ORTE_RML_TAG_SUBSCRIBE              43
/* Notify of failed processes */
#define ORTE_RML_TAG_FAILURE_NOTICE         44
/* distributed file system */
#define ORTE_RML_TAG_DFS_CMD                45
#define ORTE_RML_TAG_DFS_DATA               46
/* sensor data */
#define ORTE_RML_TAG_SENSOR_DATA            47
/* direct modex support */
#define ORTE_RML_TAG_DIRECT_MODEX           48
#define ORTE_RML_TAG_DIRECT_MODEX_RESP      49

#define ORTE_RML_TAG_MAX                   100

static const value_string rmltagnames[] = {
    { ORTE_RML_TAG_INVALID, "Invalid" },
    { ORTE_RML_TAG_DAEMON, "Daemon" },
    { ORTE_RML_TAG_IOF_HNP, "IOF HNP" },
    { ORTE_RML_TAG_IOF_PROXY, "IOF Proxy" },
    { ORTE_RML_TAG_XCAST_BARRIER, "XCAST Barrier" },
    { ORTE_RML_TAG_PLM, "PLM" },
    { ORTE_RML_TAG_PLM_PROXY, "PLM Proxy" },
    { ORTE_RML_TAG_ERRMGR, "Error Message" },
    { ORTE_RML_TAG_WIREUP, "Wireup" },
    { ORTE_RML_TAG_RML_INFO_UPDATE, "RML Info Update" },
    { ORTE_RML_TAG_ORTED_CALLBACK, "ORTED Callback" },
    { ORTE_RML_TAG_ROLLUP, "Rollup" },
    { ORTE_RML_TAG_REPORT_REMOTE_LAUNCH, "Report Remote Launch" },
    { ORTE_RML_TAG_CKPT, "CKPT" },
    { ORTE_RML_TAG_RML_ROUTE, "RML Route" },
    { ORTE_RML_TAG_XCAST, "XCAST" },
    { ORTE_RML_TAG_UPDATE_ROUTE_ACK, "Update Route ACK" },
    { ORTE_RML_TAG_SYNC, "SYNC" },
    { ORTE_RML_TAG_FILEM_BASE, "FileM Base" },
    { ORTE_RML_TAG_FILEM_BASE_RESP, "FileM Base Response" },
    { ORTE_RML_TAG_FILEM_RSH, "FileM RSH" },
    { ORTE_RML_TAG_SNAPC, "SNAPC" },
    { ORTE_RML_TAG_SNAPC_FULL, "SNAPC Full" },
    { ORTE_RML_TAG_TOOL, "Tool" },
    { ORTE_RML_TAG_DATA_SERVER, "Data Server" },
    { ORTE_RML_TAG_DATA_CLIENT, "Data Client" },
    { ORTE_RML_TAG_COLLECTIVE_TIMER, "Collective Timer" },
    { ORTE_RML_TAG_COLLECTIVE, "Collective" },
    { ORTE_RML_TAG_COLL_ID, "Collective ID" },
    { ORTE_RML_TAG_DAEMON_COLL, "Daemon Collective" },
    { ORTE_RML_TAG_COLL_ID_REQ, "Collective ID Request" },
    { ORTE_RML_TAG_SHOW_HELP, "Show Help" },
    { ORTE_RML_TAG_DEBUGGER_RELEASE, "Debugg Release" },
    { ORTE_RML_TAG_BOOTSTRAP, "Bootstrap" },
    { ORTE_RML_TAG_MISSED_MSG, "Missed Message" },
    { ORTE_RML_TAG_ABORT, "Abort" },
    { ORTE_RML_TAG_HEARTBEAT, "Heatbeat" },
    { ORTE_RML_TAG_MIGRATE, "Migrate" },
    { ORTE_RML_TAG_SSTORE, "SStore" },
    { ORTE_RML_TAG_SSTORE_INTERNAL, "SStore Internal" },
    { ORTE_RML_TAG_SUBSCRIBE, "Subscribe" },
    { ORTE_RML_TAG_FAILURE_NOTICE, "Failure Notice" },
    { ORTE_RML_TAG_DFS_CMD, "DFS Command "},
    { ORTE_RML_TAG_DFS_DATA, "DFS Data" },
    { ORTE_RML_TAG_SENSOR_DATA, "Sensor Data" },
    { ORTE_RML_TAG_DIRECT_MODEX, "Direct Modex" },
    { ORTE_RML_TAG_DIRECT_MODEX_RESP, "Direct Modex Response" },
    { ORTE_RML_TAG_MAX, "MAX Tag" },
    { 0, NULL }
};

/* pml_ob1_hdr.h pml_bfo_hdr.h */
#define MPI_PML_OB1_HDR_TYPE_MATCH 65
#define MPI_PML_BFO_HDR_TYPE_RNDV 66
#define MPI_PML_OB1_HDR_TYPE_RGET 67
#define MPI_PML_OB1_HDR_TYPE_ACK 68
#define MPI_PML_OB1_HDR_TYPE_NACK 69
#define MPI_PML_OB1_HDR_TYPE_FRAG 70
#define MPI_PML_OB1_HDR_TYPE_GET 71
#define MPI_PML_OB1_HDR_TYPE_PUT 72
#define MPI_PML_OB1_HDR_TYPE_FIN 73
#define MPI_PML_BFO_HDR_TYPE_RNDVRESTARTNOTIFY 74
#define MPI_PML_BFO_HDR_TYPE_RNDVRESTARTACK 75
#define MPI_PML_BFO_HDR_TYPE_RNDVRESTARTNACK 76
#define MPI_PML_BFO_HDR_TYPE_RECVERRNOTIFY 77

static const value_string packetbasenames[] = {
    { MPI_PML_OB1_HDR_TYPE_MATCH, "MATCH" },
    { MPI_PML_BFO_HDR_TYPE_RNDV, "RNDV" },
    { MPI_PML_OB1_HDR_TYPE_RGET, "RGET" },
    { MPI_PML_OB1_HDR_TYPE_ACK, "ACK" },
    { MPI_PML_OB1_HDR_TYPE_NACK, "NACK" },
    { MPI_PML_OB1_HDR_TYPE_FRAG, "FRAG" },
    { MPI_PML_OB1_HDR_TYPE_GET, "GET" },
    { MPI_PML_OB1_HDR_TYPE_PUT, "PUT" },
    { MPI_PML_OB1_HDR_TYPE_FIN, "FIN" },
    { MPI_PML_BFO_HDR_TYPE_RNDVRESTARTNOTIFY, "RNDVRESTARTNOTIFY" },
    { MPI_PML_BFO_HDR_TYPE_RNDVRESTARTACK, "RNDVRESTARTACK" },
    { MPI_PML_BFO_HDR_TYPE_RNDVRESTARTNACK, "RNDVRESTARTNACK" },
    { MPI_PML_BFO_HDR_TYPE_RECVERRNOTIFY, "RECVERRNOTIFY" },
    { 0, NULL }
};

static const value_string packettypenames[] = {
    { 1, "Send" },
    { 2, "Put" },
    { 3, "Get" },
    { 0, NULL }
};

static const value_string communicatornames[] = {
    { 0, "MPI_COMM_WORLD" },
    { 1, "MPI_COMM_SELF" },
    { 2, "MPI_COMM_NULL" },
    { 3, "MPI_GROUP" },
    { 0, NULL }
};

/* coll_tags.h */
static const value_string colltagnames[] = {
    { -10, "Allgather" },
    { -11, "Allgetherv" },
    { -12, "AllReduce" },
    { -13, "Alltoall" },
    { -14, "Alltoallv" },
    { -15, "Alltoallw" },
    { -16, "Barrier" },
    { -17, "Bcast" },
    { -18, "Exscan" },
    { -19, "Gather" },
    { -20, "Gatherv" },
    { -21, "Reduce" },
    { -22, "Reduce_scatter" },
    { -23, "Scan" },
    { -24, "Scatter" },
    { -25, "Scatterv" },
    { -26, "Nonblocking_base" },
    { -32767, "Nonblocking_end" }, /* ((-1 * INT_MAX/2) + 1) */
    { -32768, "Hcoll_base" }, /* (-1 * INT_MAX/2) */
    { -65535, "Hcoll_end" }, /* (-1 * INT_MAX) */
    { 0, NULL }
};

static const value_string paddingnames[] = {
    { 0, "heterogeneous support (maybe wrong!!)" },
    { 0, NULL }
};

/* iof_types.h */
#define ORTE_IOF_STDIN      0x01
#define ORTE_IOF_STDOUT     0x02
#define ORTE_IOF_STDERR     0x04
#define ORTE_IOF_STDDIAG    0x08
#define ORTE_IOF_STDOUTALL  0x0e

static const value_string ioftypenames[] = {
    { ORTE_IOF_STDIN, "STDIN" },
    { ORTE_IOF_STDOUT, "STDOUT" },
    { ORTE_IOF_STDERR, "STDERR" },
    { ORTE_IOF_STDDIAG, "STDDIAG" },
    { ORTE_IOF_STDOUTALL, "STDOUTALL" },
    { 0, NULL }
};

static const value_string opaldatatypenames[] = {
    { 0, "OPAL_UNDEF" },
    { 1, "OPAL_BYTE" },
    { 2, "OPAL_BOOL" },
    { 3, "OPAL_STRING" },
    { 4, "OPAL_SIZE" },
    { 5, "OPAL_PID" },
    { 6, "OPAL_INT" },
    { 7, "OPAL_INT8" },
    { 8, "OPAL_INT16" },
    { 9, "OPAL_INT32" },
    { 10, "OPAL_INT64" },
    { 11, "OPAL_UINT" },
    { 12, "OPAL_UINT8" },
    { 13, "OPAL_UINT16" },
    { 14, "OPAL_UINT32" },
    { 15, "OPAL_UINT64" },
    { 16, "OPAL_FLOAT" },
    { 17, "OPAL_TIMEVAL" },
    { 18, "OPAL_BYTE_OBJECT" },
    { 19, "OPAL_DATA_TYPE" },
    { 20, "OPAL_NULL" },
    { 21, "OPAL_PSTAT" },
    { 22, "OPAL_NODE_STAT" },
    { 23, "OPAL_HWLOC_TOPO" },
    { 24, "OPAL_VALUE" },
    { 25, "OPAL_BUFFER" },
    { 30, "OPAL_DSS_ID_DYNAMIC" },
    { 0, NULL }
};

static const value_string ortedatatypenames[] = {
    { 31, "ORTE_STD_CNTR" },
    { 32, "ORTE_NAME" },
    { 33, "ORTE_VPID" },
    { 34, "ORTE_JOBID" },
    { 35, "undefine?" },
    { 36, "ORTE_NODE_STATE" },
    { 37, "ORTE_PROC_STATE" },
    { 38, "ORTE_JOB_STATE" },
    { 39, "ORTE_EXIT_CODE" },
    { 40, "ORTE_VALUE" },
    { 41, "ORTE_APP_CONTEXT" },
    { 42, "ORTE_NODE_DESC" },
    { 43, "ORTE_SLOT_DESC" },
    { 44, "ORTE_JOB" },
    { 45, "ORTE_NODE" },
    { 46, "ORTE_PROC" },
    { 47, "ORTE_JOB_MAP" },
    { 48, "ORTE_RML_TAG" },
    { 49, "ORTE_DAEMON_CMD" },
    { 50, "ORTE_IOF_TAG" },
    { 80, "ORTE_DSS_ID_DYNAMIC" },
    { 0, NULL }
};

/* odls_types.h */
#define ORTE_DAEMON_CONTACT_QUERY_CMD     1
#define ORTE_DAEMON_KILL_LOCAL_PROCS      2
#define ORTE_DAEMON_SIGNAL_LOCAL_PROCS    3
#define ORTE_DAEMON_ADD_LOCAL_PROCS       4
#define ORTE_DAEMON_TREE_SPAWN            5
#define ORTE_DAEMON_HEARTBEAT_CMD         6
#define ORTE_DAEMON_EXIT_CMD              7
#define ORTE_DAEMON_PROCESS_AND_RELAY_CMD 9
#define ORTE_DAEMON_MESSAGE_LOCAL_PROCS   10
#define ORTE_DAEMON_NULL_CMD              11
#define ORTE_DAEMON_SYNC_BY_PROC          12
#define ORTE_DAEMON_SYNC_WANT_NIDMAP      13
/* commands for use by tools */
#define ORTE_DAEMON_REPORT_JOB_INFO_CMD   14
#define ORTE_DAEMON_REPORT_NODE_INFO_CMD  15
#define ORTE_DAEMON_REPORT_PROC_INFO_CMD  16
#define ORTE_DAEMON_SPAWN_JOB_CMD         17
#define ORTE_DAEMON_TERMINATE_JOB_CMD     18
#define ORTE_DAEMON_HALT_VM_CMD           19
/* request proc resource usage */
#define ORTE_DAEMON_TOP_CMD               22
/* bootstrap */
#define ORTE_DAEMON_NAME_REQ_CMD          23
#define ORTE_DAEMON_CHECKIN_CMD           24
#define ORTE_TOOL_CHECKIN_CMD             25
/* process msg command */
#define ORTE_DAEMON_PROCESS_CMD           26
/* process called "errmgr.abort_procs" */
#define ORTE_DAEMON_ABORT_PROCS_CALLED    28

static const value_string odlesdatatypenames[] = {
    { ORTE_DAEMON_CONTACT_QUERY_CMD, "Contact Query CMD" },
    { ORTE_DAEMON_KILL_LOCAL_PROCS, "Kill Local Procs" },
    { ORTE_DAEMON_SIGNAL_LOCAL_PROCS, "Signal Local Procs" },
    { ORTE_DAEMON_ADD_LOCAL_PROCS, "Add Local Procs" },
    { ORTE_DAEMON_TREE_SPAWN, "Tree Spawn" },
    { ORTE_DAEMON_HEARTBEAT_CMD, "Heartbeat CMD" },
    { ORTE_DAEMON_EXIT_CMD, "Exit CMD" },
    { ORTE_DAEMON_PROCESS_AND_RELAY_CMD, "Process and Relay CMD" },
    { ORTE_DAEMON_MESSAGE_LOCAL_PROCS, "Message Local Procs" },
    { ORTE_DAEMON_NULL_CMD, "Null CMD" },
    { ORTE_DAEMON_SYNC_BY_PROC, "SYNC by Proc" },
    { ORTE_DAEMON_SYNC_WANT_NIDMAP, "SYNC Want NIDMAP" },
    { ORTE_DAEMON_REPORT_JOB_INFO_CMD, "Report Job Info CMD" },
    { ORTE_DAEMON_REPORT_NODE_INFO_CMD, "Report Node Info CMD" },
    { ORTE_DAEMON_REPORT_PROC_INFO_CMD, "Report Proc Info CMD" },
    { ORTE_DAEMON_SPAWN_JOB_CMD, "Spawn Job CMD" },
    { ORTE_DAEMON_TERMINATE_JOB_CMD, "Terminate Job CMD" },
    { ORTE_DAEMON_HALT_VM_CMD, "Halt VM CMD" },
    { ORTE_DAEMON_TOP_CMD, "Top CMD" },
    { ORTE_DAEMON_NAME_REQ_CMD, "Name REQ CMD" },
    { ORTE_DAEMON_CHECKIN_CMD, "Checkin CMD" },
    { ORTE_TOOL_CHECKIN_CMD, "Tool Checkin CMD" },
    { ORTE_DAEMON_PROCESS_CMD, "Process CMD" },
    { ORTE_DAEMON_ABORT_PROCS_CALLED, "Abort Procs Called" },
    { 0, NULL }
};


typedef struct _mpi_info_t {
    wmem_tree_t *pdus;
} mpi_info_t;

typedef struct _mpi_sync_trans_t {
    guint32 jobid;
    guint32 vpid;
    guint32 req_frame;
    guint32 rep_frame;
    nstime_t req_time;
} mpi_sync_trans_t;

typedef struct _mpi_oob_trans_t {
    guint32 rml_tag_1;
    guint32 nbytes_1;
    guint32 rml_tag_2;
    guint32 nbytes_2;
    GHashTable *old;
} mpi_oob_trans_t;

typedef struct _mpi_oob_old_t {
    guint32 rml_tag;
    guint32 nbytes;
} mpi_oob_old_t;

/* data handler */
/* static dissector_handle_t data_handle; */
/* static dissector_handle_t mpi_sync_handler; */

static guint
address_hash_func(gconstpointer v)
{
  return GPOINTER_TO_UINT(v);
}

static gint
address_equal_func(gconstpointer v, gconstpointer v2)
{
  return v == v2;
}

static int
dissect_mpi_sync(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, guint the_offset)
{
    guint32 jobid;
    guint32 vpid;
    proto_item *ti = NULL;
    proto_tree *mpi_tree = NULL;
    conversation_t *conversation;
    mpi_info_t *mpi_info;
    mpi_sync_trans_t *mpi_sync_trans;
    gboolean is_request;
    wmem_tree_key_t key[3];

    if (8 != tvb_captured_length(tvb) - the_offset) {
        return the_offset;
    }

    if (MPI_DEBUG)
        g_print("%d dissect_mpi_sync, reported_length: %d offset: %d, tree: %s\n",
                pinfo->fd->num, tvb_reported_length(tvb), the_offset,
                tree ? "true":"false");

    col_set_str(pinfo->cinfo, COL_PROTOCOL, "MPI");

    /* Network-to-host-order accessors for 32-bit integers (guint32) */
    jobid = tvb_get_ntohl(tvb, 0);
    vpid = tvb_get_ntohl(tvb, 4);

    /* create or get conversation */
    conversation = find_or_create_conversation(pinfo);
    /* get conversation data */
    mpi_info = (mpi_info_t *)
        conversation_get_proto_data(conversation, proto_mpi);
    /* create conversation data if this not exist */
    if (!mpi_info) {
        mpi_info = wmem_new(wmem_file_scope(), mpi_info_t);
        mpi_info->pdus = wmem_tree_new(wmem_file_scope());
        conversation_add_proto_data(conversation, proto_mpi, mpi_info);
        is_request = TRUE; /* determine the request temporairily */
    } else {
        is_request = FALSE;
    }

    key[0].length = 1;
    key[0].key = &jobid;
    key[1].length = 1;
    key[1].key = &pinfo->fd->num;
    key[2].length = 0;
    key[2].key = NULL;

    /* fill the mpi_sync_trans struct only the first time */
    if (!pinfo->fd->flags.visited) {
        if (is_request) {
            mpi_sync_trans = wmem_new(wmem_file_scope(), mpi_sync_trans_t);
            mpi_sync_trans->jobid = jobid;
            mpi_sync_trans->vpid = vpid;
            mpi_sync_trans->req_frame = pinfo->fd->num;
            mpi_sync_trans->rep_frame = 0;
            mpi_sync_trans->req_time = pinfo->fd->abs_ts;
            wmem_tree_insert32_array(mpi_info->pdus, key,
                    (void *)mpi_sync_trans);
        } else {
            mpi_sync_trans = (mpi_sync_trans_t *)
                wmem_tree_lookup32_array_le(mpi_info->pdus, key);
            if (mpi_sync_trans) {
                if (mpi_sync_trans->jobid != jobid) {
                    mpi_sync_trans = NULL;
                } else {
                    mpi_sync_trans->rep_frame = pinfo->fd->num;
                }
            }
        }
    } else {
        mpi_sync_trans = (mpi_sync_trans_t *)
                wmem_tree_lookup32_array_le(mpi_info->pdus, key);
        if (mpi_sync_trans) {
            if (mpi_sync_trans->jobid != jobid) {
                mpi_sync_trans = NULL;
            /* redetermine the request, because the dissector is called a few times... */
            } else if (mpi_sync_trans->vpid != vpid) {
                is_request = FALSE;
            } else {
                is_request = TRUE;
            }
        }
    }
    if (!mpi_sync_trans) {
        /* create a "fake" mpi_sync_trans structure */
        mpi_sync_trans = wmem_new(wmem_packet_scope(), mpi_sync_trans_t);
        mpi_sync_trans->req_frame = 0;
        mpi_sync_trans->rep_frame = 0;
        mpi_sync_trans->req_time = pinfo->fd->abs_ts;
    }

    /* \xe2\x86\x92  UTF8_RIGHTWARDS_ARROW */
    col_add_fstr(pinfo->cinfo, COL_INFO, "%d\xe2\x86\x92%d [SYNC] Jobid=%d Vpid=%d (%s)",
            pinfo->srcport, pinfo->destport,
            jobid, vpid, (is_request ? "Request":"Response"));

    if (tree) {
        /* add the new tree node, from 0 to the end (-1) of this data
         * ENC_NA ("not applicable") is specified as the "encoding" parameter
         */
        /* ti = proto_tree_add_item(tree, proto_mpi, tvb, 0, -1, ENC_NA); */
        ti = proto_tree_add_protocol_format(tree, proto_mpi, tvb, 0, -1,
                "Message Passing Interface Protocol: Synchronization %s",
                is_request ? "Request":"Response");

        /* added a child node to the protocol tree
         * which is where we will do our detail dissection
         */
        mpi_tree = proto_item_add_subtree(ti, ett_mpi);
    }

    /* print in the tree */
    if (is_request) {
        if (mpi_sync_trans->rep_frame) {
            proto_item *it;
            it = proto_tree_add_uint(mpi_tree, hf_mpi_response_in, tvb, 0, 0,
                    mpi_sync_trans->rep_frame);
            PROTO_ITEM_SET_GENERATED(it);
        }
    } else {
        if (mpi_sync_trans->req_frame) {
            proto_item *it;
            nstime_t ns;

            it = proto_tree_add_uint(mpi_tree, hf_mpi_response_to, tvb, 0, 0,
                    mpi_sync_trans->req_frame);
            PROTO_ITEM_SET_GENERATED(it);

            nstime_delta(&ns, &pinfo->fd->abs_ts, &mpi_sync_trans->req_time);
            it = proto_tree_add_time(mpi_tree, hf_mpi_time, tvb, 0, 0, &ns);
            PROTO_ITEM_SET_GENERATED(it);
        }
    }

    if (tree) {
        proto_tree_add_item(mpi_tree, hf_mpi_jobid, tvb, 0, 4, ENC_BIG_ENDIAN);
        proto_tree_add_item(mpi_tree, hf_mpi_vpid, tvb, 4, 4, ENC_BIG_ENDIAN);
    }

    return tvb_captured_length(tvb);
}

static int
dissect_mpi_oop_opal_string(tvbuff_t *tvb, proto_tree *tree, guint offset, gboolean debug)
{
    if (debug) {
        proto_tree_add_item(tree, hf_mpi_oob_opal_data_type,
                tvb, offset, 1, ENC_BIG_ENDIAN);
        offset += 1;
        proto_tree_add_item(tree, hf_mpi_oob_num_vals,
                tvb, offset, 4, ENC_BIG_ENDIAN);
        offset += 4;
        proto_tree_add_item(tree, hf_mpi_oob_opal_data_type,
                tvb, offset, 1, ENC_BIG_ENDIAN);
        offset += 1;
        proto_tree_add_item(tree, hf_mpi_oob_len,
                tvb, offset, 4, ENC_BIG_ENDIAN);
        offset += 4;
    } else {
        proto_tree_add_item(tree, hf_mpi_oob_num_vals,
                tvb, offset, 4, ENC_BIG_ENDIAN);
        offset += 4;
        proto_tree_add_item(tree, hf_mpi_oob_len,
                tvb, offset, 4, ENC_BIG_ENDIAN);
        offset += 4;
    }
    return offset;
}

static int
dissect_mpi_oob_name(tvbuff_t *tvb, proto_tree *tree, guint offset, gboolean debug)
{
    if (debug) {
        proto_tree_add_item(tree, hf_mpi_oob_opal_data_type,
                tvb, offset, 1, ENC_BIG_ENDIAN);
        offset += 1;
        proto_tree_add_item(tree, hf_mpi_oob_num_vals,
                tvb, offset, 4, ENC_BIG_ENDIAN);
        offset += 4;
        proto_tree_add_item(tree, hf_mpi_oob_orte_data_type,
                tvb, offset, 1, ENC_BIG_ENDIAN);
        offset += 1;
        proto_tree_add_item(tree, hf_mpi_oob_opal_data_type,
                tvb, offset, 1, ENC_BIG_ENDIAN);
        offset += 1;
        proto_tree_add_item(tree, hf_mpi_jobid, tvb,
                offset, 4, ENC_BIG_ENDIAN);
        offset += 4;
        proto_tree_add_item(tree, hf_mpi_oob_opal_data_type,
                tvb, offset, 1, ENC_BIG_ENDIAN);
        offset += 1;
        proto_tree_add_item(tree, hf_mpi_vpid, tvb,
                offset, 4, ENC_BIG_ENDIAN);
        offset += 4;
    } else {
        proto_tree_add_item(tree, hf_mpi_oob_num_vals,
                tvb, offset, 4, ENC_BIG_ENDIAN);
        offset += 4;
        proto_tree_add_item(tree, hf_mpi_jobid, tvb,
                offset, 4, ENC_BIG_ENDIAN);
        offset += 4;
        proto_tree_add_item(tree, hf_mpi_vpid, tvb,
                offset, 4, ENC_BIG_ENDIAN);
        offset += 4;
    }
    return offset;
}


static int
dissect_mpi_oob(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, guint the_offset)
{
    proto_item *ti = NULL;
    proto_tree *mpi_tree = NULL;
    proto_tree *mpi_oob_tree = NULL;
    conversation_t *conversation;
    void *conv_data;
    mpi_oob_trans_t *mpi_oob_trans;
    guint offset;
    guint32 jobid_origin;
    guint32 vpid_origin;
    guint32 jobid_dst;
    guint32 vpid_dst;
    guint32 msg_type;
    guint32 rml_tag;
    guint32 nbytes;
    mpi_oob_old_t *value = NULL;
    /* invalid */
    int vers_len;
    int cred_len;
    const guint8 *version;
    const guint8 *credential;
    /* iof */
    guint8 fully_des;
    guint8 iof_type;
    guint32 jobid;
    guint32 vpid;
    /* orte callback */
    int uri_len;
    int nodename_len;
    const guint8 *uri;
    const guint8 *nodename;
    guint32 hwloc_len;
    /* xcast */
    guint8 odles;

    offset = 0;

    if (!(32768 <= pinfo->srcport && MAX_TCP_PORT >= pinfo->srcport &&
            32768 <= pinfo->destport && MAX_TCP_PORT >= pinfo->destport)) {
        return the_offset;
    }

    if (MPI_DEBUG)
        g_print("%d dissect_mpi_oob, reported_length: %d, offset: %d, tree: %s\n",
                pinfo->fd->num, tvb_reported_length(tvb), the_offset,
                tree ? "true":"false");

    col_set_str(pinfo->cinfo, COL_PROTOCOL, "MPI");
    col_clear(pinfo->cinfo,COL_INFO);

    col_add_fstr(pinfo->cinfo, COL_INFO, "%d\xe2\x86\x92%d [OOB]",
            pinfo->srcport, pinfo->destport);
    if (tree) {
        ti = proto_tree_add_item(tree, proto_mpi, tvb, 0, -1, ENC_NA);
        mpi_tree = proto_item_add_subtree(ti, ett_mpi);
    }

    conversation = find_conversation(pinfo->fd->num, &pinfo->src, &pinfo->dst,
            pinfo->ptype, pinfo->srcport, pinfo->destport, 0);

    if (!conversation) {
        conversation = conversation_new(pinfo->fd->num, &pinfo->src,
                &pinfo->dst, pinfo->ptype, pinfo->srcport, pinfo->destport, 0);
    }
    conv_data = conversation_get_proto_data(conversation, proto_mpi);
    if (conv_data) {
        mpi_oob_trans = (mpi_oob_trans_t *)conv_data;
    } else {
        if (28 > tvb_captured_length(tvb) - the_offset) {
            g_print("%d start new conversation without a header?\n",
                    pinfo->fd->num);
            return the_offset;
        }
        mpi_oob_trans = (mpi_oob_trans_t *)
                wmem_alloc0(wmem_file_scope(), sizeof(mpi_oob_trans_t));

        mpi_oob_trans->rml_tag_1 = 0;
        mpi_oob_trans->nbytes_1 = 0;
        mpi_oob_trans->rml_tag_2 = 0;
        mpi_oob_trans->nbytes_2 = 0;
        mpi_oob_trans->old = g_hash_table_new(address_hash_func,
                address_equal_func);

        conversation_add_proto_data(conversation, proto_mpi,
                (void *)mpi_oob_trans);
    }

    value = (mpi_oob_old_t *)
            g_hash_table_lookup(mpi_oob_trans->old, &pinfo->fd->num);
    if (NULL == value) {
        value = (mpi_oob_old_t *)
                wmem_alloc0(wmem_file_scope(), sizeof(mpi_oob_old_t));
        value->rml_tag = 0;
        value->nbytes = 0;
        g_hash_table_insert(mpi_oob_trans->old, &pinfo->fd->num, value);
    }

    /* (re)store the old values */
    if (pinfo->fd->flags.visited) {
        if (pinfo->srcport > pinfo->destport) {
            mpi_oob_trans->rml_tag_1 = value->rml_tag;
            mpi_oob_trans->nbytes_1 = value->nbytes;
        } else {
            mpi_oob_trans->rml_tag_2 = value->rml_tag;
            mpi_oob_trans->nbytes_2 = value->nbytes;
        }
        /* g_print("%d reload rml_tag: %d, nbytes: %d\n", pinfo->fd->num, value->rml_tag, value->nbytes); */
    } else {
        if (pinfo->srcport > pinfo->destport) {
            value->rml_tag = mpi_oob_trans->rml_tag_1;
            value->nbytes = mpi_oob_trans->nbytes_1;
        } else {
            value->rml_tag = mpi_oob_trans->rml_tag_2;
            value->nbytes = mpi_oob_trans->nbytes_2;
        }
        /* g_print("%d store rml_tag: %d, nbytes: %d\n", pinfo->fd->num, value->rml_tag, value->nbytes); */
    }


    while (tvb_captured_length(tvb) > the_offset) {

        offset = the_offset;

        if (pinfo->srcport > pinfo->destport) {
            nbytes = mpi_oob_trans->nbytes_1;
            rml_tag = mpi_oob_trans->rml_tag_1;
        } else {
            nbytes = mpi_oob_trans->nbytes_2;
            rml_tag = mpi_oob_trans->rml_tag_2;
        }

        if (0 == nbytes){ /* header */
            if (28 > tvb_captured_length(tvb) - offset) {
                return offset;
            }
            jobid_origin = tvb_get_ntohl(tvb, offset);
            offset += 4;
            vpid_origin = tvb_get_ntohl(tvb, offset);
            offset += 4;
            jobid_dst = tvb_get_ntohl(tvb, offset);
            offset += 4;
            vpid_dst = tvb_get_ntohl(tvb, offset);
            offset += 4;
            msg_type = tvb_get_ntohl(tvb, offset);
            offset += 4;
            rml_tag = tvb_get_ntohl(tvb, offset);
            offset += 4;
            nbytes = tvb_get_ntohl(tvb, offset);
            offset += 4;

            col_append_fstr(pinfo->cinfo, COL_INFO, " Header: "
                    "Jobid-Origin=%d Vpid-Origin=%d Jobid-Dst=%d Vpid-Dst=%d "
                    "Type=%s Tag=%s Length=%d",
                    jobid_origin, vpid_origin, jobid_dst, vpid_dst,
                    val_to_str(msg_type, msgtypenames, "%d"),
                    val_to_str(rml_tag, rmltagnames, "%d"), nbytes);

            if (tree) {
                offset = the_offset; //reset offset
                mpi_oob_tree = proto_tree_add_subtree(mpi_tree, tvb, 0, 0,
                        ett_mpi_oob_hdr, &ti, "OOB Header: ");
                proto_tree_add_item(mpi_oob_tree, hf_mpi_oob_hdr_jobid_origin, tvb,
                        offset, 4, ENC_BIG_ENDIAN);
                offset += 4;
                proto_tree_add_item(mpi_oob_tree, hf_mpi_oob_hdr_vpid_origin, tvb,
                        offset, 4, ENC_BIG_ENDIAN);
                offset += 4;
                proto_tree_add_item(mpi_oob_tree, hf_mpi_oob_hdr_jobid_dst, tvb,
                        offset, 4, ENC_BIG_ENDIAN);
                offset += 4;
                proto_tree_add_item(mpi_oob_tree, hf_mpi_oob_hdr_vpid_dst, tvb,
                        offset, 4, ENC_BIG_ENDIAN);
                offset += 4;
                proto_tree_add_item(mpi_oob_tree, hf_mpi_oob_hdr_msg_type, tvb,
                        offset, 4, ENC_BIG_ENDIAN);
                offset += 4;
                proto_tree_add_item(mpi_oob_tree, hf_mpi_oob_hdr_rml_tag, tvb,
                        offset, 4, ENC_BIG_ENDIAN);
                offset += 4;
                proto_tree_add_item(mpi_oob_tree, hf_mpi_oob_hdr_nbytes, tvb,
                        offset, 4, ENC_BIG_ENDIAN);
                offset += 4;

                proto_item_append_text(ti,
                        "jobid_origin: %d, vpid_origin: %d, "
                        "jobid_dst: %d, vpid_dst: %d, "
                        "type: %s, tag: %s, length: %d",
                        jobid_origin, vpid_origin, jobid_dst, vpid_dst,
                        val_to_str(msg_type, msgtypenames, "%d"),
                        val_to_str(rml_tag, rmltagnames, "%d"), nbytes);
            }

            if (pinfo->srcport > pinfo->destport) {
                mpi_oob_trans->rml_tag_1 = rml_tag;
                mpi_oob_trans->nbytes_1 = nbytes;
            } else {
                mpi_oob_trans->rml_tag_2 = rml_tag;
                mpi_oob_trans->nbytes_2 = nbytes;
            }

            the_offset = offset;

        } else { /* message */

            if (tvb_captured_length(tvb) - offset < nbytes) {
                if (pinfo->srcport > pinfo->destport) {
                    mpi_oob_trans->nbytes_1 = nbytes - 
                        (tvb_captured_length(tvb) - offset);
                } else {
                    mpi_oob_trans->nbytes_2 = nbytes - 
                        (tvb_captured_length(tvb) - offset);
                }
                nbytes = tvb_captured_length(tvb) - offset;
            } else {
                if (pinfo->srcport > pinfo->destport) {
                    mpi_oob_trans->nbytes_1 = 0;
                } else {
                    mpi_oob_trans->nbytes_2 = 0;
                }
            }

            col_append_fstr(pinfo->cinfo, COL_INFO, " Message: RML-Tag=%s",
                    val_to_str(rml_tag, rmltagnames, "%d"));

            if (tree) {
                mpi_oob_tree = proto_tree_add_subtree(mpi_tree, tvb, 0, 0,
                        ett_mpi_oob_msg, &ti, "OOB Message: ");

                proto_item_append_text(ti, "rml-tag: %s (%d)",
                        val_to_str(rml_tag, rmltagnames, "%d"), rml_tag);
            }

            if (MPI_DEBUG)
                g_print("%d dissect_mpi_oob_msg, rml_tag: %s (%d), offset: %d, "
                        "tree: %s\n",
                        pinfo->fd->num, val_to_str(rml_tag, rmltagnames, "%d"),
                        rml_tag, offset, tree ? "true":"false");
            switch(rml_tag) {
                case ORTE_RML_TAG_INVALID:
                    /* mpi-version "1.8.4\0" + credential "1234567\0" = 14 bytes */
                    if (14 == nbytes) {
                        version = tvb_get_const_stringz(tvb, offset, &vers_len);
                        if (tree) {
                            proto_tree_add_string(mpi_oob_tree,
                                    hf_mpi_oob_version, tvb, offset, vers_len,
                                    version); 
                        }
                        offset += vers_len;
                        credential = tvb_get_const_stringz(tvb, offset, &cred_len);
                        if (tree) {
                            proto_tree_add_string(mpi_oob_tree,
                                    hf_mpi_oob_credential, tvb, offset,
                                    cred_len, credential);
                        }
                        offset += cred_len;

                        proto_item_append_text(ti, ", mpi-version: %s, "
                                "credebtials: %s", version, credential);

                    } /* else: don't know */
                    break;
                case ORTE_RML_TAG_IOF_HNP:
                case ORTE_RML_TAG_IOF_PROXY:
                    fully_des = tvb_get_guint8(tvb, offset);
                    if (9 == fully_des) { /* with debug information */
                        if (30 > nbytes) { /* min length */
                            break;
                        }
                        offset += 7; /* OPAL_INT32(1) + num_vals(4) + ORTE_IOF_TAG(1) + OPAL_UINT8(1) */
                        iof_type = tvb_get_guint8(tvb, offset);
                        offset += 8; /* iof_type(1) + OPAL_INT32(1) + num_vals(4) + ORTE_NAME(1) + OPAL_UINT32(1) */
                        jobid = tvb_get_ntohl(tvb, offset);
                        offset += 5; /* jobid(4) + OPAL_UINT32(1) */
                        vpid = tvb_get_ntohl(tvb, offset);
                        offset += 10; /* vpid(4) + OPAL_INT32(1) + num_vals(4) + OPAL_BYTE(1) */

                        if (tree) {
                            offset = the_offset;
                            proto_tree_add_item(mpi_oob_tree, hf_mpi_oob_opal_data_type,
                                    tvb, offset, 1, ENC_BIG_ENDIAN);
                            offset += 1;
                            proto_tree_add_item(mpi_oob_tree, hf_mpi_oob_num_vals,
                                    tvb, offset, 4, ENC_BIG_ENDIAN);
                            offset += 4;
                            proto_tree_add_item(mpi_oob_tree, hf_mpi_oob_orte_data_type,
                                    tvb, offset, 1, ENC_BIG_ENDIAN);
                            offset += 1;
                            proto_tree_add_item(mpi_oob_tree, hf_mpi_oob_opal_data_type,
                                    tvb, offset, 1, ENC_BIG_ENDIAN);
                            offset += 1;
                            proto_tree_add_item(mpi_oob_tree, hf_mpi_oob_iof_type,
                                    tvb, offset, 1, ENC_BIG_ENDIAN);
                            offset += 1;

                            offset = dissect_mpi_oob_name(tvb, mpi_oob_tree,
                                    offset, TRUE);

                            proto_tree_add_item(mpi_oob_tree, hf_mpi_oob_opal_data_type,
                                    tvb, offset, 1, ENC_BIG_ENDIAN);
                            offset += 1;
                            proto_tree_add_item(mpi_oob_tree, hf_mpi_oob_num_vals,
                                    tvb, offset, 4, ENC_BIG_ENDIAN);
                            offset += 4;
                            proto_tree_add_item(mpi_oob_tree, hf_mpi_oob_opal_data_type,
                                    tvb, offset, 1, ENC_BIG_ENDIAN);
                            offset += 1;
                        }
                    } else { /* without debug information */
                        if (21 > nbytes) { /* min length */
                            break;
                        }
                        offset += 4; /* num_vals(4) */
                        iof_type = tvb_get_guint8(tvb, offset);
                        offset += 5; /* iof_type(1) + num_vals(4) */
                        jobid = tvb_get_ntohl(tvb, offset);
                        offset += 4; /* jobid(4) */
                        vpid = tvb_get_ntohl(tvb, offset);
                        offset += 8; /* vpid(4) + num_vals(4) */

                        if (tree) {
                            offset = the_offset;
                            proto_tree_add_item(mpi_oob_tree, hf_mpi_oob_num_vals,
                                    tvb, offset, 4, ENC_BIG_ENDIAN);
                            offset += 4;
                            proto_tree_add_item(mpi_oob_tree, hf_mpi_oob_iof_type,
                                    tvb, offset, 1, ENC_BIG_ENDIAN);
                            offset += 1;

                            offset = dissect_mpi_oob_name(tvb, mpi_oob_tree,
                                    offset, FALSE);

                            proto_tree_add_item(mpi_oob_tree, hf_mpi_oob_num_vals,
                                    tvb, offset, 4, ENC_BIG_ENDIAN);
                            offset += 4;
                        }
                    }

                    col_append_fstr(pinfo->cinfo, COL_INFO, " Type=%s "
                            "Jobid=%d Vpid=%d",
                            val_to_str(iof_type, ioftypenames, "%d"),
                            jobid, vpid);

                    proto_item_append_text(ti, ", debug: %s, type: %s, "
                            "jobid: %d, vpid: %d",
                            (9 == fully_des) ? "True" : "False",
                            val_to_str(iof_type, ioftypenames, "%d"),
                            jobid, vpid);
                    break;
                case ORTE_RML_TAG_ORTED_CALLBACK:
                    /*
                     * TODO: dissect hwloc with segmentation support
                     */
                    fully_des = tvb_get_guint8(tvb, offset);
                    if (9 == fully_des) { /* with debug information */
                        if (54 > nbytes || 1 != tvb_get_ntohl(tvb, offset+1)) {
                            break; /* min length up to the hwloc or a segment*/
                        }
                        offset += 7; /* OPAL_INT32(1) + num_vals(4) + ORTE_NAME(1) + OPAL_UINT32(1) */
                        jobid = tvb_get_ntohl(tvb, offset);
                        offset += 5; /* jobid(4) + OPAL_UINT32(1) */
                        vpid = tvb_get_ntohl(tvb, offset);
                        offset += 14; /* vpid(4) + OPAL_INT32(1) + num_vals(4) + OPAL_STRING(1) + len(4)*/
                        uri = tvb_get_const_stringz(tvb, offset, &uri_len);
                        offset += uri_len;
                        offset += 10; /* OPAL_INT32(1) + num_vals(4) + OPAL_STRING(1) + len(4) */
                        nodename = tvb_get_const_stringz(tvb, offset,
                                &nodename_len);
                        offset += nodename_len;
                        offset += 14; /* OPAL_INT32(1) + num_vals(4) + opal_data_type(4) + OPAL_INT32(1) + num_vasl(4) + OPAL_STRING(1) */
                        hwloc_len = tvb_get_ntohl(tvb, offset);
                        offset += 4;

                        if (tree) {
                            offset = dissect_mpi_oob_name(tvb, mpi_oob_tree,
                                    the_offset, TRUE);

                            offset = dissect_mpi_oop_opal_string(tvb,
                                    mpi_oob_tree, offset, TRUE);
                            proto_tree_add_string(mpi_oob_tree,
                                    hf_mpi_oob_uri, tvb, offset,
                                    uri_len, uri);
                            offset += uri_len;

                            offset = dissect_mpi_oop_opal_string(tvb,
                                    mpi_oob_tree, offset, TRUE);
                            proto_tree_add_string(mpi_oob_tree,
                                    hf_mpi_oob_nodename, tvb, offset,
                                    nodename_len, nodename);
                            offset += nodename_len;

                            proto_tree_add_item(mpi_oob_tree, hf_mpi_oob_opal_data_type,
                                    tvb, offset, 1, ENC_BIG_ENDIAN);
                            offset += 1;
                            proto_tree_add_item(mpi_oob_tree, hf_mpi_oob_num_vals,
                                    tvb, offset, 4, ENC_BIG_ENDIAN);
                            offset += 4;
                            proto_tree_add_item(mpi_oob_tree, hf_mpi_oob_opal_data_type,
                                    tvb, offset, 1, ENC_BIG_ENDIAN);
                            offset += 1;

                            offset = dissect_mpi_oop_opal_string(tvb,
                                    mpi_oob_tree, offset, TRUE);
                        }
                    } else { /* without debug information */
                        if (40 > nbytes || 1 != tvb_get_ntohl(tvb, offset)) {
                            break; /* min length up to the hwloc or a segment*/
                        }
                        offset += 4; /* num_vals(4) */
                        jobid = tvb_get_ntohl(tvb, offset);
                        offset += 4; /* jobid(4) */
                        vpid = tvb_get_ntohl(tvb, offset);
                        offset += 12; /* vpid(4) + num_vals(4) + len(4)*/
                        uri = tvb_get_const_stringz(tvb, offset, &uri_len);
                        offset += uri_len;
                        offset += 8; /* num_vals(4) + len(4) */
                        nodename = tvb_get_const_stringz(tvb, offset,
                                &nodename_len);
                        offset += nodename_len;
                        offset += 8; /* num_vals(4) + num_vasl(4) */
                        hwloc_len = tvb_get_ntohl(tvb, offset);
                        offset += 4;
                    
                        if (tree) {
                            offset = dissect_mpi_oob_name(tvb, mpi_oob_tree,
                                    the_offset, FALSE);

                            offset = dissect_mpi_oop_opal_string(tvb,
                                    mpi_oob_tree, offset, FALSE);
                            proto_tree_add_string(mpi_oob_tree,
                                    hf_mpi_oob_uri, tvb, offset,
                                    uri_len, uri);
                            offset += uri_len;

                            offset = dissect_mpi_oop_opal_string(tvb,
                                    mpi_oob_tree, offset, FALSE);
                            proto_tree_add_string(mpi_oob_tree,
                                    hf_mpi_oob_nodename, tvb, offset,
                                    nodename_len, nodename);
                            offset += nodename_len;

                            proto_tree_add_item(mpi_oob_tree, hf_mpi_oob_num_vals,
                                    tvb, offset, 4, ENC_BIG_ENDIAN);
                            offset += 4;

                            offset = dissect_mpi_oop_opal_string(tvb,
                                    mpi_oob_tree, offset, FALSE);
                        }
                    }

                    col_append_fstr(pinfo->cinfo, COL_INFO, " Jobid=%d Vpid=%d, "
                            "Nodename=%s URI=%s hwloc-len=%d",
                            jobid, vpid, nodename, uri, hwloc_len);

                    proto_item_append_text(ti, ", jobid: %d, vpid: %d, "
                            "nodename: %s, uri: %s, hwloc-len: %d",
                            jobid, vpid, nodename, uri, hwloc_len);
                    break;
                case ORTE_RML_TAG_XCAST:
                    fully_des = tvb_get_guint8(tvb, offset);
                    if (9 == fully_des) { /* with debug information */
                        if (8 > nbytes) { /* MPI_Abort: 09:00:00:00:01:31:0c:07 */
                            break;
                        } /* TODO: implement other cases */
                        offset += 7;
                        odles = tvb_get_guint8(tvb, offset);
                        offset += 1;
                        if (tree) {
                            offset = the_offset;
                            proto_tree_add_item(mpi_oob_tree, hf_mpi_oob_opal_data_type,
                                    tvb, offset, 1, ENC_BIG_ENDIAN);
                            offset += 1;
                            proto_tree_add_item(mpi_oob_tree, hf_mpi_oob_num_vals,
                                    tvb, offset, 4, ENC_BIG_ENDIAN);
                            offset += 4;
                            proto_tree_add_item(mpi_oob_tree, hf_mpi_oob_orte_data_type,
                                    tvb, offset, 1, ENC_BIG_ENDIAN);
                            offset += 1;
                            proto_tree_add_item(mpi_oob_tree, hf_mpi_oob_opal_data_type,
                                    tvb, offset, 1, ENC_BIG_ENDIAN);
                            offset += 1;
                            proto_tree_add_item(mpi_oob_tree, hf_mpi_oob_odles_data_type,
                                    tvb, offset, 1, ENC_BIG_ENDIAN);
                            offset += 1;
                        }
                    } else { /* without debug information */
                        if (5 > nbytes) { /* MPI_Abort: 00:00:00:01:07 */
                            break;
                        }
                        offset += 4;
                        odles = tvb_get_guint8(tvb, offset);
                        offset += 1;
                        if (tree) {
                            offset = the_offset;
                            proto_tree_add_item(mpi_oob_tree, hf_mpi_oob_num_vals,
                                    tvb, offset, 4, ENC_BIG_ENDIAN);
                            offset += 4;
                            proto_tree_add_item(mpi_oob_tree, hf_mpi_oob_odles_data_type,
                                    tvb, offset, 1, ENC_BIG_ENDIAN);
                            offset += 1;
                        }
                    }

                    col_append_fstr(pinfo->cinfo, COL_INFO, " Daemon-CMD=%s",
                            val_to_str(odles, odlesdatatypenames, "%d"));

                    proto_item_append_text(ti, ", daemon-cmd: %s",
                            val_to_str(odles, odlesdatatypenames, "%d"));
                    break;
            }
            nbytes -= (offset - the_offset);
            if (0 < nbytes) {
                col_append_fstr(pinfo->cinfo, COL_INFO, " Length=%d", nbytes);
                proto_item_append_text(ti, ", length: %d", nbytes);
            }
            if (tvb_captured_length(tvb) > offset) {
                proto_tree_add_item(mpi_oob_tree, hf_mpi_oob_data, tvb,
                        offset, nbytes, ENC_BIG_ENDIAN);
                offset += nbytes;
            }
            the_offset = offset;
        }
    }

    return the_offset;
}

static int
dissect_mpi_match(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, guint the_offset)
{
    proto_item *ti = NULL;
    proto_tree *mpi_match_tree = NULL;
    guint32 byte_order;
    guint offset;
    guint16 match_ctx;
    gint32 match_src;
    gint32 match_tag;
    guint16 match_seq;
    guint16 match_padding;

    if (12 > tvb_reported_length(tvb) - the_offset) {
        return the_offset;
    }

    if (MPI_DEBUG)
        g_print("%d dissect_mpi_match, reported_length: %d offset: %d, tree: %s\n",
                pinfo->fd->num, tvb_reported_length(tvb), the_offset,
                tree ? "true":"false");

    match_padding = 1;
    offset = the_offset;
    if (pref_little_endian) {
        byte_order = ENC_LITTLE_ENDIAN;
        match_ctx = tvb_get_letohs(tvb, offset);
        offset += 2;
        match_src = tvb_get_letohl(tvb, offset);
        offset += 4;
        match_tag = tvb_get_letohl(tvb, offset);
        offset += 4;
        match_seq = tvb_get_letohs(tvb, offset);
        offset += 2;
        if (offset + 2 <= tvb_reported_length(tvb)) {
            /* ugly hack :-( */
            if (!(4 == tvb_reported_length(tvb) - offset &&
                    0 == tvb_get_letohl(tvb, offset))) {
                match_padding = tvb_get_letohs(tvb, offset);
                offset += 2;
            }
        }
    } else {
        byte_order = ENC_BIG_ENDIAN;

        match_ctx = tvb_get_ntohs(tvb, offset);
        offset += 2;
        match_src = tvb_get_ntohl(tvb, offset);
        offset += 4;
        match_tag = tvb_get_ntohl(tvb, offset);
        offset += 4;
        match_seq = tvb_get_ntohs(tvb, offset);
        offset += 2;
        if (offset + 2 <= tvb_reported_length(tvb)) {
            /* ugly hack :-( */
            if (!(4 == tvb_reported_length(tvb) - offset &&
                    0 == tvb_get_letohl(tvb, offset))) {
                match_padding = tvb_get_ntohs(tvb, offset);
                offset += 2;
            }
        }
    }

    col_append_fstr(pinfo->cinfo, COL_INFO, " %s (%s) Src-Vpid=%d Seq=%d",
            val_to_str(match_tag, colltagnames, "Msg-Tag=%d"),
            val_to_str(match_ctx, communicatornames, "ctx=%d"),
            match_src, match_seq);

    if (tree) {
        /* match header */
        offset = the_offset;
        mpi_match_tree = proto_tree_add_subtree(tree, tvb, 0, 0, ett_mpi_match,
                &ti, "BTL Match Header: ");
        proto_tree_add_item(mpi_match_tree, hf_mpi_match_hdr_ctx, tvb,
                offset, 2, byte_order);
        offset += 2;
        proto_tree_add_item(mpi_match_tree, hf_mpi_match_hdr_src, tvb,
                offset, 4, byte_order);
        offset += 4;
        proto_tree_add_item(mpi_match_tree, hf_mpi_match_hdr_tag, tvb,
                offset, 4, byte_order);
        offset += 4;
        proto_tree_add_item(mpi_match_tree, hf_mpi_match_hdr_seq, tvb,
                offset, 2, byte_order);
        offset += 2;
        /* padding for heterogeneous support */
        if (0 == match_padding) {
            proto_tree_add_item(mpi_match_tree, hf_mpi_padding2, tvb,
                    offset, 2, byte_order);
            offset += 2;
        }
        proto_item_append_text(ti, "%s, src: %d, tag: %s, seq: %d%s",
                val_to_str(match_ctx, communicatornames, "ctx: %d"), match_src,
                val_to_str(match_tag, colltagnames, "%d"), match_seq,
                (0 == match_padding ? ", padding: 2 Bytes":""));
    }
    return offset;
}

static int
dissect_mpi_rndv(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, guint the_offset)
{
    proto_item *ti = NULL;
    proto_tree *mpi_rndv_tree = NULL;
    guint32 byte_order;
    guint offset;
    guint64 rndv_msg_len;
    guint64 rndv_src_req64;
    guint64 rndv_dst_req64;
    guint8 rndv_restartseq;
    gboolean rndv_bfo;

    /* too small for a match header */
    if (12 > tvb_reported_length(tvb) - the_offset) {
        return the_offset;
    }

    if (MPI_DEBUG)
        g_print("%d dissect_mpi_rndv, reported_length: %d, offset: %d, tree: %s\n",
                pinfo->fd->num, tvb_reported_length(tvb), the_offset,
                tree ? "true":"false");

    the_offset = dissect_mpi_match(tvb, pinfo, tree, the_offset);

    /* we need 16 bytes for the minimum rendezvous header */
    if (16 > tvb_reported_length(tvb) - the_offset) {
        return the_offset;
    }

    offset = the_offset;
    rndv_bfo = FALSE;

    if (pref_little_endian) {
        byte_order = ENC_LITTLE_ENDIAN;
        rndv_msg_len = tvb_get_letoh64(tvb, offset);
        offset += 8;
        rndv_src_req64 = tvb_get_letoh64(tvb, offset);
        offset += 8;
        if (9 <= tvb_reported_length(tvb) - offset) {
            rndv_dst_req64 = tvb_get_letoh64(tvb, offset);
            offset += 8;
            rndv_bfo = TRUE;
        }
    } else {
        byte_order = ENC_BIG_ENDIAN;
        rndv_msg_len = tvb_get_ntoh64(tvb, offset);
        offset += 8;
        rndv_src_req64 = tvb_get_ntoh64(tvb, offset);
        offset += 8;
        if (9 <= tvb_reported_length(tvb) - offset) {
            rndv_dst_req64 = tvb_get_ntoh64(tvb, offset);
            offset += 8;
            rndv_bfo = TRUE;
        }
    }
    if (rndv_bfo) {
        rndv_restartseq = tvb_get_guint8(tvb, offset);
        offset += 1;
        col_append_fstr(pinfo->cinfo, COL_INFO,
                " Msg-Len=%" G_GINT64_MODIFIER "u Restartseq=%d",
                rndv_msg_len, rndv_restartseq);
    } else {
        col_append_fstr(pinfo->cinfo, COL_INFO,
                " Msg-Len=%" G_GINT64_MODIFIER "u", rndv_msg_len);
    }

    if (tree) {
        /* rendezvous header */
        offset = the_offset;
        mpi_rndv_tree = proto_tree_add_subtree(tree, tvb, 0, 0, ett_mpi_rndv,
                &ti, "BTL Rendezvous Header: ");
        proto_tree_add_item(mpi_rndv_tree, hf_mpi_rndv_hdr_len, tvb,
                offset, 8, byte_order);
        offset += 8;
        /* typedef union {
         *     uint64_t lval;
         *     uint32_t ival;
         *     void*    pval;
         *     struct {
         *         uint32_t uval;
         *         uint32_t lval;
         *     } sval;
         *  } ompi_ptr_t;
         */
        proto_tree_add_item(mpi_rndv_tree, hf_mpi_src_req32_1, tvb,
                offset, 4, byte_order);
        proto_tree_add_item(mpi_rndv_tree, hf_mpi_src_req32_2, tvb,
                offset + 4, 4, byte_order);
        proto_tree_add_item(mpi_rndv_tree, hf_mpi_src_req64, tvb,
                offset, 8, byte_order);
        offset += 8;
        if (rndv_bfo) {
            proto_tree_add_item(mpi_rndv_tree, hf_mpi_dst_req32_1, tvb,
                    offset, 4, byte_order);
            proto_tree_add_item(mpi_rndv_tree, hf_mpi_dst_req32_2, tvb,
                    offset + 4, 4, byte_order);
            proto_tree_add_item(mpi_rndv_tree, hf_mpi_dst_req64, tvb,
                    offset, 8, byte_order);
            offset += 8;
            proto_tree_add_item(mpi_rndv_tree, hf_mpi_rndv_hdr_restartseq, tvb,
                    offset, 1, byte_order);
            offset += 1;

            proto_item_append_text(ti,
                    "msg_len: %" G_GUINT64_FORMAT ", "
                    "src_req: 0x%016" G_GINT64_MODIFIER "x "
                    "dst_req: 0x%016" G_GINT64_MODIFIER "x "
                    "restartseq: %d",
                    rndv_msg_len, rndv_src_req64,
                    rndv_dst_req64, rndv_restartseq);
        } else {
            proto_item_append_text(ti,
                    "msg_len: %" G_GUINT64_FORMAT ", "
                    "src_req: 0x%016" G_GINT64_MODIFIER "x",
                    rndv_msg_len, rndv_src_req64);
        }
    }
    return offset;
}

static int
dissect_mpi_rget(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, guint the_offset)
{
    proto_item *ti = NULL;
    proto_tree *mpi_rget_tree = NULL;
    guint32 byte_order;
    guint offset;
    guint32 rget_seg_cnt;
    guint32 rget_padding;
    guint64 rget_src_des64;

    /* too small for a rendezvous header */
    if (28 > tvb_reported_length(tvb) - the_offset) {
        return the_offset;
    }

    if (MPI_DEBUG)
        g_print("%d dissect_mpi_rget, reported_length: %d, offset: %d, tree: %s\n",
                pinfo->fd->num, tvb_reported_length(tvb), the_offset,
                tree ? "true":"false");

    the_offset = dissect_mpi_rndv(tvb, pinfo, tree, the_offset);

    /* we need minimum 12 bytes for the rendezvous/get header */
    if (12 > tvb_reported_length(tvb) - the_offset) {
        return the_offset;
    }

    offset = the_offset;
    rget_padding = 1;

    if (pref_little_endian) {
        byte_order = ENC_LITTLE_ENDIAN;
        rget_seg_cnt = tvb_get_letohl(tvb, offset);
        offset += 4;
        /* space for padding (4 bytes) + source descriptor (8 bytes) */
        if (12 <= tvb_reported_length(tvb) - offset) {
            rget_padding = tvb_get_letohl(tvb, offset);
            offset += 4;
        }
        rget_src_des64 = tvb_get_letoh64(tvb, offset);
        offset += 8;
    } else {
        byte_order = ENC_BIG_ENDIAN;
        rget_seg_cnt = tvb_get_ntohl(tvb, offset);
        offset += 4;
        if (tvb_reported_length(tvb) - offset >= 12) {
            rget_padding = tvb_get_ntohl(tvb, offset);
            offset += 4;
        }
        rget_src_des64 = tvb_get_ntoh64(tvb, offset);
        offset += 8;
    }

    col_append_fstr(pinfo->cinfo, COL_INFO,
            " Num-Seg=%d Src-Des=0x%016" G_GINT64_MODIFIER "x",
            rget_seg_cnt, rget_src_des64);

    if (tree) {
        offset = the_offset;
        mpi_rget_tree = proto_tree_add_subtree(tree, tvb, 0, 0, ett_mpi_rget,
                &ti, "BTL Rendezvous/Get Header: ");

        proto_tree_add_item(mpi_rget_tree, hf_mpi_seg_cnt, tvb,
                offset, 4, byte_order);
        offset += 4;
        if (0 == rget_padding) {
            proto_tree_add_item(mpi_rget_tree, hf_mpi_padding4, tvb,
                    offset, 4, byte_order);
            offset += 4;
        }
        proto_tree_add_item(mpi_rget_tree, hf_mpi_src_des64, tvb,
                offset, 8, byte_order);
        offset += 8;

        proto_item_append_text(ti,
            "seg_cnt: %d, src_des: 0x%016" G_GINT64_MODIFIER "x",
            rget_seg_cnt, rget_src_des64);
    }

    return offset;
}

static int
dissect_mpi_frag(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, guint the_offset)
{
    proto_item *ti = NULL;
    proto_tree *mpi_frag_tree = NULL;
    guint32 byte_order;
    guint offset;
    guint64 frag_padding;
    guint64 frag_frag_offset;
    guint64 frag_src_req64;
    guint64 frag_des_req64;

    /* we need minimum 24 bytes for the frag header */
    if (24 > tvb_reported_length(tvb) - the_offset) {
        return the_offset;
    }

    if (MPI_DEBUG)
        g_print("%d dissect_mpi_frag, reported_length: %d, offset: %d, tree: %s\n",
                pinfo->fd->num, tvb_reported_length(tvb), the_offset,
                tree ? "true":"false");

    offset = the_offset;
    frag_padding = 1;

    if (pref_little_endian) {
        byte_order = ENC_LITTLE_ENDIAN;
        /* space for padding (6 bytes) + offset (8 bytes) + 2* pointer (16 bytes) */
        if (30 <= tvb_reported_length(tvb) - offset) {
            frag_padding = tvb_get_letoh48(tvb, offset);
            offset += 6;
        }
        frag_frag_offset = tvb_get_letoh64(tvb, offset);
        offset += 8;
        frag_src_req64 = tvb_get_letoh64(tvb, offset);
        offset += 8;
        frag_des_req64 = tvb_get_letoh64(tvb, offset);
        offset += 8;
    } else {
        byte_order = ENC_BIG_ENDIAN;
        /* space for padding (6 bytes) + offset (8 bytes) + 2* pointer (16 bytes) */
        if (30 <= tvb_reported_length(tvb) - offset) {
            frag_padding = tvb_get_ntoh48(tvb, offset);
            offset += 6;
        }
        frag_frag_offset = tvb_get_ntoh64(tvb, offset);
        offset += 8;
        frag_src_req64 = tvb_get_ntoh64(tvb, offset);
        offset += 8;
        frag_des_req64 = tvb_get_ntoh64(tvb, offset);
        offset += 8;
    }

    col_append_fstr(pinfo->cinfo, COL_INFO,
            " Msg-Offset=%" G_GINT64_MODIFIER "u"
            " Src-Req=0x%016" G_GINT64_MODIFIER "x"
            " Des-Req=0x%016" G_GINT64_MODIFIER "x",
            frag_frag_offset, frag_src_req64, frag_des_req64);

    if (tree) {
        offset = the_offset;
        mpi_frag_tree = proto_tree_add_subtree(tree, tvb, 0, 0, ett_mpi_frag,
                &ti, "BTL Fragment Header: ");

        if (0 == frag_padding) {
            proto_tree_add_item(mpi_frag_tree, hf_mpi_padding6, tvb,
                    offset, 6, byte_order);
            offset += 6;
        }

        proto_tree_add_item(mpi_frag_tree, hf_mpi_frag_hdr_frag_offset, tvb,
                offset, 8, byte_order);
        offset += 8;
        proto_tree_add_item(mpi_frag_tree, hf_mpi_src_req32_1, tvb,
                offset, 4, byte_order);
        proto_tree_add_item(mpi_frag_tree, hf_mpi_src_req32_2, tvb,
                offset + 4, 4, byte_order);
        proto_tree_add_item(mpi_frag_tree, hf_mpi_src_req64, tvb,
                offset, 8, byte_order);
        offset += 8;
        proto_tree_add_item(mpi_frag_tree, hf_mpi_dst_req32_1, tvb,
                offset, 4, byte_order);
        proto_tree_add_item(mpi_frag_tree, hf_mpi_dst_req32_2, tvb,
                offset + 4, 4, byte_order);
        proto_tree_add_item(mpi_frag_tree, hf_mpi_dst_req64, tvb,
                offset, 8, byte_order);
        offset += 8;

        proto_item_append_text(ti,
                "frag_offset: %" G_GINT64_MODIFIER "u"
                "src_req: 0x%016" G_GINT64_MODIFIER "x"
                "des_req: 0x%016" G_GINT64_MODIFIER "x",
                frag_frag_offset, frag_src_req64, frag_des_req64);
    }
    return offset;
}

static int
dissect_mpi_ack(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, guint the_offset)
{
    proto_item *ti = NULL;
    proto_tree *mpi_ack_tree = NULL;
    guint32 byte_order;
    guint offset;
    guint64 ack_padding;
    guint64 ack_src_req64;
    guint64 ack_dst_req64;
    guint64 ack_send_offset;

    /* we need minimum 24 bytes for the ack header */
    if (24 > tvb_reported_length(tvb) - the_offset) {
        return the_offset;
    }

    if (MPI_DEBUG)
        g_print("%d dissect_mpi_ack, reported_length: %d, offset: %d, tree: %s\n",
                pinfo->fd->num, tvb_reported_length(tvb), the_offset,
                tree ? "true":"false");

    offset = the_offset;
    ack_padding = 1;

    if (pref_little_endian) {
        byte_order = ENC_LITTLE_ENDIAN;
        /* space for padding (6 bytes) + 2* pointer (16 bytes) + offset (8 bytes) */
        if (30 <= tvb_reported_length(tvb) - offset) {
            ack_padding = tvb_get_letoh48(tvb, offset);
            offset += 6;
        }
        ack_src_req64 = tvb_get_letoh64(tvb, offset);
        offset += 8;
        ack_dst_req64 = tvb_get_letoh64(tvb, offset);
        offset += 8;
        ack_send_offset = tvb_get_letoh64(tvb, offset);
        offset += 8;
    } else {
        byte_order = ENC_BIG_ENDIAN;
        /* space for padding (6 bytes) + 2* pointer (16 bytes) + offset (8 bytes) */
        if (30 <= tvb_reported_length(tvb) - offset) {
            ack_padding = tvb_get_ntoh48(tvb, offset);
            offset += 6;
        }
        ack_src_req64 = tvb_get_ntoh64(tvb, offset);
        offset += 8;
        ack_dst_req64 = tvb_get_ntoh64(tvb, offset);
        offset += 8;
        ack_send_offset = tvb_get_ntoh64(tvb, offset);
        offset += 8;
    }

    col_append_fstr(pinfo->cinfo, COL_INFO,
            " Src-Req=0x%016" G_GINT64_MODIFIER "x"
            " Dst-Req=0x%016" G_GINT64_MODIFIER "x"
            " Send-Offset=%" G_GINT64_MODIFIER "u",
            ack_src_req64, ack_dst_req64, ack_send_offset);

    if (tree) {
        offset = the_offset;
        mpi_ack_tree = proto_tree_add_subtree(tree, tvb, 0, 0, ett_mpi_ack,
                &ti, "BTL Acknowledgment Header: ");

        if (0 == ack_padding) {
            proto_tree_add_item(mpi_ack_tree, hf_mpi_padding6,
                tvb, offset, 6, byte_order);
            offset += 6;
        }

        proto_tree_add_item(mpi_ack_tree, hf_mpi_src_req32_1, tvb,
                offset, 4, byte_order);
        proto_tree_add_item(mpi_ack_tree, hf_mpi_src_req32_2, tvb,
                offset + 4, 4, byte_order);
        proto_tree_add_item(mpi_ack_tree, hf_mpi_src_req64, tvb,
                offset, 8, byte_order);
        offset += 8;
        proto_tree_add_item(mpi_ack_tree, hf_mpi_dst_req32_1, tvb,
                offset, 4, byte_order);
        proto_tree_add_item(mpi_ack_tree, hf_mpi_dst_req32_2, tvb,
                offset + 4, 4, byte_order);
        proto_tree_add_item(mpi_ack_tree, hf_mpi_dst_req64, tvb,
                offset, 8, byte_order);
        offset += 8;
        proto_tree_add_item(mpi_ack_tree, hf_mpi_ack_hdr_send_offset, tvb,
                offset, 8, byte_order);
        offset += 8;

        proto_item_append_text(ti,
                "src_req: 0x%016" G_GINT64_MODIFIER "x, "
                "dst_req: 0x%016" G_GINT64_MODIFIER "x, "
                "send_offset: %" G_GINT64_MODIFIER "u",
                ack_src_req64, ack_dst_req64, ack_send_offset);
    }
    return offset;
}

static int
dissect_mpi_rdma(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, guint the_offset)
{
    proto_item *ti = NULL;
    proto_tree *mpi_rdma_tree = NULL;
    guint32 byte_order;
    guint offset;
    guint16 rdma_padding;
    guint32 rdma_seg_cnt;
    guint64 rdma_rdma_offset;
    guint64 rdma_seg_addr64;
    guint64 rdma_seg_len;

    /* we need minimum 52 bytes for the rdma header */
    if (52 > tvb_reported_length(tvb) - the_offset) {
        return the_offset;
    }

    if (MPI_DEBUG)
        g_print("%d dissect_mpi_rdma, reported_length: %d, offset: %d, tree: %s\n",
                pinfo->fd->num, tvb_reported_length(tvb), the_offset,
                tree ? "true":"false");

    offset = the_offset;
    rdma_padding = 1;

    if (pref_little_endian) {
        byte_order = ENC_LITTLE_ENDIAN;
        /* space for padding (2 bytes) + rdma header (52 bytes) */
        if (54 <= tvb_reported_length(tvb) - offset) {
            rdma_padding = tvb_get_letohs(tvb, offset);
            offset += 2;
        }
        rdma_seg_cnt = tvb_get_letohl(tvb, offset);
        offset += 4;
        offset += 24; /* destination request, source descriptor, source descriptor */
        rdma_rdma_offset = tvb_get_letoh64(tvb, offset);
        offset += 8;
        rdma_seg_addr64 = tvb_get_letoh64(tvb, offset);
        offset += 8;
        rdma_seg_len = tvb_get_letoh64(tvb, offset);
        offset += 8;
    } else {
        byte_order = ENC_BIG_ENDIAN;
        /* space for padding (2 bytes) + rdma header (52 bytes) */
        if (54 <= tvb_reported_length(tvb) - offset) {
            rdma_padding = tvb_get_letohs(tvb, offset);
            offset += 2;
        }
        rdma_seg_cnt = tvb_get_ntohl(tvb, offset);
        offset += 4;
        offset += 24; /* destination request, source descriptor, source descriptor */
        rdma_rdma_offset = tvb_get_ntoh64(tvb, offset);
        offset += 8;
        rdma_seg_addr64 = tvb_get_ntoh64(tvb, offset);
        offset += 8;
        rdma_seg_len = tvb_get_ntoh64(tvb, offset);
        offset += 8;
    }

    col_append_fstr(pinfo->cinfo, COL_INFO,
            " Seg-Num=%d RDMA-Offset=%" G_GINT64_MODIFIER "u"
            " Seg-Addr=0x%016" G_GINT64_MODIFIER "x"
            " Seg-Len=%" G_GINT64_MODIFIER "u",
            rdma_seg_cnt, rdma_rdma_offset, rdma_seg_addr64, rdma_seg_len);

    if (tree) {
        offset = the_offset;
        mpi_rdma_tree = proto_tree_add_subtree(tree, tvb, 0, 0, ett_mpi_rdma,
                &ti, "BTL RDMA Header: ");

        if (0 == rdma_padding) {
            proto_tree_add_item(mpi_rdma_tree, hf_mpi_padding2, tvb,
                    offset, 2, byte_order);
            offset += 2;
        }

        proto_tree_add_item(mpi_rdma_tree, hf_mpi_seg_cnt, tvb,
                offset, 4, byte_order);
        offset += 4;
        proto_tree_add_item(mpi_rdma_tree, hf_mpi_dst_req32_1, tvb,
                offset, 4, byte_order);
        proto_tree_add_item(mpi_rdma_tree, hf_mpi_dst_req32_2, tvb,
                offset + 4, 4, byte_order);
        proto_tree_add_item(mpi_rdma_tree, hf_mpi_dst_req64, tvb,
                offset, 8, byte_order);
        offset += 8;
        proto_tree_add_item(mpi_rdma_tree, hf_mpi_src_des32_1, tvb,
                offset, 4, byte_order);
        proto_tree_add_item(mpi_rdma_tree, hf_mpi_src_des32_2, tvb,
                offset + 4, 4, byte_order);
        proto_tree_add_item(mpi_rdma_tree, hf_mpi_src_des64, tvb,
                offset, 8, byte_order);
        offset += 8;
        proto_tree_add_item(mpi_rdma_tree, hf_mpi_rdma_hdr_recv_req32_1, tvb,
                offset, 4, byte_order);
        proto_tree_add_item(mpi_rdma_tree, hf_mpi_rdma_hdr_recv_req32_2, tvb,
                offset + 4, 4, byte_order);
        proto_tree_add_item(mpi_rdma_tree, hf_mpi_rdma_hdr_recv_req64, tvb,
                offset, 8, byte_order);
        offset += 8;
        proto_tree_add_item(mpi_rdma_tree, hf_mpi_rdma_hdr_rdma_offset, tvb,
                offset, 8, byte_order);
        offset += 8;
        proto_tree_add_item(mpi_rdma_tree, hf_mpi_rdma_hdr_seg_addr32_1, tvb,
                offset, 4, byte_order);
        proto_tree_add_item(mpi_rdma_tree, hf_mpi_rdma_hdr_seg_addr32_2, tvb,
                offset + 4, 4, byte_order);
        proto_tree_add_item(mpi_rdma_tree, hf_mpi_rdma_hdr_seg_addr64, tvb,
                offset, 8, byte_order);
        offset += 8;
        proto_tree_add_item(mpi_rdma_tree, hf_mpi_rdma_hdr_seg_len, tvb,
                offset, 4, byte_order);
        offset += 4;

        proto_item_append_text(ti,
                "seg_cnt: %d "
                "rdma_offset: %" G_GINT64_MODIFIER "u"
                "(0x%016" G_GINT64_MODIFIER "x), "
                "seg_addr: 0x%016" G_GINT64_MODIFIER "x, "
                "seg_len: %" G_GINT64_MODIFIER "u",
                rdma_seg_cnt, rdma_rdma_offset, rdma_rdma_offset,
                rdma_seg_addr64, rdma_seg_len);
    }
    return offset;
}

static int
dissect_mpi_fin(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, guint the_offset)
{
    proto_item *ti = NULL;
    proto_tree *mpi_fin_tree = NULL;
    guint32 byte_order;
    guint offset;
    guint16 fin_padding;
    guint32 fin_fail;
    guint32 fin_des32_1;
    guint32 fin_des32_2;
    guint64 fin_des64;

    /* we need minimum 12 bytes for the minimum fin header */
    if (12 > tvb_reported_length(tvb) - the_offset) {
        return the_offset;
    }

    if (MPI_DEBUG)
        g_print("%d dissect_mpi_fin, reported_length: %d, offset: %d, tree: %s\n",
                pinfo->fd->num, tvb_reported_length(tvb), the_offset,
                tree ? "true":"false");

    offset = the_offset;
    fin_padding = 1;

    if (pref_little_endian) {
        byte_order = ENC_LITTLE_ENDIAN;
        /* space for padding (2 bytes) + fail (4 bytes) + hdr_des (8 bytes)
         * or additional with bfo + 14 for match header (also with padding) */
        if (14 == tvb_reported_length(tvb) - offset ||
                28 == tvb_reported_length(tvb) - offset) {
            fin_padding = tvb_get_letohs(tvb, offset);
            offset += 2;
        }
        /* space for match header 12 bytes (14 with padding) + 12 fin header */
        if (26 == tvb_reported_length(tvb) - offset ||
                24 == tvb_reported_length(tvb) - offset) {
            offset = dissect_mpi_match(tvb, pinfo, tree, offset);
        }
        fin_fail = tvb_get_letohl(tvb, offset);
        offset += 4;
        fin_des32_1 = tvb_get_letohl(tvb, offset);
        fin_des32_2 = tvb_get_letohl(tvb, offset + 4);
        fin_des64 = tvb_get_letoh64(tvb, offset);
        offset += 8;
    } else {
        byte_order = ENC_BIG_ENDIAN;
        /* space for padding (2 bytes) + fail (4 bytes) + hdr_des (8 bytes)
         * or additional with bfo + 14 for match header (also with padding) */
        if (14 == tvb_reported_length(tvb) - offset ||
                28 == tvb_reported_length(tvb) - offset) {
            fin_padding = tvb_get_ntohs(tvb, offset);
            offset += 2;
        }
        /* space for match header 12 bytes (14 with padding) + 12 fin header */
        if (26 == tvb_reported_length(tvb) - offset ||
                24 == tvb_reported_length(tvb) - offset) {
            offset = dissect_mpi_match(tvb, pinfo, tree, offset);
        }
        fin_fail = tvb_get_ntohl(tvb, offset);
        offset += 4;
        fin_des32_1 = tvb_get_ntohl(tvb, offset);
        fin_des32_2 = tvb_get_ntohl(tvb, offset + 4);
        fin_des64 = tvb_get_ntoh64(tvb, offset);
        offset += 8;
    }

    col_append_fstr(pinfo->cinfo, COL_INFO,
            " Failed=%d Descriptor=0x%016" G_GINT64_MODIFIER "x",
            fin_fail, fin_des64);

    if (tree) {
        offset = the_offset;
        mpi_fin_tree = proto_tree_add_subtree(tree, tvb, 0, 0, ett_mpi_fin,
                &ti, "BTL Finish Header: ");

        if (0 == fin_padding) {
            proto_tree_add_item(mpi_fin_tree, hf_mpi_padding2, tvb,
                    offset, 2, byte_order);
            offset += 2;
        }

        proto_tree_add_item(mpi_fin_tree, hf_mpi_fin_hdr_fail, tvb,
                offset, 4, byte_order);
        offset += 4;
        proto_tree_add_item(mpi_fin_tree, hf_mpi_fin_hdr_des32_1, tvb,
                offset, 4, byte_order);
        proto_tree_add_item(mpi_fin_tree, hf_mpi_fin_hdr_des32_2, tvb,
                offset + 4, 4, byte_order);
        proto_tree_add_item(mpi_fin_tree, hf_mpi_fin_hdr_des64, tvb,
                offset, 8, byte_order);
        offset += 8;

        proto_item_append_text(ti,
                "failed: %d descriptor_1: 0x%08x, descriptor_2: 0x%08x, "
                "descriptor: 0x%016" G_GINT64_MODIFIER "x, ",
                fin_fail, fin_des32_1, fin_des32_2, fin_des64);
    }
    return offset;
}

static int
dissect_mpi_rndvrestartnotify(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, guint the_offset)
{
    proto_item *ti = NULL;
    proto_tree *mpi_rndvrestartnotify_tree = NULL;
    guint32 byte_order;
    guint offset;
    guint64 rndvrestartnotify_padding;
    guint8 rndvrestartnotify_restartseq;
    guint64 rndvrestartnotify_src_req64;
    guint64 rndvrestartnotify_dst_req64;
    guint32 rndvrestartnotify_dst_rank;
    guint32 rndvrestartnotify_jobid;
    guint32 rndvrestartnotify_vpid;

    /* too small for the minimum match header (12 bytes)
     * + restart header (29 bytes)*/
    if (41 > tvb_reported_length(tvb) - the_offset) {
        return the_offset;
    }

    if (MPI_DEBUG)
        g_print("%d dissect_mpi_rndvrestartnotify, reported_length: %d, "
                "offset: %d, tree: %s\n",
                pinfo->fd->num, tvb_reported_length(tvb), the_offset,
                tree ? "true":"false");

    the_offset = dissect_mpi_match(tvb, pinfo, tree, the_offset);

    offset = the_offset;
    rndvrestartnotify_padding = 1;

    rndvrestartnotify_restartseq = tvb_get_guint8(tvb, offset);
    offset += 1;

    if (pref_little_endian) {
        byte_order = ENC_LITTLE_ENDIAN;
        if (31 <= tvb_reported_length(tvb) - offset) {
            rndvrestartnotify_padding = tvb_get_letoh48(tvb, offset);
            if (0 == rndvrestartnotify_padding) {
                offset += 3;
            }
        }
        rndvrestartnotify_src_req64 = tvb_get_letoh64(tvb, offset);
        offset += 8;
        rndvrestartnotify_dst_req64 = tvb_get_letoh64(tvb, offset);
        offset += 8;
        rndvrestartnotify_dst_rank = tvb_get_letohl(tvb, offset);
        offset += 4;
        rndvrestartnotify_jobid = tvb_get_letohl(tvb, offset);
        offset += 4;
        rndvrestartnotify_vpid = tvb_get_letohl(tvb, offset);
        offset += 4;
    } else {
        byte_order = ENC_BIG_ENDIAN;
        if (31 <= tvb_reported_length(tvb) - offset) {
            rndvrestartnotify_padding = tvb_get_ntoh48(tvb, offset);
            if (0 == rndvrestartnotify_padding) {
                offset += 3;
            }
        }
        rndvrestartnotify_src_req64 = tvb_get_ntoh64(tvb, offset);
        offset += 8;
        rndvrestartnotify_dst_req64 = tvb_get_ntoh64(tvb, offset);
        offset += 8;
        rndvrestartnotify_dst_rank = tvb_get_ntohl(tvb, offset);
        offset += 4;
        rndvrestartnotify_jobid = tvb_get_ntohl(tvb, offset);
        offset += 4;
        rndvrestartnotify_vpid = tvb_get_ntohl(tvb, offset);
        offset += 4;
    }

    col_append_fstr(pinfo->cinfo, COL_INFO,
            " Restart-Seq=%d Dst-Vpid=%d Jobid=%d Vpid=%d"
            " Src-Req=0x%016" G_GINT64_MODIFIER "x"
            " Dst-Req=0x%016" G_GINT64_MODIFIER"x",
            rndvrestartnotify_restartseq, rndvrestartnotify_dst_rank,
            rndvrestartnotify_jobid, rndvrestartnotify_vpid,
            rndvrestartnotify_src_req64, rndvrestartnotify_dst_req64);

    if (tree) {
        offset = the_offset;
        mpi_rndvrestartnotify_tree = proto_tree_add_subtree(tree, tvb, 0, 0,
                ett_mpi_rndvrestartnotify, &ti,
                "BTL Restart Rendezvous Header: ");

        if (0 == rndvrestartnotify_padding) {
            proto_tree_add_item(mpi_rndvrestartnotify_tree,
                    hf_mpi_padding3,
                    tvb, offset, 3, byte_order);
            offset += 3;
        }

        proto_tree_add_item(mpi_rndvrestartnotify_tree, hf_mpi_src_req32_1, tvb,
                offset, 4, byte_order);
        proto_tree_add_item(mpi_rndvrestartnotify_tree, hf_mpi_src_req32_2, tvb,
                offset + 4, 4, byte_order);
        proto_tree_add_item(mpi_rndvrestartnotify_tree, hf_mpi_src_req64, tvb,
                offset, 8, byte_order);
        offset += 8;
        proto_tree_add_item(mpi_rndvrestartnotify_tree, hf_mpi_dst_req32_1, tvb,
                offset, 4, byte_order);
        proto_tree_add_item(mpi_rndvrestartnotify_tree, hf_mpi_dst_req32_2, tvb,
                offset + 4, 4, byte_order);
        proto_tree_add_item(mpi_rndvrestartnotify_tree, hf_mpi_dst_req64, tvb,
                offset, 8, byte_order);
        offset += 8;
        proto_tree_add_item(mpi_rndvrestartnotify_tree, hf_mpi_dst_vpid, tvb,
                offset, 4, byte_order);
        offset += 4;
        proto_tree_add_item(mpi_rndvrestartnotify_tree, hf_mpi_jobid, tvb,
                offset, 4, byte_order);
        offset += 4;
        proto_tree_add_item(mpi_rndvrestartnotify_tree, hf_mpi_vpid, tvb,
                offset, 4, byte_order);
        offset += 4;

        proto_item_append_text(ti,
                "restartseq: %d, dst_vpid: %d, jobid: %d, vpid: %d"
                "src_req: 0x%016" G_GINT64_MODIFIER "x, "
                "dst_req: 0x%016" G_GINT64_MODIFIER "x, ",
                rndvrestartnotify_restartseq, rndvrestartnotify_dst_rank,
                rndvrestartnotify_jobid, rndvrestartnotify_vpid,
                rndvrestartnotify_src_req64, rndvrestartnotify_dst_req64);
    }
    return offset;
}
/* "tvb" containing the raw data, but not any protocol headers above it
 * "pinfo" Packet info
 * "tree" if the pointer is NULL, then we are being asked for a summary,
 *        else for details of the packet
 */

/* Code to actually dissect the packets */
static int
dissect_mpi(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data _U_)
{
    /* Set up structures needed to add the protocol subtree and manage it */
    proto_item *ti = NULL;
    proto_tree *mpi_tree = NULL;
    proto_tree *mpi_base_tree = NULL;
    proto_tree *mpi_common_tree = NULL;
    proto_tree *mpi_common_flags_tree = NULL;
    /* Other misc. local variables. */
    guint offset = 0;
    guint32 byte_order;
    guint8 base_base;
    guint8 base_type;
    guint16 base_count;
    guint32 base_size;
    guint8 common_type;
    guint8 common_flags;

    /* Check that the packet is long enough for it to belong to us. */
    if (MPI_MIN_LENGTH > tvb_reported_length(tvb)) {
        return 0;
    }

    if (MPI_DEBUG)
        g_print("%d dissect_mpi, reported_length: %d, tree: %s\n",
                pinfo->fd->num, tvb_reported_length(tvb),
                tree ? "true":"false");

    /* oob packet: src and dst port in range of 2^15 and 2^16 -1 */
    if (32768 <= pinfo->srcport && MAX_TCP_PORT >= pinfo->srcport &&
            32768 <= pinfo->destport && MAX_TCP_PORT >= pinfo->destport) {
        return dissect_mpi_oob(tvb, pinfo, tree, offset);
    }

    /* sync packet: length == 8 */
    if (8 == tvb_captured_length(tvb)) {
        return dissect_mpi_sync(tvb, pinfo, tree, offset);
    }

    base_base = tvb_get_guint8(tvb, 0);

    if (10 > tvb_reported_length(tvb) || 65 > base_base || 77 < base_base) {
        return 0;
    }

    /* set protocol name */
    col_set_str(pinfo->cinfo, COL_PROTOCOL, "MPI");
    /* Clear out stuff in the info column */
    col_clear(pinfo->cinfo,COL_INFO);

    /* \xe2\x86\x92  UTF8_RIGHTWARDS_ARROW */
    col_add_fstr(pinfo->cinfo, COL_INFO, "%d\xe2\x86\x92%d [%s]",
            pinfo->srcport, pinfo->destport,
            val_to_str(base_base, packetbasenames, "Unknown (0x%02x) o_O"));

    if (tree) {
        ti = proto_tree_add_item(tree, proto_mpi, tvb, 0, -1, ENC_NA);
        mpi_tree = proto_item_add_subtree(ti, ett_mpi);

        base_type = tvb_get_guint8(tvb, 1);
        common_type = tvb_get_guint8(tvb, 8);
        common_flags = tvb_get_guint8(tvb, 9);
        if (pref_little_endian) {
            byte_order = ENC_LITTLE_ENDIAN;
            base_count = tvb_get_letohs(tvb, 2);
            base_size = tvb_get_letohl(tvb, 4);
        } else {
            byte_order = ENC_BIG_ENDIAN;
            base_count = tvb_get_ntohs(tvb, 2);
            base_size = tvb_get_ntohl(tvb, 4);
        }

        /* base header */
        mpi_base_tree = proto_tree_add_subtree(mpi_tree, tvb, 0, 0, ett_mpi_base,
                &ti, "BTL Base Header: ");
        proto_tree_add_item(mpi_base_tree, hf_mpi_base_hdr_base, tvb,
                offset, 1, byte_order);
        offset += 1;
        proto_tree_add_item(mpi_base_tree, hf_mpi_base_hdr_type, tvb,
                offset, 1, byte_order);
        offset += 1;
        proto_tree_add_item(mpi_base_tree, hf_mpi_base_hdr_count, tvb,
                offset, 2, byte_order);
        offset += 2;
        proto_tree_add_item(mpi_base_tree, hf_mpi_base_hdr_size, tvb,
                offset, 4, byte_order);
        offset += 4;
        proto_item_append_text(ti, "base: %s, type: %s, count: %d, size: %d",
                val_to_str(base_base, packetbasenames, "Unknown (0x%02x)"),
                val_to_str(base_type, packettypenames, "Unknown (0x%02x)"),
                base_count, base_size);

        /* common header */
        mpi_common_tree = proto_tree_add_subtree(mpi_tree, tvb, 0, 0,
                ett_mpi_common, &ti, "BTL Common Header: ");
        proto_tree_add_item(mpi_common_tree, hf_mpi_common_hdr_type, tvb,
                offset, 1, byte_order);
        offset += 1;
        /* add a flag tree */
        mpi_common_flags_tree = proto_item_add_subtree(ti, ett_mpi_common_flags);
        proto_tree_add_bitmask(mpi_common_flags_tree, tvb, offset,
                hf_mpi_common_hdr_flags, ett_mpi_common_flags,
                common_hdr_flags, byte_order);
        offset +=1;
        proto_item_append_text(ti, "type: %s, flags: 0x%02x",
                val_to_str(common_type, packetbasenames, "Unknown (0x%02x)"),
                common_flags);
    } else {
        offset = 10;
    }

    switch(base_base) {
        case MPI_PML_OB1_HDR_TYPE_MATCH:
            offset = dissect_mpi_match(tvb, pinfo, mpi_tree, offset);
            break;
        case MPI_PML_BFO_HDR_TYPE_RNDV:
            offset = dissect_mpi_rndv(tvb, pinfo, mpi_tree, offset);
            break;
        case MPI_PML_OB1_HDR_TYPE_RGET: /* not tested yet !!!*/
            offset = dissect_mpi_rget(tvb, pinfo, mpi_tree, offset);
            break;
        case MPI_PML_OB1_HDR_TYPE_FRAG: /* not tested yet !!!*/
            offset = dissect_mpi_frag(tvb, pinfo, mpi_tree, offset);
            break;
        case MPI_PML_OB1_HDR_TYPE_ACK: /* not tested yet !!!*/
            offset = dissect_mpi_ack(tvb, pinfo, mpi_tree, offset);
            break;
        case MPI_PML_OB1_HDR_TYPE_PUT: /* tested, but with curious extra data.. */
            offset = dissect_mpi_rdma(tvb, pinfo, mpi_tree, offset);
            break;
        case MPI_PML_OB1_HDR_TYPE_FIN:
            offset = dissect_mpi_fin(tvb, pinfo, mpi_tree, offset);
            break;
        case MPI_PML_BFO_HDR_TYPE_RNDVRESTARTNOTIFY:
            offset = dissect_mpi_rndvrestartnotify(tvb, pinfo, mpi_tree, offset);
            break;
        case MPI_PML_OB1_HDR_TYPE_NACK:
        case MPI_PML_OB1_HDR_TYPE_GET:
        case MPI_PML_BFO_HDR_TYPE_RNDVRESTARTACK:
        case MPI_PML_BFO_HDR_TYPE_RNDVRESTARTNACK:
        case MPI_PML_BFO_HDR_TYPE_RECVERRNOTIFY:
            /* Single-byte accessor */
            col_append_str(pinfo->cinfo, COL_INFO,
                    " not implemented yet :-("
                    " please send this capture file to the dissector author!");
            break;
        default:
            col_append_str(pinfo->cinfo, COL_INFO, " something goes wrong!");
    }

    if (tvb_captured_length(tvb) > offset) {
        proto_tree_add_item(mpi_tree, hf_mpi_oob_data, tvb,
                offset, tvb_captured_length(tvb) - offset, ENC_BIG_ENDIAN);
        offset = tvb_captured_length(tvb);
    }
    /* push the payload to the data section */
    /*if (offset < (guint)tvb_captured_length(tvb)) {
        tvbuff_t *next_tvb;
        next_tvb = tvb_new_subset_remaining(tvb, offset);
        call_dissector(data_handle, next_tvb, pinfo, tree);
    }*/
    /* Continue adding tree items to process the packet here... */

    /* If this protocol has a sub-dissector call it here, see section 1.8 of
     * README.dissector for more information. */

    /* Return the amount of data this dissector was able to dissect (which may
     * or may not be the total captured packet as we return here). */
    return offset;
}

/* Register the protocol with Wireshark.
 *
 * This format is require because a script is used to build the C function that
 * calls all the protocol registration.
 */
void
proto_register_mpi(void)
{
    module_t        *mpi_module;

    /* Setup list of header fields  See Section 1.5 of README.dissector for
     * details. */
    static hf_register_info hf[] = {
        { &hf_mpi_jobid,    /* The index for this node */
            { "Jobid",      /* The label for this item */
              "mpi.jobid",  /* This is the filter string.
                               It enables us to type constructs
                               such as foo.type=1 into the filter box. */
              FT_UINT32,    /* This specifies this item is an 32bit unsigned integer. */
              BASE_DEC,     /* BASE_DEC - Tor an integer type,
                               this tells it to be printed as a decimal number.
                               It could be hexdecimal (BASE_HEX) or octal
                               (BASE_OCT) if that made more sense, or sth. else */
              NULL,         /* replace the value with a string,
                               use the VALS macro and a value_string array*/
              0x0,          /* flag value */
              NULL,         /* expert info */
              HFILL         /* The HFILL macro at the end of the struct
                               will set reasonable default values
                               for internally used fields. */
            }
        },
        { &hf_mpi_vpid,
            { "Vpid (Rank)", "mpi.vpid",
                FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL }
        },
        { &hf_mpi_dst_vpid,
            { "Destination Vpid (Rank)", "mpi.dst_vpid",
                FT_INT32, BASE_DEC, NULL, 0x0, NULL, HFILL }
        },
        { &hf_mpi_oob_num_vals,
            { "Number of Values", "mpi.num_vals",
                FT_INT32, BASE_DEC, NULL, 0x0, NULL, HFILL }
        },
        { &hf_mpi_oob_len,
            { "Length", "mpi.len",
                FT_INT32, BASE_DEC, NULL, 0x0, NULL, HFILL }
        },
        { &hf_mpi_oob_odles_data_type,
            { "ORTE Daemon", "mpi.orte_daemon",
                FT_UINT8, BASE_DEC, VALS(odlesdatatypenames), 0x0, NULL, HFILL }
        },
        { &hf_mpi_oob_opal_data_type,
            { "OPAL Datatype", "mpi.opal_datatype",
                FT_UINT8, BASE_DEC, VALS(opaldatatypenames), 0x0, NULL, HFILL }
        },
        { &hf_mpi_oob_orte_data_type,
            { "ORTE Datatype", "mpi.orte_datatype",
                FT_UINT8, BASE_DEC, VALS(ortedatatypenames), 0x0, NULL, HFILL }
        },
        { &hf_mpi_padding2,
            { "Padding (2 Bytes)", "mpi.padding",
                FT_UINT16, BASE_DEC, VALS(paddingnames), 0x0, NULL, HFILL }
        },
        { &hf_mpi_padding3,
            { "Padding (3 Bytes)", "mpi.padding",
                FT_UINT64, BASE_DEC, VALS(paddingnames), 0x0, NULL, HFILL }
        },
        { &hf_mpi_padding4,
            { "Padding (4 Bytes)", "mpi.padding",
                FT_UINT32, BASE_DEC, VALS(paddingnames), 0x0, NULL, HFILL }
        },
        { &hf_mpi_padding6,
            { "Padding (6 Bytes)", "mpi.padding",
                FT_UINT64, BASE_DEC, VALS(paddingnames), 0x0, NULL, HFILL }
        },
        { &hf_mpi_base_hdr_base,
            { "Base", "mpi.base",
                FT_UINT8, BASE_DEC, VALS(packetbasenames), 0x0, NULL, HFILL }
        },
        { &hf_mpi_base_hdr_type,
            { "Type", "mpi.hdr_type",
                FT_UINT8, BASE_DEC, VALS(packettypenames), 0x0, NULL, HFILL }
        },
        { &hf_mpi_base_hdr_count,
            { "Count", "mpi.count",
                FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL }
        },
        { &hf_mpi_base_hdr_size,
            { "Size", "mpi.size",
                FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL }
        },
        { &hf_mpi_common_hdr_type,
            { "Type", "mpi.type",
                FT_UINT8, BASE_DEC, VALS(packetbasenames), 0x0, NULL, HFILL }
        },
        { &hf_mpi_common_hdr_flags,
            { "Fragment Flags", "mpi.flags",
                FT_UINT8, BASE_HEX, NULL, 0x0, NULL, HFILL }
        },
        { &hf_mpi_common_hdr_flags_ack,
            { "Acknowledgement required", "mpi.flags.ack",
                FT_UINT8, BASE_HEX, NULL, 0x01, NULL, HFILL }
        },
        { &hf_mpi_common_hdr_flags_nbo,
            { "Header in Network-Byte-Order", "mpi.flags.nbo",
                FT_UINT8, BASE_HEX, NULL, 0x02, NULL, HFILL }
        },
        { &hf_mpi_common_hdr_flags_pin,
            { "User buffer pinned", "mpi.flags.pin",
                FT_UINT8, BASE_HEX, NULL, 0x04, NULL, HFILL }
        },
        { &hf_mpi_common_hdr_flags_contig,
            { "User buffer contiguous", "mpi.flags.contig",
                FT_UINT8, BASE_HEX, NULL, 0x08, NULL, HFILL }
        },
        { &hf_mpi_common_hdr_flags_nordma,
            { "Rest will be send by copy-in-out", "mpi.flags.nordma",
                FT_UINT8, BASE_HEX, NULL, 0x10, NULL, HFILL }
        },
        { &hf_mpi_common_hdr_flags_restart,
            { "Restart RNDV because of error", "mpi.flags.restart",
                FT_UINT8, BASE_HEX, NULL, 0x20, NULL, HFILL }
        },
        { &hf_mpi_match_hdr_ctx,
            { "Communicator Index", "mpi.ctx",
                FT_UINT16, BASE_DEC, VALS(communicatornames), 0x0, NULL, HFILL }
        },
        { &hf_mpi_match_hdr_src,
            { "Source Vpid (Rank)", "mpi.src",
                FT_INT32, BASE_DEC, NULL, 0x0, NULL, HFILL }
        },
        { &hf_mpi_match_hdr_tag,
            { "Message Tag", "mpi.tag",
                FT_INT32, BASE_DEC, VALS(colltagnames), 0x0, NULL, HFILL }
        },
        { &hf_mpi_match_hdr_seq,
            { "Sequence Number", "mpi.seq",
                FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL }
        },
        { &hf_mpi_rndv_hdr_len,
            { "Message Length", "mpi.msg_len",
                FT_UINT64, BASE_DEC, NULL, 0x0, NULL, HFILL }
        },
        { &hf_mpi_rndv_hdr_restartseq,
            { "Restart Sequence", "mpi.restartseq",
                FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL }
        },
        { &hf_mpi_src_req32_1,
            { "Source Request Pointer (4 Bytes, part 1)", "mpi.src_req_1",
                FT_UINT32, BASE_DEC_HEX, NULL, 0x0, NULL, HFILL }
        },
        { &hf_mpi_src_req32_2,
            { "Source Request Pointer (4 Bytes, part 2)", "mpi.src_req_2",
                FT_UINT32, BASE_DEC_HEX, NULL, 0x0, NULL, HFILL }
        },
        { &hf_mpi_src_req64,
            { "Source Request Pointer (8 Bytes)", "mpi.src_req",
                FT_UINT64, BASE_DEC_HEX, NULL, 0x0, NULL, HFILL }
        },
        { &hf_mpi_dst_req32_1,
            { "Destination Request Pointer (4 Bytes, part 1)", "mpi.dst_req_1",
                FT_UINT32, BASE_DEC_HEX, NULL, 0x0, NULL, HFILL }
        },
        { &hf_mpi_dst_req32_2,
            { "Destination Request Pointer (4 Bytes, part 2)", "mpi.dst_req_2",
                FT_UINT32, BASE_DEC_HEX, NULL, 0x0, NULL, HFILL }
        },
        { &hf_mpi_dst_req64,
            { "Destination Request Pointer (8 Bytes)", "mpi.dst_req",
                FT_UINT64, BASE_DEC_HEX, NULL, 0x0, NULL, HFILL }
        },
        { &hf_mpi_seg_cnt,
            { "Segments Count", "mpi.seg_cnt",
                FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL }
        },
        { &hf_mpi_src_des32_1,
            { "Source Descriptor (4 Bytes, part 1)", "mpi.src_des_1",
                FT_UINT32, BASE_DEC_HEX, NULL, 0x0, NULL, HFILL }
        },
        { &hf_mpi_src_des32_2,
            { "Source Descriptor (4 Bytes, part 2)", "mpi.src_des_1",
                FT_UINT32, BASE_DEC_HEX, NULL, 0x0, NULL, HFILL }
        },
        { &hf_mpi_src_des64,
            { "Source Descriptor (8 Bytes)", "mpi.src_des",
                FT_UINT64, BASE_DEC_HEX, NULL, 0x0, NULL, HFILL }
        },
        { &hf_mpi_frag_hdr_frag_offset,
            { "Offset into Message", "mpi.frag_offset",
                FT_UINT64, BASE_DEC, NULL, 0x0, NULL, HFILL }
        },
        { &hf_mpi_ack_hdr_send_offset,
            { "Staring point of copy in/out", "mpi.send_offset",
                FT_UINT64, BASE_DEC, NULL, 0x0, NULL, HFILL }
        },
        { &hf_mpi_rdma_hdr_recv_req32_1,
            { "Receive Request Pointer (4 Bytes, part 1)", "mpi.recv_req_1",
                FT_UINT32, BASE_DEC_HEX, NULL, 0x0, NULL, HFILL }
        },
        { &hf_mpi_rdma_hdr_recv_req32_2,
            { "Receive Request Pointer (4 Bytes, part 2)", "mpi.recv_req_2",
                FT_UINT32, BASE_DEC_HEX, NULL, 0x0, NULL, HFILL }
        },
        { &hf_mpi_rdma_hdr_recv_req64,
            { "Receive Request Pointer (8 Bytes)", "mpi.recv_req",
                FT_UINT64, BASE_DEC_HEX, NULL, 0x0, NULL, HFILL }
        },
        { &hf_mpi_rdma_hdr_rdma_offset,
            { "Current offset into user buffer", "mpi.rdma_offset",
                FT_UINT64, BASE_DEC, NULL, 0x0, NULL, HFILL }
        },
        { &hf_mpi_rdma_hdr_seg_addr32_1,
            { "Segment Address Pointer (4 Bytes, part 1)", "mpi.seg_addr_1",
                FT_UINT32, BASE_DEC_HEX, NULL, 0x0, NULL, HFILL }
        },
        { &hf_mpi_rdma_hdr_seg_addr32_2,
            { "Segment Address Pointer (4 Bytes, part 1)", "mpi.seg_addr_2",
                FT_UINT32, BASE_DEC_HEX, NULL, 0x0, NULL, HFILL }
        },
        { &hf_mpi_rdma_hdr_seg_addr64,
            { "Segment Address Pointer (8 Bytes)", "mpi.seg_addr",
                FT_UINT64, BASE_DEC_HEX, NULL, 0x0, NULL, HFILL }
        },
        { &hf_mpi_rdma_hdr_seg_len,
            { "Segment Length", "mpi.seg_len",
                FT_UINT64, BASE_DEC, NULL, 0x0, NULL, HFILL }
        },
        { &hf_mpi_fin_hdr_fail,
            { "RDMA operation failed", "mpi.fail",
                FT_UINT32, BASE_DEC_HEX, NULL, 0x0, NULL, HFILL }
        },
        { &hf_mpi_fin_hdr_des32_1,
            { "Completed Descriptor Pointer (4 Bytes, part 1)", "mpi.des_1",
                FT_UINT32, BASE_DEC_HEX, NULL, 0x0, NULL, HFILL }
        },
        { &hf_mpi_fin_hdr_des32_2,
            { "Completed Descriptor Pointer (4 Bytes, part 2)", "mpi.des_2",
                FT_UINT32, BASE_DEC_HEX, NULL, 0x0, NULL, HFILL }
        },
        { &hf_mpi_fin_hdr_des64,
            { "Completed Descriptor Pointer (8 Bytes)", "mpi.des",
                FT_UINT64, BASE_DEC_HEX, NULL, 0x0, NULL, HFILL }
        },
        { &hf_mpi_oob_hdr_jobid_origin,
            { "Origin Jobid", "mpi.jobid_origin",
                FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL }
        },
        { &hf_mpi_oob_hdr_vpid_origin,
            { "Origin Vpid", "mpi.vpid_origin",
                FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL }
        },
        { &hf_mpi_oob_hdr_jobid_dst,
            { "Destination Jobid", "mpi.jobid_dst",
                FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL }
        },
        { &hf_mpi_oob_hdr_vpid_dst,
            { "Destination Vpid", "mpi.vpid_dst",
                FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL }
        },
        { &hf_mpi_oob_hdr_msg_type,
            { "Message Type", "mpi.msg_type",
                FT_UINT32, BASE_DEC, VALS(msgtypenames), 0x0, NULL, HFILL }
        },
        { &hf_mpi_oob_hdr_rml_tag,
            { "RML Tag", "mpi.rml_tag",
                FT_UINT32, BASE_DEC, VALS(rmltagnames), 0x0, NULL, HFILL }
        },
        { &hf_mpi_oob_hdr_nbytes,
            { "Message length", "mpi.len",
                FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL }
        },
        { &hf_mpi_oob_version,
            { "MPI Version", "mpi.version",
                FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL }
        },
        { &hf_mpi_oob_uri,
            { "RML URI", "mpi.uri",
                FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL }
        },
        { &hf_mpi_oob_nodename,
            { "Nodename", "mpi.nodename",
                FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL }
        },
        { &hf_mpi_oob_credential,
            { "Credential", "mpi.cred",
                FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL }
        },
        { &hf_mpi_oob_iof_type,
            { "IOF Type", "mpi.iof_type",
                FT_UINT8, BASE_DEC, VALS(ioftypenames), 0x0, NULL, HFILL }
        },
        { &hf_mpi_oob_data,
            { "Message Data", "mpi.data",
                FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL }
        },
        { &hf_mpi_response_in,
            { "Response In", "mpi.sync.response_in",
                FT_FRAMENUM, BASE_NONE, NULL, 0x0, NULL, HFILL }
        },
        { &hf_mpi_response_to,
            { "Response To", "mpi.sync.response_to",
                FT_FRAMENUM, BASE_NONE, NULL, 0x0, NULL, HFILL }
        },
        { &hf_mpi_time,
            { "Time", "mpi.sync.time",
                FT_RELATIVE_TIME, BASE_NONE, NULL, 0x0, NULL, HFILL }
        }
    };

    /* Setup protocol subtree array */
    static gint *ett[] = {
        &ett_mpi,
        &ett_mpi_oob_hdr,
        &ett_mpi_oob_msg,
        &ett_mpi_base,
        &ett_mpi_common,
        &ett_mpi_common_flags,
        &ett_mpi_match,
        &ett_mpi_rndv,
        &ett_mpi_rget,
        &ett_mpi_frag,
        &ett_mpi_ack,
        &ett_mpi_rdma,
        &ett_mpi_fin,
        &ett_mpi_rndvrestartnotify
    };

    if (MPI_DEBUG)
        g_print("proto_register_mpi\n");

    /* Register the protocol name and description */
    proto_mpi = proto_register_protocol(
            "Message Passing Interface Protocol", /* PROTONAME */
            "MPI", /* PROTOSHORTNAME */
            "mpi" /* PROTOABBREV */
            );

    /* Required function calls to register the header fields and subtrees */
    proto_register_field_array(proto_mpi, hf, array_length(hf));
    proto_register_subtree_array(ett, array_length(ett));

    /* register sub handler */
    /* mpi_sync_handler = new_create_dissector_handle(dissect_mpi_sync, proto_mpi); */

    /* Register a preferences module under the preferences subtree.
     * Only use this function instead of prefs_register_protocol (above) if you
     * want to group preferences of several protocols under one preferences
     * subtree.
     *
     * Argument subtree identifies grouping tree node name, several subnodes can
     * be specified using slash '/' (e.g. "OSI/X.500" - protocol preferences
     * will be accessible under Protocols->OSI->X.500-><PROTOSHORTNAME>
     * preferences node.
     */
    mpi_module = prefs_register_protocol_subtree("MPI/BTL",
            proto_mpi, proto_reg_handoff_mpi);

    /* Register a the byte order preference */
    prefs_register_bool_preference(mpi_module, "show_little",
            "Use little endian for the P2P traffic",
            "Dissect the BTL traffic with little endian byte order(default).",
            &pref_little_endian);

    /* Register an alternative port preference */
    range_convert_str(&global_mpi_tcp_port_range, DEFAULT_MPI_PORT_RANGE,
            MAX_TCP_PORT);
    prefs_register_range_preference(mpi_module, "tcp.ports", "MPI TCP Ports",
            "TCP ports to be decoded as Message Passing Interface protocol "
            "(default: " DEFAULT_MPI_PORT_RANGE ")",
            &global_mpi_tcp_port_range, MAX_TCP_PORT);
}

void
proto_reg_handoff_mpi(void)
{
    static gboolean initialized = FALSE;
    static dissector_handle_t mpi_handle;
    static range_t *mpi_tcp_port_range;

    if (MPI_DEBUG)
        g_print("proto_reg_handoff_mpi\n");

    if (!initialized) {
        mpi_handle = new_create_dissector_handle(dissect_mpi, proto_mpi);
        initialized = TRUE;

    } else {
        dissector_delete_uint_range("tcp.port", mpi_tcp_port_range, mpi_handle);
        g_free(mpi_tcp_port_range);
    }

    mpi_tcp_port_range = range_copy(global_mpi_tcp_port_range);
    dissector_add_uint_range("tcp.port", mpi_tcp_port_range, mpi_handle);

    /* data_handle = find_dissector("data"); */
}

/*
 * Editor modelines  -  https://www.wireshark.org/tools/modelines.html
 *
 * Local variables:
 * c-basic-offset: 4
 * tab-width: 4
 * indent-tabs-mode: nil
 * End:
 *
 * vi: set shiftwidth=4 tabstop=4 expandtab:
 * :indentSize=4:tabSize=4:noTabs=true:
 */
