#include "../lib/rosetta-helpers.h"
#include "../lib/bigint.h"
#include "../lib/cryptolib.h"

/* Rosetta Communication Interface.
 *
 * These 4 function pointers drive the basic functioning of ANY physical form of
 * communication, regardless of what happens at its lower levels of abstraction.
 *
 * They make up Rosetta's communication interface. This interface allows the
 * system to elegantly use the same functions for communicating regardless of
 * what the actual communication method being used at the moment is.
 *
 * It allows easily adding new available communication methods too.
 */
uint8_t(*init_communication)(void);
uint8_t(*transmit_payload)  (uint64_t socket_ix, uint8_t* buf, size_t send_siz);
ssize_t(*receive_payload)   (uint64_t socket_ix, uint8_t* buf, size_t max_siz);
uint8_t(*onboard_new_client)(void);

/* Select local interprocess communications with AF_UNIX sockets. Used by the
 * Rosetta Test Framework when simulatig human users via local OS processes.
 */
#define SELECT_LOCAL_UNIX_COMMUNICATIONS          \
    init_communication = ipc_init_communication;  \
    transmit_payload   = ipc_transmit_payload;    \
    receive_payload    = ipc_receive_payload;     \
    onboard_new_client = ipc_onboard_new_client;

/* Select internet communications over TCP. Used by the regular user-facing
 * version of the system.
 */
#define SELECT_TCP_INTERNET_COMMUNICATIONS        \
    init_communication = tcp_init_communication;  \
    transmit_payload   = tcp_transmit_payload;    \
    receive_payload    = tcp_receive_payload;     \
    onboard_new_client = tcp_onboard_new_client;

/* The structure that represents a Rosetta client connected to the server. */
struct connected_client
{
    char   user_id[SMALL_FIELD_LEN];
    u64    room_ix;
    u64    num_pending_msgs;
    u64    pending_msg_sizes[MAX_PEND_MSGS];
    u8*    pending_msgs[MAX_PEND_MSGS];
    u64    nonce_counter;
    bigint client_pubkey;
    bigint client_pubkey_mont;
    bigint shared_secret;
};

/* The structure that represents a Rosetta chat room. */
struct chatroom
{
    u64 num_people;
    u64 owner_ix;
    u64 room_id;
};

/* Memory region for short-term cryptographic artifacts for a login handshake */
u8* temp_handshake_buf = NULL;
u8  temp_handshake_memory_region_isLocked = 0;

/* Login handshake is a two-transmission process, so keep track of whether we're
 * in the middle of it currently or not.
 */
u8 login_not_finished = 0;

/* Bitmasks telling the server which client and room slots are currently free.
 *
 * Begin populating room slots and user slots at index [1]. Reserve index [0]
 * for meaning that a user is not in any room at all.
 */
u64 users_status_bitmask    = 0;
u64 rooms_status_bitmask    = 0;
u64 room_owner_left_bitmask = 0;

/* Keep track of the smallest user and room indices currently available. */
u64 curr_free_user_ix = 1;
u64 next_free_room_ix = 1;

u8 server_privkey[PRIVKEY_LEN];
pthread_mutex_t mutex;

/* Array of descriptors for clients and chat rooms. */
struct connected_client clients[MAX_CLIENTS];
struct chatroom rooms[MAX_CHATROOMS];

/* Create thread_id's for every connected client's request processing thread. */
pthread_t client_thread_ids[MAX_CLIENTS];

bigint* M;  /* Diffie-Hellman prime modulus M.                     */
bigint* Q;  /* Diffie-Hellman prime order, exactly dividing (M-1). */
bigint* G;  /* Diffie-Hellman generator G.                         */
bigint* Gm; /* Montgomery Form of G.                               */

bigint* server_pubkey_bigint;
bigint  server_privkey_bigint;

#include "server-communications.h"
#include "server-packet-functions.h"
#include "server-primary-functions.h"

/* Takes a single command-line argument:
 *
 * 0 for user-facing internet communications over standard TCP Linux sockets.
 *
 * 1 for local interprocess communications over AF_UNIX sockets, used by the
 *   Rosetta Test Framework when simulating human users via local OS processes.
 */
int main(int argc, char* argv[])
{
    u8  ret = 0;
    u32 status = 0;
    uint8_t thread_func_arg_buf[sizeof(curr_free_user_ix)];
    int arg1;

    if(argc != 2)
    {
        printf("[ERR] Server: Needs 1 cmd line arg: 0 = regular, 1 = RTF.\n");
        exit(1);
    }

    arg1 = atoi(argv[1]);

    /* Set Rosetta Communication Interface to a concrete communication method */

    /* Server started for the Rosetta Test Framework, use AF_UNIX sockets. */
    if(arg1 == 1) { SELECT_LOCAL_UNIX_COMMUNICATIONS }

    /* Server started for real user-facing operation, use AF_INET sockets. */
    else if(arg1 == 0) { SELECT_TCP_INTERNET_COMMUNICATIONS }

    else
    {
        printf("[ERR] Server: Pass 0 for user-facing, 1 for Test Framework.\n");
        exit(1);
    }

    /* Server initialization. */
    status = self_init();

    if(status)
    {
        printf("\n[ERR] Server: Could not complete self initialization!\n\n");
        exit(1);
    }
    printf("\n\n[OK]  Server: SUCCESS - Finished self initializing!\n\n");

    while(1)
    {
        printf("\n[OK] Server: SET curr_free_user_ix %lu\n", curr_free_user_ix);

        /* Block here until a newly seen client wants to log in to Rosetta. */
        ret = onboard_new_client();

        /* Unblocked and continues here. A login handshake has begun. */
        login_not_finished = 1;

        if(ret)
        {
            printf("[ERR] Server: accepting a newly seen client failed!\n");
            login_not_finished = 0;
            continue;
        }

        /**********************************************************************/

        /* Fill in arguments for the thread function for this user's thread. */
        memcpy(thread_func_arg_buf, &curr_free_user_ix,
               sizeof(curr_free_user_ix));

        pthread_mutex_lock(&mutex);

        pthread_create(&(client_thread_ids[curr_free_user_ix]), NULL,
                       start_new_client_thread, (void*)thread_func_arg_buf);

        pthread_detach(client_thread_ids[curr_free_user_ix]);
        ++curr_free_user_ix;

        /* Find the next available connected client descriptor index. */
        while(curr_free_user_ix < MAX_CLIENTS)
        {
            if(!(users_status_bitmask & (1ULL<<(63ULL - curr_free_user_ix))))
                break;

            ++curr_free_user_ix;
        }
        pthread_mutex_unlock(&mutex);
    }
    return 0;
}
