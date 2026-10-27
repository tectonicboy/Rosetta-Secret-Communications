#include <signal.h>

u8 check_pubkey_exists(u8* pubkey_buf, u64 pubkey_siz)
{
    if(pubkey_siz < 300)
    {
        printf("[ERR] Server: Passed a small PubKey Size: %lu\n", pubkey_siz);
        return 1;
    }

    /* Client slot is taken, client sizes match, public keys match. */
    for(u64 i = 0; i < MAX_CLIENTS; ++i)
    {
        if(   (users_status_bitmask & (1ULL << (63ULL - i)))
           && (PUBKEY_LEN == pubkey_siz)
           && (memcmp(pubkey_buf, (clients[i].client_pubkey).bits, pubkey_siz)
               == 0))
        {
            printf("\n[ERR] Server: PubKey already exists for user[%lu]\n", i);
            return 10;
        }
    }
    return 0;
}

/* The server has received information or a essage that must be relayed to a
 * user, such as the owner of their chatroom having closed the room, or a guest
 * having left/joined the chat room.
 *
 * Add this to the user's list of pending payloads, so it can be sent back when
 * that user's next poll transmission comes.
 */
void add_pending_msg(u64 user_ix, u64 data_len, u8* data)
{
    /* Make sure the user has space in their list of pending messages. */
    if(clients[user_ix].num_pending_msgs == MAX_PEND_MSGS)
    {
        printf("[ERR] Server: No space for pend_msgs of userix[%lu]\n",user_ix);
        return;
    }
    /* Make sure the message is within the maximum permitted message length. */
    if(data_len >= MAX_MSG_LEN)
    {
        printf("[ERR] Server: Pend_msg of userix[%lu] is too long!\n", user_ix);
        printf("              The MSG length is: %lu bytes\n\n", data_len);
        return;
    }

    /* Warn the server operator that the user has just reached the limit for the
     * number of pending messages. While not dangerous right now, this is still
     * considered an anomaly.
     */
    if(clients[user_ix].num_pending_msgs == (MAX_PEND_MSGS - 1))
        printf("[ERR] Server: userix[%lu] reached pend_msgs limit!\n", user_ix);

    /* num_pending_msgs conveniently doubles as a way to tell which pending
     * message slot is the next free one for each user. If that user has 0
     * pending messages, fill the slot at index [0]. If they have 1 pending
     * message, fill out the second slot, which is at index [1], etcetera.
     */

    /* Add it to the user's list of pending messages, for the next poll. */
    memcpy(clients[user_ix].pending_msgs[clients[user_ix].num_pending_msgs],
           data, data_len);

    clients[user_ix].pending_msg_sizes[clients[user_ix].num_pending_msgs]
        = data_len;

    ++clients[user_ix].num_pending_msgs;
    return;
}

void remove_user_from_room(u64 sender_ix)
{
    u8* reply_buf;
    u64 reply_len;
    u64 tmp_packet_id;

    /* If it's not the owner, just tell the others that the person has left. */
    if(sender_ix != rooms[clients[sender_ix].room_ix].owner_ix)
    {
        /* Construct the message and send it to everyone else in the chatroom.*/
        reply_len = (2 * SMALL_FIELD_LEN) + SIGNATURE_LEN;
        reply_buf = calloc(1, reply_len);
        PRINT_ERR_AND_EXIT_IF_NULL_PTR(reply_buf,
         "[ERR] Heap alloc in remove_user_from_room for reply_buf 1 failed: ")

        tmp_packet_id = PACKET_ID_50;

        memcpy(reply_buf, &tmp_packet_id, sizeof(u64));
        memcpy(reply_buf + SMALL_FIELD_LEN, clients[sender_ix].user_id,
               SMALL_FIELD_LEN);

        /* Compute a signature so the clients can authenticate the server. */
        signature_generate( M, Q, Gm, reply_buf, reply_len - SIGNATURE_LEN,
                            reply_buf + (reply_len - SIGNATURE_LEN),
                            &server_privkey_bigint, PRIVKEY_LEN);

        /* Let the other room guests know that a user has left. */
        for(u64 i = 0; i < MAX_CLIENTS; ++i)
        {
            if(   (i != sender_ix)
               && (clients[i].room_ix == clients[sender_ix].room_ix))
            {
                add_pending_msg(i, reply_len, reply_buf);
                printf("[OK]  Server: Added pending message to user[%lu] that\n"
                       "              user[%lu] left the room.\n",i,sender_ix);
            }
        }

        /* Server bookkeeping - a guest has left the chatroom they were in.
         * In this case, simply decrement the number of guests in the char room
         * and reset the user descriptor.
         */
        rooms[clients[sender_ix].room_ix].num_people -= 1;
        clients[sender_ix].room_ix = 0;
        clients[sender_ix].num_pending_msgs = 0;
        memset(clients[sender_ix].user_id, 0x00, SMALL_FIELD_LEN);
        room_owner_left_bitmask &= ~(1ULL << (63ULL - sender_ix));

        for(size_t i = 0; i < MAX_PEND_MSGS; ++i)
        {
            memset(clients[sender_ix].pending_msgs[i], 0, MAX_MSG_LEN);
            clients[sender_ix].pending_msg_sizes[i] = 0;
        }
    }
    /* if it WAS the room owner, boot everyone else from the chatroom as well */
    else{
        printf("[OK] Removing room[%lu] owner!\n", clients[sender_ix].room_ix);
        reply_len = SMALL_FIELD_LEN + SIGNATURE_LEN;
        reply_buf = calloc(1, reply_len);
        PRINT_ERR_AND_EXIT_IF_NULL_PTR(reply_buf,
         "[ERR] Heap alloc in remove_user_from_room for reply_buf 2 failed: ")

        tmp_packet_id = PACKET_ID_51;
        memcpy(reply_buf, &tmp_packet_id, sizeof(u64));

        /* Compute a signature so the clients can authenticate the server. */
        signature_generate( M, Q, Gm, reply_buf, reply_len - SIGNATURE_LEN,
                            reply_buf + (reply_len - SIGNATURE_LEN),
                            &server_privkey_bigint, PRIVKEY_LEN);

        /* Let the other room guests know that the room owner has closed it. */
        for(u64 i = 0; i < MAX_CLIENTS; ++i)
        {
            if(   (i != sender_ix)
               && (clients[i].room_ix == clients[sender_ix].room_ix))
            {
                printf("[OK]  Server: Adding pending MSG to user[%lu] that\n"
                       "              they've been booted from the room.\n", i);
                add_pending_msg(i, reply_len, reply_buf);
                room_owner_left_bitmask |= (1ULL << (63ULL - i));
            }
        }
        /* Reflect in the global chat room bitmask that the room is free. */
        rooms_status_bitmask &= ~(1ULL << (63ULL - clients[sender_ix].room_ix));

        /* Bookkeeping - a room owner closed their chatroom. Boot everyone.
         * In this case, nullify the entire room's descriptor structure.
         * Also move next free room slot to here if it was before this index.
         */
        rooms[clients[sender_ix].room_ix].num_people = 0;
        rooms[clients[sender_ix].room_ix].owner_ix   = 0;
        rooms[clients[sender_ix].room_ix].room_id    = 0;

        if(clients[sender_ix].room_ix < next_free_room_ix)
            next_free_room_ix = clients[sender_ix].room_ix;

        clients[sender_ix].room_ix = 0;
    }

    free(reply_buf);
    return;
}

u8 authenticate_client( u64 client_ix,  u8* signed_ptr,
                        u64 signed_len, u64 sign_offset)
{
    bigint *recv_e;
    bigint *recv_s;
    u64 s_offset = sign_offset;
    u64 e_offset = (sign_offset + sizeof(bigint) + PRIVKEY_LEN);
    u8 ret;

    /* Reconstruct the sender's signature as the two BigInts that make it up. */
    /* Then proceed to validate the signature for the user's authenticity.    */
    recv_s = (bigint*)(signed_ptr + s_offset);
    recv_e = (bigint*)(signed_ptr + e_offset);

    recv_s->bits = calloc(1, MAX_USED_BITWIDTH);
    PRINT_ERR_AND_EXIT_IF_NULL_PTR(recv_s->bits,
        "[ERR] Heap alloc in authenticate_client for recv_s->bits failed: ")

    recv_e->bits = calloc(1, MAX_USED_BITWIDTH);
    PRINT_ERR_AND_EXIT_IF_NULL_PTR(recv_e->bits,
        "[ERR] Heap alloc in authenticate_client for recv_e->bits 1 failed: ")

    memcpy(recv_s->bits, signed_ptr + (sign_offset + sizeof(bigint)),
           PRIVKEY_LEN);

    memcpy(recv_e->bits,
           signed_ptr + (sign_offset + (2*sizeof(bigint)) + PRIVKEY_LEN),
           PRIVKEY_LEN);

    ret = signature_validate(Gm, &(clients[client_ix].client_pubkey_mont),
                             M, Q, recv_s, recv_e, signed_ptr, signed_len);
    bigint_cleanup(recv_s);
    bigint_cleanup(recv_e);
    return ret;
}

void remove_user_from_rosetta(u64 removing_user_ix)
{
    int status = 0;

    /* Might have to remove them from a room (as a guest or as the owner)
     * or simply from the server if they weren't in a room. Then release the
     * heap-allocated pending message buffers as well as BigInts, then clear the
     * user's descriptor structure, mark their global user index slot as
     * available and lastly close the server's connection to the client machine.
     */
    if(clients[removing_user_ix].room_ix != 0)
        remove_user_from_room(removing_user_ix);

    for(size_t i = 0; i < MAX_PEND_MSGS; ++i)
        free(clients[removing_user_ix].pending_msgs[i]);

    bigint_nullify( & (clients[removing_user_ix].client_pubkey) );
    bigint_cleanup(&(clients[removing_user_ix].client_pubkey));

    bigint_nullify( & (clients[removing_user_ix].client_pubkey_mont) );
    bigint_cleanup(&(clients[removing_user_ix].client_pubkey_mont));

    bigint_nullify( & (clients[removing_user_ix].shared_secret) );
    bigint_cleanup(&(clients[removing_user_ix].shared_secret));

    memset(&(clients[removing_user_ix]), 0, sizeof(struct connected_client));
    users_status_bitmask &= ~(1ULL << (63ULL - removing_user_ix));

    status = close(client_socket_fd[removing_user_ix]);
    if(status != 0)
        printf("[ERR] Server: Couldn't close quitting client's socket.\n\n");

    /* Update next free user slot if needed. */
    if(removing_user_ix < curr_free_user_ix)
    {
        curr_free_user_ix = removing_user_ix;
        printf("[DEBUG] Server: Removed user. Set curr free user ix: %lu\n",
               removing_user_ix);
    }
    return;
}

/* First thing done when we start the Rosetta server - initialize it. */
u8 self_init()
{
    FILE* privkey_dat = NULL;
    u8 status = 0;

    /* Set a signal disposition (handler function) for the SIGPIPE signal,
     * telling the server to ignore that signal. This is because a client
     * could crash or otherwise disappear suddenly, while a poll request
     * sent by them is still on its way to the server (or being processed
     * by the server already), in which case, at least for interprocess
     * communication (AF_UNIX) sockets, the OS sends a SIGPIPE to the server,
     * killing it if no handler has been set for that signal. When ignoring it,
     * write() and send() issued by the server to that no longer present client
     * will return -1 and sent errno to EPIPE, which can be handled eleganrtly
     * by the server, instead of the server process getting terminated.
     */
    struct sigaction sa;
    sa.sa_handler = SIG_IGN;
    sigemptyset(&sa.sa_mask);
    sa.sa_flags = 0;

    if(sigaction(SIGPIPE, &sa, NULL) == -1)
    {
        perror("[ERR] Server: Setting SIG_IGN disposition for SIGPIPE failed:");
        exit(1);
    }
    printf("[OK]  Server: Signal handler SIG_IGN for SIGPIPE has been set.\n");

    temp_handshake_buf = NULL;

    /* Start listening for incoming user client requests. */
    status = init_communication();
    if(status)
    {
        printf("[ERR] Server: Communication init function ptr call fail.\n");
        goto label_cleanup;
    }

    /* Allocate memory for the temporary login handshake memory region. */
    temp_handshake_buf = calloc(1, TEMP_BUF_SIZ);
    PRINT_ERR_AND_EXIT_IF_NULL_PTR(temp_handshake_buf,
        "[ERR] Heap alloc in server self_init for temp_handshake_buf failed: ")

    /*  Server will use its private key to compute cryptographic signatures of
     *  everything it transmits, so all users can authenticate it using the
     *  server's long-term public key they already have at install time.
     */
    privkey_dat = fopen(SERV_PRIVKEY_PATH, "r");
    if(!privkey_dat)
    {
        perror("[ERR] Server: couldn't open private key DAT file:\n");
        status = 1;
        goto label_cleanup;
    }
    if(fread(server_privkey, 1, PRIVKEY_LEN, privkey_dat) != PRIVKEY_LEN)
    {
        printf("[ERR] Server: couldn't get private key from file. Aborting.\n");
        status = 1;
        goto label_cleanup;
    }
    else
        printf("[OK]  Server: Successfully loaded private key.\n");

    /* Initialize the global BigInt that stores the server's private key. */
    bigint_create_from_u32(&server_privkey_bigint, MAX_USED_BITWIDTH, 0);
    memcpy(server_privkey_bigint.bits, server_privkey, PRIVKEY_LEN);

    server_privkey_bigint.used_bits =
        get_used_bits(server_privkey, PRIVKEY_LEN);

    /* Load in other BigInts needed for the cryptography to work.   */
    /* Diffie-Hellman modulus M, large prime number around 3070-bit */
    M = get_bigint_from_dat
            (DH_MODULUS_M_PATH, DH_M_BITWIDTH, MAX_USED_BITWIDTH);

    /* DH prime order Q, dividing M-1, around 320-bit. Gives M security. */
    Q = get_bigint_from_dat
            (DH_PRIME_ORDER_Q_PATH, DH_Q_BITWIDTH, MAX_USED_BITWIDTH);

    /* Diffie-Hellman generator G = [2 ^ ((M-1) / Q)] mod M */
    G = get_bigint_from_dat
            (DH_GENERATOR_G_PATH, DH_G_BITWIDTH, MAX_USED_BITWIDTH);

    /* Montgomery Form of G, since we use Montgomery Modular Multiplication. */
    Gm = get_bigint_from_dat
             (DH_G_MONT_PATH, DH_G_MONT_BITWIDTH, MAX_USED_BITWIDTH);

    /* The public key of the Rosetta server, ~ same bitwidth as M. */
    server_pubkey_bigint = get_bigint_from_dat
                    (SERV_PUBKEY_PATH, SERV_PUBKEY_BITWIDTH, MAX_USED_BITWIDTH);

    /* Initialize the mutex that will be used to prevent the main thread and
     * the connection checker thread from getting into a race condition.
     */
    if(pthread_mutex_init(&mutex, NULL) != 0)
    {
        printf("[ERR] Server: Mutex could not be initialized. Aborting.\n");
        status = 1;
        goto label_cleanup;
    }

label_cleanup:

    if(privkey_dat)
        fclose(privkey_dat);

    free(temp_handshake_buf);
    return status;
}

/*  To make the server design more elegant, this top-level message processor
 *  only checks whether the message is legit or not, and which of the predefined
 *  accepted types it is.
 *
 *  The message is then sent to its own individual processor function to be
 *  further analyzed and reacted to as defined by Rosetta's custom userspace
 *  communication protocol.
 *
 *  This logical split of functionality eases the server implementation.
 *
 *  The complete list of possible legitimate transmissions to the server:
 *
 *      - A client decides to log in Rosetta
 *      - A client decides to make a new chat room
 *      - A client decides to join a chat room.
 *      - A client decides to send a new message to the chatroom.
 *      - A client decides to poll the server about unreceived messages.
 *      - A client decides to exit the chat room they're in.
 *      - A client decides to log off Rosetta.
 */
u8 identify_new_transmission(u8* client_msg_buf, s64 bytes_read, u64 sock_ix)
{
    u64 transmission_type = 0;
    u64 found_user_ix = 0;
    u64 text_msg_len;
    s64 expected_siz = 0;
    u32 status = 0;
    char *msg_type_str = calloc(1, 3);

    PRINT_ERR_AND_EXIT_IF_NULL_PTR(msg_type_str,
      "[ERR] Heap alloc in identify_new_transmission for msg_type_str failed: ")

    /* Read the first 8 bytes to see what type of init transmission it is. */
    memcpy(&transmission_type, client_msg_buf, SMALL_FIELD_LEN);

    switch(transmission_type)
    {
    /* A client tried to log in Rosetta */
    case(PACKET_ID_00):
    {
        expected_siz = SMALL_FIELD_LEN + PUBKEY_LEN;
        strncpy(msg_type_str, "00\0", 3);
        if(bytes_read != expected_siz)
        {
            status = 200;
            login_not_finished = 0;
            goto label_error;
        }
        /* If transmission is of a valid type and size, process it. */
        status = (uint32_t)process_msg_00(client_msg_buf, sock_ix);
        if(status)
        {
            login_not_finished = 0;
            status = 200;
        }
        break;
    }
    /* Login part 2 - client sent their encrypted long-term public key. */
    case(PACKET_ID_01):
    {
        expected_siz = SMALL_FIELD_LEN + PUBKEY_LEN + HMAC_TRUNC_BYTES;
        strncpy(msg_type_str, "01\0", 3);
        if(bytes_read != expected_siz)
        {
            status = 1;
            goto label_error;
        }
        /* If transmission is of a valid type and size, process it. */
        status = (uint32_t)process_msg_01(client_msg_buf, sock_ix);
        if(status)
            status = 200;

        break;
    }
    /* A client wants to create a new chatroom of their own. */
    case(PACKET_ID_10):
    {
        expected_siz = (4 * SMALL_FIELD_LEN) + ONE_TIME_KEY_LEN + SIGNATURE_LEN;
        strncpy(msg_type_str, "10\0", 3);
        if(bytes_read != expected_siz)
        {
            status = 1;
            goto label_error;
        }
        /* If transmission is of a valid type and size, process it. */
        process_msg_10(client_msg_buf, sock_ix);
        break;
    }
    /* A client wants to join an existing chatroom. */
    case(PACKET_ID_20):
    {
        expected_siz = (4 * SMALL_FIELD_LEN) + ONE_TIME_KEY_LEN + SIGNATURE_LEN;
        strncpy(msg_type_str, "20\0", 3);
        if(bytes_read != expected_siz)
        {
            status = 1;
            goto label_error;
        }
        /* If transmission is of a valid type and size, process it. */
        process_msg_20(client_msg_buf, sock_ix);
        break;
    }
    /* A client wants to send a text message to everyone else in the chatroom */
    case(PACKET_ID_30):
    {
        strncpy(msg_type_str, "30\0", 3);

        /* Size must be in bytes:
         *   (3 * SMALL_FIELD_LEN) + L + SIG_LEN
         *   where L is the length of associated data:
         *   L = (people in room - 1) * (SMALL_LEN + ONE_TIME_KEY_LEN + TXT_LEN)
         *   where TXT_LEN is given in the 3rd SMALL_FIELD_LEN field.
         */
        for(u64 x = 0; x < MAX_CLIENTS; ++x)
        {
            if(strncmp( clients[x].user_id,
                        (const char*)(client_msg_buf + SMALL_FIELD_LEN),
                        SMALL_FIELD_LEN) == 0)
            {
                found_user_ix = x;
                break;
            }
        }
        memcpy(&text_msg_len, client_msg_buf + (2 * SMALL_FIELD_LEN),
               SMALL_FIELD_LEN);

        expected_siz =   (3 * SMALL_FIELD_LEN)
                       + (
                          (rooms[clients[found_user_ix].room_ix].num_people - 1)
                          *
                          (SMALL_FIELD_LEN + ONE_TIME_KEY_LEN + text_msg_len)
                         )
                       + SIGNATURE_LEN;

        if(bytes_read != expected_siz)
        {
            status = 1;
            goto label_error;
        }
        /* If transmission is of a valid type and size, process it. */
        process_msg_30(client_msg_buf, expected_siz,
                       expected_siz - SIGNATURE_LEN, found_user_ix);
        break;
    }
    /* A client polled the server asking for any pending unreceived messages. */
    case(PACKET_ID_40):
    {
        strncpy(msg_type_str, "40\0", 3);
        expected_siz = (2 * SMALL_FIELD_LEN) + SIGNATURE_LEN;
        if(bytes_read != expected_siz)
        {
            status = 1;
            goto label_error;
        }
        /* If transmission is of a valid type and size, process it. */
        process_msg_40(client_msg_buf, sock_ix);
        break;
    }
    /* A client decided to exit the chatroom they're currently in. */
    case(PACKET_ID_50):
    {
        strncpy(msg_type_str, "50\0", 3);
        expected_siz = (2 * SMALL_FIELD_LEN) + SIGNATURE_LEN;
        if(bytes_read != expected_siz)
        {
            status = 1;
            goto label_error;
        }
        /* If transmission is of a valid type and size, process it. */
        process_msg_50(client_msg_buf);
        break;
    }
    /* A client decided to log off Rosetta. */
    case(PACKET_ID_60):
    {
        strncpy(msg_type_str, "60\0", 3);
        expected_siz = (2 * SMALL_FIELD_LEN) + SIGNATURE_LEN;
        if(bytes_read != expected_siz)
        {
            status = 1;
            goto label_error;
        }
        /* If transmission is of a valid type and size, process it. */
        process_msg_60(client_msg_buf);

        /* Indicate to this client's poll listening thread function to return */
        status = 100;
        break;
    }

    /* Also do something in case it was a bad unrecognized transmission.  */
    default:
    {
        /* DO NOT REACT TO BAD PACKETS!! Drop them silently instead. */
        break;
    } /* end of default case.     */
    } /* end of switch statement.  */

    goto label_cleanup;

label_error:

    printf("[ERR] Server: MSG Type was %s but of wrong size or contents\n"
           "              or another error occurred, check log.\n\n",
           msg_type_str);

    printf("              Size was: %ld\n", bytes_read);
    printf("              Expected: %ld\n", expected_siz);
    printf("\n[OK]  Server: Discarding transmission.\n\n ");

label_cleanup:

    free(msg_type_str);
    return status;
}

void* start_new_client_thread(void* ix_ptr)
{
    u8* client_msg_buf = calloc(1, MAX_MSG_LEN);
    ssize_t bytes_read;
    u32 status;
    u64 ix;

    PRINT_ERR_AND_EXIT_IF_NULL_PTR(client_msg_buf,
      "[ERR] Heap alloc in start_new_client_thread for client_msg_buf failed: ")

    memcpy(&ix, ix_ptr, sizeof(ix));
    memset(client_msg_buf, 0, MAX_MSG_LEN);

    while(1)
    {
        /* Blocking. TIMES OUT automatically via SO_RCVTIMEO socket option. */
        bytes_read = receive_payload(ix, client_msg_buf, MAX_MSG_LEN);

        if( __builtin_expect (bytes_read <= 0, 0) )
        {
            if(temp_handshake_memory_region_isLocked == 1)
            {
                /* At various points of this buffer's lifetime, various pointers
                 * in it point to heap memory. Sudden disruption of login
                 * leading to here DOES NOT free() them or erase the memory
                 * they might point to.
                 * TODO ^
                 */
                memset(temp_handshake_buf, 0, TEMP_BUF_SIZ);
                temp_handshake_memory_region_isLocked = 0;
            }
            if(login_not_finished)
            {
                login_not_finished = 0;
                close(client_socket_fd[ix]);
                if(ix < curr_free_user_ix)
                        curr_free_user_ix = ix;
            }
            else
                remove_user_from_rosetta(ix);

            break;
        }
        pthread_mutex_lock(&mutex);
        status = identify_new_transmission(client_msg_buf, bytes_read, ix);

        /* 200 - login can not proceed. Remove the user. No struct slot has
         *       been allocated yet, but a socket is used and next_free_user_ix
         *       has been moved. Move it back, release the socket, stop this
         *       thread.
         */
        if(status == 200)
        {
            /* At various points of this buffer's lifetime, various pointers
             * in it point to heap memory. Sudden disruption of login leading to
             * here DOES NOT free() them or erase the memory they point to.
             * TODO ^
             */
            u8 socket_closed = 0;

            if( users_status_bitmask & (1ULL << (63ULL - ix)) )
            {
                remove_user_from_rosetta(ix);
                socket_closed = 1;
            }
            memset(temp_handshake_buf, 0, TEMP_BUF_SIZ);
            temp_handshake_memory_region_isLocked = 0;

            if(!socket_closed)
                close(client_socket_fd[ix]);
            if(ix < curr_free_user_ix)
                curr_free_user_ix = ix;

            pthread_mutex_unlock(&mutex);
            break;
        }
        if(status != 100 && status > 0)
        {
            printf("[ERR] Server: identifying new transmission went bad!\n");
            remove_user_from_rosetta(ix);
            pthread_mutex_unlock(&mutex);
            break;
        }
        /* In this case, by definition, it's also OK to stop accepting any more
         * poll requests by this client since they know they're not in the room
         * anymore since they initiated their leaving.
         */
        if( status == 100 )
        {
            printf("[OK] Server: client poll thread [%lu] exits: "
                   "User logged out!\n", ix);
            pthread_mutex_unlock(&mutex);
            break;
        }
        memset(client_msg_buf, 0, bytes_read);
        pthread_mutex_unlock(&mutex);
    }
    free(client_msg_buf);
    return NULL;
}
