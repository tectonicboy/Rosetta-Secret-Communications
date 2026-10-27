/* This source file was created because, from a system design point of view,
 * there was a circular dependency between server packet functions and server
 * primary functions. There was no way to have all primary functions in the file
 * server-primary-functions.h, because certain packet functions called primary
 * functions, while certain primary functions called packet functions.
 *
 * Thus, place the function prorotypes of the server primary functions here and
 * include this file before the two headers that had the circular dependency
 * (server-packet-functions.h and server-primary-functions.h).
 */

u8 self_init(void);
u8 identify_new_transmission(u8* client_msg_buf, s64 bytes_read, u64 sock_ix);
void* start_new_client_thread(void* ix_ptr);

u8 check_pubkey_exists(u8* pubkey_buf, u64 pubkey_siz);

u8 authenticate_client(u64 client_ix,  u8* signed_ptr,
                      u64 signed_len, u64 sign_offset);

void add_pending_msg(u64 user_ix, u64 data_len, u8* data);
void remove_user_from_room(u64 sender_ix);
void remove_user_from_rosetta(u64 removing_user_ix);

