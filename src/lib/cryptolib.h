#pragma once

/* These simplify pointer arithmetic to access Argon2's memory matrix B[][].  */
typedef struct block_1024
{
    uint8_t block_data[1024];
} block1024_t;

typedef struct block_64
{
    uint8_t block_data[64];
} block64_t;

/* Parameters to Argon2. */
struct Argon2_parms
{
    uint64_t p;  /* Paralellism - how many threads to use. 1   to (2^24) - 1 */
    uint64_t T;  /* How many bytes of output we want.      4   to (2^32) - 1 */
    uint64_t m;  /* Memory usage in kibibytes, as per RFC. 8*p to (2^32) - 1 */
    uint64_t t;  /* Number of passes Argon2 should do.     1   to (2^32) - 1 */
    uint64_t v;  /* Version number.                        It is always 0x13 */
    uint64_t y;  /* Type of Argon2 algorithm.              0x02 for Argon2id */

    uint8_t* P;  /* Input password used as the hashing KEY. */
    uint8_t* S;  /* Input salt.                             */
    uint8_t* K;  /* OPTIONAL secret value.                  */
    uint8_t* X;  /* OPTIONAL associated data.               */

    uint64_t len_P; /* Length of input password in bytes.     <= (2^32) - 1  */
    uint64_t len_S; /* Length of input salt in bytes.         <= (2^32) - 1  */
    uint64_t len_K; /* Length of secret value in bytes.       <= (2^32) - 1  */
    uint64_t len_X; /* Length of associated data in bytes.    <= (2^32) - 1  */
};

/* Offsets into the input memory buffer for Argon2's multithreading function. */
#define OFFSET_r  (sizeof(block1024_t*) + (0 * sizeof(uint64_t)))
#define OFFSET_l  (sizeof(block1024_t*) + (1 * sizeof(uint64_t)))
#define OFFSET_sl (sizeof(block1024_t*) + (2 * sizeof(uint64_t)))
#define OFFSET_md (sizeof(block1024_t*) + (3 * sizeof(uint64_t)))
#define OFFSET_t  (sizeof(block1024_t*) + (4 * sizeof(uint64_t)))
#define OFFSET_y  (sizeof(block1024_t*) + (5 * sizeof(uint64_t)))
#define OFFSET_p  (sizeof(block1024_t*) + (6 * sizeof(uint64_t)))
#define OFFSET_q  (sizeof(block1024_t*) + (7 * sizeof(uint64_t)))

/* Initialization vector of constants for BLAKE2b. Defined in the RFC spec. */
const uint64_t BLAKE2B_IV[8] =
{
    0x6A09E667F3BCC908, 0xBB67AE8584CAA73B,
    0x3C6EF372FE94F82B, 0xA54FF53A5F1D36F1,
    0x510E527FADE682D1, 0x9B05688C2B3E6C1F,
    0x1F83D9ABFB41BD6B, 0x5BE0CD19137E2179
};

/* Message word permutation constants for BLAKE2b. Defined in the RFC spec. */
const uint64_t BLAKE2B_sigma[12][16] =
{
    { 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15 },
    { 14, 10, 4, 8, 9, 15, 13, 6, 1, 12, 0, 2, 11, 7, 5, 3 },
    { 11, 8, 12, 0, 5, 2, 15, 13, 10, 14, 3, 6, 7, 1, 9, 4 },
    { 7, 9, 3, 1, 13, 12, 11, 14, 2, 6, 5, 10, 4, 0, 15, 8 },
    { 9, 0, 5, 7, 2, 4, 10, 15, 14, 1, 11, 12, 6, 8, 3, 13 },
    { 2, 12, 6, 10, 0, 11, 8, 3, 4, 13, 7, 5, 15, 14, 1, 9 },
    { 12, 5, 1, 15, 14, 13, 4, 10, 0, 7, 6, 3, 9, 2, 8, 11 },
    { 13, 11, 7, 14, 12, 1, 3, 9, 5, 0, 15, 4, 8, 6, 2, 10 },
    { 6, 15, 14, 9, 11, 3, 0, 8, 12, 2, 13, 7, 1, 4, 10, 5 },
    { 10, 2, 8, 4, 7, 6, 1, 5, 15, 11, 9, 14, 3, 12, 13, 0 },
    { 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15 },
    { 14, 10, 4, 8, 9, 15, 13, 6, 1, 12, 0, 2, 11, 7, 5, 3 }
};

/* Rotation constants for BLAKE2b. Defined in the RFC spec. */
#define R1 32
#define R2 24
#define R3 16
#define R4 63

/*****************************************************************************/
/*                   CHACHA20 IMPLEMENTATION BEGINS                          */
/*                                                                           */
/*     The implementation is based on RFC 8439's theoretical description.    */
/*****************************************************************************/
static void
chacha_qround(uint32_t* matrix, uint8_t a, uint8_t b, uint8_t c, uint8_t d)
{
    matrix[a] += matrix[b];
    matrix[d] ^= matrix[a];
    UINT32_ROLL_LEFT((matrix + d), 16);
    matrix[c] += matrix[d];
    matrix[b] ^= matrix[c];
    UINT32_ROLL_LEFT((matrix + b), 12);
    matrix[a] += matrix[b];
    matrix[d] ^= matrix[a];
    UINT32_ROLL_LEFT((matrix + d), 8);
    matrix[c] += matrix[d];
    matrix[b] ^= matrix[c];
    UINT32_ROLL_LEFT((matrix + b), 7);
    return;
}

static void chacha_inner(uint32_t* matrix)
{
    chacha_qround(matrix, 0, 4, 8,  12);
    chacha_qround(matrix, 1, 5, 9,  13);
    chacha_qround(matrix, 2, 6, 10, 14);
    chacha_qround(matrix, 3, 7, 11, 15);
    chacha_qround(matrix, 0, 5, 10, 15);
    chacha_qround(matrix, 1, 6, 11, 12);
    chacha_qround(matrix, 2, 7, 8,  13);
    chacha_qround(matrix, 3, 4, 9,  14);
    return;
}

/*  Part of the block function is to construct the actual
 *  chacha state matrix. It always consists of exactly
 *  16 unsigned 32-bit integers. The constants are always
 *  four and always exactly the same as per the RFC.
 *
 *  This means: (key_len + counter_len + nonce_len)
 *              MUST add up to 12. One unit of length
 *              here means one unsigned 32-bit integer.
 */
static void chacha_block_func
    (uint32_t* key,   uint8_t key_len,   uint32_t* counter, uint8_t counter_len,
     uint32_t* nonce, uint8_t nonce_len, uint32_t* serialized_result)
{
    u32 state[16];
    u32 initial_state[16];
    u32 next_ix;
    u32 i;
    uint8_t* aux_ptr8_state;
    uint8_t* aux_ptr8_key;
    uint8_t* aux_ptr8_nonce;
    uint8_t* aux_ptr8_serial_result;

    if(key_len + counter_len + nonce_len != 12)
    {
        printf("[ERR] Cryptolib - lengths of key, counter,"
               " nonce DOES NOT add up to 12.\n");
        return;
    }

    /* The 4 constants. Specified in the RFC.*/
    state[0] = 0x61707865;
    state[1] = 0x3320646e;
    state[2] = 0x79622d32;
    state[3] = 0x6b206574;

    next_ix = 4;

    /* For each uint32_t part in the key. */
    for(i = key_len; i > 0; --i)
    {
        aux_ptr8_state = (uint8_t*)(state + next_ix);
        aux_ptr8_key   = (uint8_t*)(key + (key_len - i));
        aux_ptr8_state[3] = aux_ptr8_key[0];
        aux_ptr8_state[2] = aux_ptr8_key[1];
        aux_ptr8_state[1] = aux_ptr8_key[2];
        aux_ptr8_state[0] = aux_ptr8_key[3];
        ++next_ix;
    }
    if(counter_len)
    {
        state[next_ix] = *counter;
        ++next_ix;
    }
    for(i = nonce_len; i > 0; --i)
    {
        aux_ptr8_state = (uint8_t*)(state + next_ix);
        aux_ptr8_nonce = (uint8_t*)(nonce + (nonce_len - i));
        aux_ptr8_state[3] = aux_ptr8_nonce[0];
        aux_ptr8_state[2] = aux_ptr8_nonce[1];
        aux_ptr8_state[1] = aux_ptr8_nonce[2];
        aux_ptr8_state[0] = aux_ptr8_nonce[3];
        ++next_ix;
    }

    memcpy(initial_state, state, 16 * sizeof(uint32_t));

    for(i = 1; i <= 10; ++i)
        chacha_inner(state);

    for(i = 0; i < 16; ++i)
        state[i] += initial_state[i];

    /* Every uint32_t has its bytes reversed. This is the serialized result.
     * So each uint32_t goes:
     * from [byte_0 byte_1 byte_2 byte_3] to [byte_3 byte_2 byte_1 byte_0]
     */
    for(i = 0; i < 16; ++i)
    {
        aux_ptr8_state            = (uint8_t*)(state + i);
        aux_ptr8_serial_result    = (uint8_t*)(serialized_result + i);
        aux_ptr8_serial_result[0] = aux_ptr8_state[0];
        aux_ptr8_serial_result[1] = aux_ptr8_state[1];
        aux_ptr8_serial_result[2] = aux_ptr8_state[2];
        aux_ptr8_serial_result[3] = aux_ptr8_state[3];
    }
    return;
}

/* Optimization successful:
 *
 * Moving this loop from the body of chacha20() itself into this helper
 * function that takes the pointers that the loop operates on as restricted
 * pointers (because they are guaranteed to never access overlapping memory
 * by design here) did in fact help the compiler's aliasing analysis
 * and removed the need to version this same loop by emitting a vectorized
 * and a non-vectorized version due to aliasing concerns, with a runtime check
 * to see if the loop will cause the pointers to alias each other's memory,
 * that determines which of the two emitted versions of the loop to use.
 *
 * The compiler has now entirely dropped the loop versioning and only kept the
 * fast vectorized version of the loop for all of its uses.
 */
static inline void chacha20_cyphertext_populate_full_blocks
    (uint8_t* __restrict__ outputs,    uint8_t* __restrict__ plaintext,
     uint8_t* __restrict__ cyphertext, uint32_t block_ix)
{
    for(uint32_t j = 0; j < 64; ++j)
        cyphertext[(64 * block_ix) + j] =
            plaintext[(64 * block_ix) + j] ^ outputs[j];
    return;
}

void chacha20(uint8_t* plaintext, uint32_t txt_len, uint32_t* nonce,
              uint8_t nonce_len,  uint32_t* key,    uint8_t key_len,
              uint8_t* cyphertext)
{
    const u32 num_matrices = (uint32_t)ceil((double)txt_len / 64.0);
    u32   i;
    u32   j;
    u32   counter_len = 16 - (key_len + nonce_len + 4);
    u32   last_txt_block_len;
    u32** outputs = NULL;
    u32*  counter = NULL;
    u32   full_txt_blocks = 0;
    u8*   aux_ptr8_outputs;
    u8    have_last_block = 0;

    /* This sum can be either 16 or 15. 16 means no space for a counter, 15
     * means one 32-bit space for a counter. Bigger counters are not supported.
     */
    if( (key_len + nonce_len + 4) > 16 || (key_len + nonce_len + 4) < 15 )
    {
        printf("[ERR] Cryptolib - sum of lengths of key,"
               " nonce, constants is invalid.\n");
        return;
    }

    outputs = (u32**)calloc(1, num_matrices * sizeof(uint32_t*));
    PRINT_ERR_AND_EXIT_IF_NULL_PTR(outputs,
        "[ERR] Heap alloc in chacha20 for outputs failed: ")

    for(i = 0; i < num_matrices; ++i)
    {
        outputs[i] = (u32*)calloc(1, 64 * sizeof(uint8_t));
        PRINT_ERR_AND_EXIT_IF_NULL_PTR(outputs[i],
        "[ERR] Heap alloc in chacha20 for outputs[i] failed: ")
    }
    if(counter_len > 0)
    {
        counter = (u32*)calloc(1, sizeof(uint32_t));
        PRINT_ERR_AND_EXIT_IF_NULL_PTR(counter,
            "[ERR] Heap alloc in chacha20 for counter failed: ")
        *counter = 1;
    }
    for(i = 0; i < num_matrices; ++i)
    {
        chacha_block_func
            (key, key_len, counter, counter_len, nonce, nonce_len, outputs[i]);

        if(counter)
            ++(*counter);
    }
    if(txt_len < 64)
    {
        have_last_block    = 1;
        last_txt_block_len = txt_len;
        full_txt_blocks    = 0;
    }
    else
    {
        if(txt_len % 64 == 0)
        {
            have_last_block = 0;
            full_txt_blocks = num_matrices;
        }
        else
        {
            have_last_block = 1;
            last_txt_block_len = txt_len % 64;
            full_txt_blocks = num_matrices - 1;
        }
    }

    /* Placed the inner loop in a small helper function taking the 3 pointers
     * as __restrict__ arguments. The compiler now drops the loop versioning
     * with a vectorized and a non-vectorized version of the inner loop
     * (which was because of possible pointer aliasing) and now only emits the
     * vectorized version of the loop. Amazing compiler optimization!
     */
    for(i = 0; i < full_txt_blocks; ++i)
    {
        aux_ptr8_outputs = (uint8_t*)(outputs[i]);
        chacha20_cyphertext_populate_full_blocks
            (aux_ptr8_outputs, plaintext, cyphertext, i);
    }
    if(have_last_block)
    {
        aux_ptr8_outputs = (uint8_t*)(outputs[full_txt_blocks]);
        for(j = 0; j < last_txt_block_len; ++j)
            cyphertext[(64 * full_txt_blocks) + j] =
                plaintext[(64 * full_txt_blocks) + j] ^ aux_ptr8_outputs[j];

    }

    /* Cleanup */
    free(counter);

    for(i = 0; i < num_matrices; ++i)
        free(outputs[i]);

    free(outputs);
    return;
}

/*****************************************************************************/
/*                   BLAKE2B IMPLEMENTATION BEGINS                           */
/*                                                                           */
/*     The implementation is based on RFC 7693's theoretical description.    */
/*****************************************************************************/
static void blake2b_g(u64* v, u64 a, u64 b, u64 c ,u64 d, u64 x, u64 y)
{
    v[a] = v[a] + v[b] + x;
    v[d] ^= v[a];
    UINT64_ROLL_RIGHT(&(v[d]), R1);
    v[c] += v[d];
    v[b] ^= v[c];
    UINT64_ROLL_RIGHT(&(v[b]), R2);
    v[a] = v[a] + v[b] + y;
    v[d] ^= v[a];
    UINT64_ROLL_RIGHT(&(v[d]), R3);
    v[c] += v[d];
    v[b] ^= v[c];
    UINT64_ROLL_RIGHT(&(v[b]), R4);
    return;
}

static void blake2b_f(uint64_t* h, uint64_t* m, uint64_t t, uint8_t f)
{
    uint64_t v[16];
    uint64_t s[16];

    memcpy(v, h, 8 * sizeof(uint64_t));
    memcpy(v + 8, BLAKE2B_IV, 8 * sizeof(uint64_t));

    /* NOTE: Usually, t is a 128-bit unsigned integer. The second batch of 64
     *       bits are used if the input message has more than 2^64-1 bytes in it
     *       which is never going to happen in Rosetta. So hardcode v[13], which
     *       holds that second batch of 64 bits in the 128-bit integer t, to 0.
     */
    v[12] ^= t;
    v[13] ^= 0;

    if(f)
        v[14] = ~v[14];

    for(uint8_t i = 0; i < 12; ++i)
    {
        memcpy(s, (BLAKE2B_sigma[i % 12]), (16*sizeof(uint64_t)));
        blake2b_g(v, 0, 4, 8,  12, m[s[0]], m[s[1]]);
        blake2b_g(v, 1, 5, 9,  13, m[s[2]], m[s[3]]);
        blake2b_g(v, 2, 6, 10, 14, m[s[4]], m[s[5]]);
        blake2b_g(v, 3, 7, 11, 15, m[s[6]], m[s[7]]);
        blake2b_g(v, 0, 5, 10, 15, m[s[8]],  m[s[9]]);
        blake2b_g(v, 1, 6, 11, 12, m[s[10]], m[s[11]]);
        blake2b_g(v, 2, 7, 8,  13, m[s[12]], m[s[13]]);
        blake2b_g(v, 3, 4, 9,  14, m[s[14]], m[s[15]]);
    }
    for(uint8_t i = 0; i < 8; ++i)
        h[i] ^= (v[i] ^ v[i+8]);

    return;
}

/* Input 1 - Padded message blocks. It's a 2D array.
 *           Each element is a 1D array of exactly 16 uint64_t's.
 * Input 2 - Input bytes. Must be in [0, 2^128).
 * Input 3 - Key bytes. Must be in [0, 64].
 * Input 4 - Hash byte arity (how much output we want). Must be in [1, 64].
 */
static void blake2b(uint64_t** d, uint64_t ll, uint64_t kk,
                    uint64_t  dd, uint64_t nn, uint8_t* ret_bytes)
{
    uint64_t h[8];

    memcpy(h, BLAKE2B_IV, 8 * sizeof(uint64_t));
    h[0] ^= 0x01010000 ^ (kk << 8) ^ nn;

    /* Process padded key and data blocks. */
    if(dd > 1)
        for(uint64_t i = 0; i < (dd - 1); ++i)
            blake2b_f(h, (d[i]), (i + 1) * 128, 0);

    /* Final block. */
    if(kk == 0)
        blake2b_f(h, d[dd-1], ll, 1);

    else
        blake2b_f(h, d[dd-1], ll + 128, 1);

    /* Return the first NN bytes of the resulting little-endian word array h.
     * The BLAKE2B initializer function must provide this buffer with enough
     * memory allocated to hold NN bytes.
     */
    memcpy(ret_bytes, h, nn);
    return;
}

/* The top-level function that any code using Blake2B will call.
 *
 * Prepare padded 2D array of key and message blocks d. Prepare the buffer which
 * will hold the result of BLAKE2B with enough allocated memory for NN bytes.
 *
 * NOTE: In the Rosetta Security Scheme, all uses of BLAKE2B are without a key,
 *       they all pass 0 for kk.
 *
 * The caller must provide:
 *
 * m  - the raw message input.
 * ll - length in bytes of the input message
 * kk - length of secret key. Never used in Rosetta, so always passed as 0.
 * nn - How many bytes of output we want from BLAKE2B.
 * rr - result buffer for BLAKE2B's output. Must have been already allocated.
 */
void blake2b_init(u8* m, u64 ll, u64 kk, u64 nn, u8* rr)
{
    /* Find how many data blocks we will need in the 2D array d[][]. */
    uint64_t dd = ceil((double)kk/128.0) + ceil((double)ll/128.0);

    /* Find length of last data block. */
    uint64_t last_len = ll % 128;

    uint64_t** data_blocks = (u64**)calloc(1, dd * sizeof(uint64_t*));
    PRINT_ERR_AND_EXIT_IF_NULL_PTR(data_blocks,
        "[ERR] Heap alloc in blake2b_init for data_blocks failed: ")

    for(uint64_t i = 0; i < dd; ++i)
    {
        data_blocks[i] = (u64*)calloc(1, 16 * sizeof(uint64_t));
        PRINT_ERR_AND_EXIT_IF_NULL_PTR(data_blocks[i],
            "[ERR] Heap alloc in blake2b_init for data_blocks[i] failed: ")

        /* At last block? */
        if(i == dd-1)
        {
            /* If it's 0, that means last block's length is 128. */
            if(last_len == 0)
                last_len = 128;

            memcpy(data_blocks[i], m + ((dd-1) * 128), last_len);
            break;
        }
        /* All blocks before the last one are always full 128 bytes. */
        else
            memcpy(data_blocks[i], m + (i*128), 128);
    }

    /* Carry out the Blake2B algorithm now. */
    blake2b(data_blocks, ll, kk, dd, nn, rr);

    /* Cleanup */
    for(uint64_t i = 0; i < dd; ++i)
        free(data_blocks[i]);

    free(data_blocks);
    return;
}

/*****************************************************************************/
/*                   Argon2id IMPLEMENTATION BEGINS                          */
/*                                                                           */
/*     The implementation is based on RFC 9106's theoretical description.    */
/*****************************************************************************/

/* NOTE: The arithmetic operations in this function are done modulo 2^64. We're
 *       working with uint64_t's, so we can let overflow happen and ignore it.
 */
static void argon2_gb(uint64_t *a, uint64_t *b, uint64_t *c, uint64_t *d)
{
    /*  Part of this code takes only the 32 least significant bits of a and b.
     *
     *  Do this by: 1. Dereferencing the pointer for a 64-bit unsigned integer;
     *              2. Casting that to an unsigned 32-bit integer;
     *              3. Reading that 32-bit integer.
     *              4. Casting the result back to an unsigned 64-bit integer
     *                 to play nicely with the entire operation on 64-bit ints.
     *
     *  Assumes little-endian byte ordering in the machine of course.
     *  Perhaps the C standard says that this kind of casting ALWAYS grabs
     *  the last significant 32 bits of the 64-bit unsigned integer, regardless
     *  of machine byte order. Haven't checked.
     */
    *a = (*a) + (*b) + ((u64)2 * ((u64)((u32)(*a))) * ((u64)((u32)(*b))));
    *d = (*d) ^ (*a);
    UINT64_ROLL_RIGHT(d, 32);
    *c = (*c) + (*d) + ((u64)2 * ((u64)((u32)(*c))) * ((u64)((u32)(*d))));
    *b = (*b) ^ (*c);
    UINT64_ROLL_RIGHT(b, 24);
    *a = (*a) + (*b) + ((u64)2 * ((u64)((u32)(*a))) * ((u64)((u32)(*b))));
    *d = (*d) ^ (*a);
    UINT64_ROLL_RIGHT(d, 16);
    *c = (*c) + (*d) + ((u64)2 * ((u64)((u32)(*c))) * ((u64)((u32)(*d))));
    *b = (*b) ^ (*c);
    UINT64_ROLL_RIGHT(b, 63);
    return;
}

/* Takes eight 16-byte inputs and constructs a 2D array of 4x4 uint64_t's.
 * Input is in the form of a 128-byte contiguous memory block.
 * It comes from rows or columns of the 2D array of 8x8 16-byte numbers
 * that was constructed in the Argon2 G function from its 1024-byte input.
 */
static void argon2_p(uint8_t* input_128)
{
    /* To make the calls to GB() more elegant, prepare the matrix of 4x4
     * uint64_t's in advance here.
     */
    u64* matrix[16];

    for(size_t i = 0; i < 16; ++i)
        matrix[i] = (uint64_t*)(input_128 + (i * 8));

    argon2_gb((matrix[0]), (matrix[4]), (matrix[8]),  (matrix[12]));
    argon2_gb((matrix[1]), (matrix[5]), (matrix[9]),  (matrix[13]));
    argon2_gb((matrix[2]), (matrix[6]), (matrix[10]), (matrix[14]));
    argon2_gb((matrix[3]), (matrix[7]), (matrix[11]), (matrix[15]));
    argon2_gb((matrix[0]), (matrix[5]), (matrix[10]), (matrix[15]));
    argon2_gb((matrix[1]), (matrix[6]), (matrix[11]), (matrix[12]));
    argon2_gb((matrix[2]), (matrix[7]), (matrix[8]),  (matrix[13]));
    argon2_gb((matrix[3]), (matrix[4]), (matrix[9]),  (matrix[14]));
    return;
}

/* Compression function G for Argon2.
 *
 * Takes two 1024-byte blocks as input (X, Y).
 * Outputs one resulting 1024-byte block.
 *
 * Pass a pointer to where the output 1024-byte block memory region is.
 * Does not change the input memory blocks X and Y directly.
 */
static void argon2_g(uint8_t* X, uint8_t* Y, uint8_t* out_1024)
{
    uint8_t matrix_R[1024];
    uint8_t R_transformed[1024];
    uint8_t Q_columns[1024];
    uint8_t matrix_Z[1024];
    size_t i;
    size_t j;

    for(i = 0; i < 1024; ++i)
        matrix_R[i] = X[i] ^ Y[i];

    /*  R is used at the end, so save it. Pass a copy of it to P(), which
     *  transforms the copy twice, first into matrix Q, then into matrix Z.
     */
    memcpy(R_transformed, matrix_R, 1024);

    /*  Use P() to transform matrix R into matrix Q. Each ROW of matrix R is fed
     *  as the input to P(), producing the respective rows of matrix Q.
     */
    for(i = 0; i < 8; ++i)
        argon2_p(R_transformed + (i * 128));

    /*  Now further transform matrix Q into matrix Z.
     *  Each COLUMN of matrix Q is fed as input to P(),
     *  producing the respective columns of matrix Z.
     *
     *  Since columns are not contiguous in memory, we
     *  form new 128-byte buffers to serve as the 128-byte
     *  contiguous memory block input to transformation P(),
     *  the transformed output buffers we will use to construct
     *  matrix Z at the end.
     */
    for(i = 0; i < 8; ++i) /* for each of the 8 rows in Q */
        for(j = 0; j < 8; ++j) /* for each 16-byte register in that row */
            memcpy(Q_columns     + (j * 128) + (i * 16),
                   R_transformed + (i * 128) + (j * 16),
                   16);

    /* Now that we have the columns of Q in eight contiguous 128-byte buffers,
     * we are ready to feed them to the P() transformation.
     */
    for(i = 0; i < 8; ++i)
        argon2_p(Q_columns + (i * 128));

    /* Reconstruct the contiguous rows of Z. This is the final matrix. */

    for(i = 0; i < 8; ++i)      /* for each column of matrix Q */
        for(j = 0; j < 8; ++j)  /* for each 16-byte register in that column */
            memcpy(matrix_Z  + (j * 128) + (i * 16),
                   Q_columns + (i * 128) + (j * 16),
                   16);

    /* Final output is matrix R XOR matrix Z. */
    for(i = 0; i < 1024; ++i)
        out_1024[i] = matrix_R[i] ^ matrix_Z[i];

    return;
}

static void argon2_h_dash
    (uint8_t* input, uint8_t* output, uint32_t out_len, uint64_t in_len)
{
    /* We allocate memory for (r + 1) 64-byte V[i]'s. We pass a pointer to the
     * next 64-byte memory block V[i] as the output destination of BLAKE2b.
     */
    uint32_t   r = ceil(out_len / 32) - 2;

    block64_t* V = (block64_t*)calloc(1, (r + 1) * sizeof(block64_t));
    PRINT_ERR_AND_EXIT_IF_NULL_PTR(V,
        "[ERR] Heap alloc in argon2_h_dash for V failed: ")

    uint8_t* H_input = (u8*)calloc(1, 4 + in_len);
    PRINT_ERR_AND_EXIT_IF_NULL_PTR(H_input,
        "[ERR] Heap alloc in argon2_h_dash for H_input failed: ")

    memcpy(H_input + 0, &out_len, sizeof(uint32_t));
    memcpy(H_input + 4, input,    in_len);
    memset(output, 0, out_len);

    if(out_len <= 64)
        blake2b_init(H_input, (4 + in_len), 0, out_len, output);

    else
    {
        blake2b_init(H_input, (4 + in_len), 0, 64, V[0].block_data);

        for(uint64_t i = 1; i <= r-1; ++i)
            blake2b_init(V[i-1].block_data, 64, 0, 64, V[i].block_data);

        blake2b_init
            (V[r - 1].block_data, 64, 0, (out_len - (32 * r)), V[r].block_data);

        /* Construct a buffer of concatenated W_1 || W_2 ... || W_r || V_(r+1)
         * and place this result in the output target buffer of H_dash here.
         * Note, W_i is the 32 least significant bytes of 64-byte V_i.
         * Output buffer's size must be ((r * 4) + 8) bytes. Preallocated.
         */
        for(uint64_t i = 0; i <= r-1; ++i)
            memcpy(output + (32*i), V[i].block_data, 32);

        memcpy(output + (32*r), V[r].block_data, 64);
    }

    /* Cleanup. */
    free(H_input);
    free(V);
    return;
}

static void
argon2_initJ1J2_blockpool_for2i(u8* Z, block1024_t* blocks, u64 num_blocks)
{
    /* About to compute (q / (128 * SL)) 1024-byte blocks. SL = 4 slices.
     * Allocate memory for them after working out exactly how many to compute.
     */
    uint64_t G_inner_counter = 0;

    /* Some helpers for constructing the input to function G() here. */
    u8 zero1024[1024];
    u8 zero968[968];

    /* Remember, Argon2 G() takes two 1024-byte blocks and outputs one block. */

    /* Second argument of the inner G() call. */
    u8 G_inner_input_2[1024];

    /* Output of the inner G() call and input to the outer G() call. */
    u8 G_inner_output[1024];

    memset(zero1024, 0, 1024);
    memset(zero968,  0, 968 );

    /* Initialize the buffer for the 2nd input block to the inner G() call. */
    memcpy(G_inner_input_2, Z, 6 * sizeof(uint64_t));
    memcpy(G_inner_input_2 + (7 * sizeof(uint64_t)), zero968, 968);

    /* Generate the 1024-byte blocks. */
    for(uint64_t i = 0; i < num_blocks; ++i)
    {
        ++G_inner_counter;

        memcpy(G_inner_input_2 + (6 * sizeof(uint64_t)),
               &G_inner_counter, sizeof(uint64_t));

        /* First do the inner G(), whose output is 2nd input to outer G(). */
        argon2_g(zero1024, G_inner_input_2, G_inner_output);

        /* Now the outer G() that generates this actual 1024-byte block. */
        argon2_g(zero1024, G_inner_output, (uint8_t*)(&(blocks[i])));
    }
    return;
}

static uint64_t Argon2_getLZ
    (uint64_t r,   uint64_t sl,  uint64_t cur_lane, uint64_t p, uint32_t J_1,
     uint32_t J_2, uint64_t n,   uint64_t q,        uint64_t computed_blocks)
{
    u64 W_siz;
    u64 x;
    u64 y;
    u64 zz;
    u64 l_ix;
    u64 z_ix;
    u64 start_z_ix;

    /* Get the lane index from which we will take blocks. */
    if(r == 0 && sl == 0)
        l_ix = cur_lane;

    else
        l_ix = J_2 % p;

    /* Compute the size of W */
    if(l_ix != cur_lane)
    {
        W_siz = sl * n;

        if(computed_blocks == 0)
            --W_siz;
    }
    else
    {
        W_siz = (sl * n) + computed_blocks;
        --W_siz;
    }

    /* Now pick one block index from W[]. This will be z in B[l][z].         */
    /* The 4294967296 is specified in Argon2's RFC, it's not a magic number. */
    start_z_ix = l_ix * q;
    x  = (u64)(((double)(J_1 * J_1)) / (double)4294967296);
    y  = (u64)(((double)(W_siz * x)) / (double)4294967296);
    zz = W_siz - 1 - y;
    z_ix = start_z_ix + zz;
    return z_ix;
}

/*  Each thread processes one segment of the Argon2 memory matrix B[][].
 *  A segment is the intersection of one of the 4 vertical slices, with
 *  a row. Therefore one segment contains many 1024-byte blocks. To be
 *  precise, ( (m' / p) / 4) 1024-byte blocks in a single segment.
 *
 *  The operation of a single thread is the following:
 *
 *  - Begin the loop that transforms each 1024-byte block in this segment.
 *
 *    Each cycle of that loop does the following:
 *
 *      - Compute J_1 and J_2 in one of 2 ways, using the provided thread input.
 *      - Use J_1 and J_2 to compute indices l and z.
 *      - Call compression function G(), transforming this 1024-byte block.
 *
 *  Input buffer contains: Pointer to start of this thread's segment in B[][],
 *                         as well as: r, l, sl, m', t, y, p, q; as uint64_t's.
 */
void* argon2_transform_segment(void* thread_input)
{
    u64 J_1 = 0;
    u64 J_2 = 0;
    u64 z_ix;
    u64 n;
    u64 j;
    u64 j_start;
    u64 j_end;
    u64 computed_blocks = 0;
    u64 cur_lane;
    u64 q;
    u64 sl;
    u64 r;
    u64 p;
    u64 md;
    u64 num_blocks;
    block1024_t*  G_input_one;
    block1024_t*  G_input_two;
    block1024_t*  G_output;
    block1024_t*  J1J2blockpool;
    u8 Z_buf[6 * sizeof(uint64_t)];

    /* The first thing in the thread's input buffer is a pointer to an array of
     * pointers, each pointing to the start of the respective lane in the
     * working memory matrix B[][].
     */
    block1024_t** B;

    memcpy(&cur_lane, ((uint8_t*)thread_input) + OFFSET_l,  sizeof(cur_lane));
    memcpy(&q,        ((uint8_t*)thread_input) + OFFSET_q,  sizeof(q));
    memcpy(&sl,       ((uint8_t*)thread_input) + OFFSET_sl, sizeof(sl));
    memcpy(&r,        ((uint8_t*)thread_input) + OFFSET_r,  sizeof(r));
    memcpy(&p,        ((uint8_t*)thread_input) + OFFSET_p,  sizeof(p));
    memcpy(&md,       ((uint8_t*)thread_input) + OFFSET_md, sizeof(md));

    num_blocks = ceil((double)q / (double)(128 * 4));
    memcpy(&B, thread_input, sizeof(B));

    J1J2blockpool = (block1024_t*)calloc(1, num_blocks * (1024));
    PRINT_ERR_AND_EXIT_IF_NULL_PTR(J1J2blockpool,
      "[ERR] Heap alloc in argon2_transform_segment for J1J2blockpool failed: ")

    memcpy(Z_buf, ((uint8_t*)thread_input) + OFFSET_r, (6 * sizeof(uint64_t)));

    /* Determine the start and end control values of this thread's j-loop.
     * In short, which quarter of this thread's row we're transforming,
     * in terms of THE INDICES of 1024-byte blocks where the 0th block is
     * the very first block OF THIS LANE, not at the start of 2D array B[][].
     *
     * This is in contrast to index z, which is the index of a 1024-byte block
     * relative to the start of the entire 2D array B[][], not relative to the
     * start of a lane in the 2D array B.
     */

    /* Let n be the number of 1024-byte blocks in a segment. n = (m' / p) / 4 */
    n = (md / p) / 4;

    /* First block transformed relative to lane start is (n * (sl + 0))     */
    /* Last  block transformed relative to lane start is (n * (sl + 1)) - 1 */
    j_start = n *  sl;
    j_end   = n * (sl + 1);

    /* If at first slice (sl = 0), we will do 2 fewer cycles of the thread loop,
     * since the first 2 loop cycles in pass 0 are hardcoded in the Argon2 RFC
     * and are different.
     */
    if(sl == 0)
    {
        j_start = 2;
        computed_blocks = 2;
    }

    argon2_initJ1J2_blockpool_for2i(Z_buf, J1J2blockpool, num_blocks);

    for(j = j_start; j < j_end; ++j)
    {
        /* If pass number r = 0 and slice number sl = 0 or 1:
         * compute 32-bit values J_1, J_2 for Argon2i as specified by RFC.
         */
        if( r == 0 && sl < 2 )
        {
            /* Extract J_1 and J_2.
             * Offset from J1J2blockpool is in terms of bytes for J_2.
             */
            memcpy(&J_1, J1J2blockpool + 0, sizeof(uint32_t));
            memcpy(&J_2, ((u8*)J1J2blockpool) + (num_blocks *512), sizeof(u32));
        }
        /* Otherwise: get J_1, J_2 for Argon2d as specified by RFC. */
        else
        {
            memcpy(&J_1, ((u32*)(&(B[cur_lane][j-1]))) + 0, sizeof(u32));
            memcpy(&J_2, ((u32*)(&(B[cur_lane][j-1]))) + 1, sizeof(u32));
        }

        z_ix = Argon2_getLZ(r, sl, cur_lane, p, J_1, J_2, n, q,computed_blocks);

        /* Now we're ready for this loop cycle's call to G(). */

        /* Prepare input arguments of G(). These will be pointers to the two
         * 1024-byte blocks that will be read by G() as its input, and a pointer
         * to the 1024-byte block that G() will transform.
         * They are of type block1024_t*
         */

        /* j is the index of the block we're about to transform in this loop
         * cycle RELATIVE TO THE START OF THE CURRENT LANE in Argon2 matrix B.
         */
        G_input_one = (B[0] + (cur_lane*q)) + (j-1);
        G_output    = (B[0] + (cur_lane*q)) + (j);

        /* On the other hand, z is the index of the block we feed as second
         * input to G() RELATIVE TO THE START OF B[][] ITSELF!! Not relative
         * to the start of lane l_ix. l_ix was already taken into account
         * when computing index z.
         */
        G_input_two = B[0] + z_ix;
        argon2_g((u8*)G_input_one, (u8*)G_input_two, (u8*)G_output);
        ++computed_blocks;
    }

label_finish_segment:

    free(J1J2blockpool);
    return NULL;
}

/* The top-level function that any code using Argon2id will call.
 *
 * For now only the first pass of Argon2id is implemented. This is sufficient
 * for the purposes of the Rosetta Security Scheme.
 */
void Argon2_MAIN(struct Argon2_parms* parms, uint8_t* output_tag)
{
    void**        thread_inputs;
    pthread_t*    argon2_thread_ids;
    block1024_t** B;

    /* Input size to the generator of 64-byte H0. The generator is Blake2B. */
    u64 H0_input_len =   (10 * sizeof(u32)) + parms->len_P + parms->len_S
                       + parms->len_K + parms->len_X;

    /* How many 1024-byte blocks are in the Argon2 matrix B[][]. */
    u64 m_dash = 4 * parms->p * floor(parms->m / (4 * parms->p));

    /* How many columns are in the Argon2 matrix B[][]. Doubles as the size of
     * one row, counted in 1024-byte blocks. Each column intersecting a row is
     * one 1024-byte block.
     */
    u64 q = m_dash / parms->p;

    /* Input to the generator of 64-byte H0. The generator is Blake2B. */
    u8* H0_input = (u8*)calloc(1, H0_input_len);
    PRINT_ERR_AND_EXIT_IF_NULL_PTR(H0_input,
        "[ERR] Heap alloc in Argon2_MAIN for H0_input failed: ")

    u8  final_block_C[sizeof(block1024_t)];
    u8  H0[64];
    u8* working_memory;
    u8  B_init_buf[64 + 4 + 4];
    u32 zero = 0;
    u32 one = 1;
    u64 r = 0;
    size_t H0_in_offset;
    size_t thread_in_offset;

    if(parms->t != 1)
    {
        printf("[ERR] Cryptolib: Argon2 input parameter t (number of passes) "
               "must be 1.\n");
        exit(1);
    }
    /* Construct the input buffer to H{64}() that generates 64-byte H0.
     * The order has to be exactly as specified in the RFC.
     */
    memcpy(H0_input +  0, &(parms->p),     4);
    memcpy(H0_input +  4, &(parms->T),     4);
    memcpy(H0_input +  8, &(parms->m),     4);
    memcpy(H0_input + 12, &(parms->t),     4);
    memcpy(H0_input + 16, &(parms->v),     4);
    memcpy(H0_input + 20, &(parms->y),     4);
    memcpy(H0_input + 24, &(parms->len_P), 4);

    H0_in_offset = 28;

    memcpy((H0_input + H0_in_offset), parms->P, parms->len_P);
    H0_in_offset += parms->len_P;

    memcpy(H0_input + H0_in_offset, &(parms->len_S), 4);
    H0_in_offset += 4;

    memcpy((H0_input + H0_in_offset), parms->S, parms->len_S);
    H0_in_offset += parms->len_S;

    memcpy(H0_input + H0_in_offset, &(parms->len_K), 4);
    H0_in_offset += 4;

    if(parms->len_K)
    {
        memcpy((H0_input + H0_in_offset), parms->K, parms->len_K);
        H0_in_offset += parms->len_K;
    }

    memcpy(H0_input + H0_in_offset, &(parms->len_X), 4);
    H0_in_offset += 4;

    if(parms->len_X)
    {
        memcpy((H0_input + H0_in_offset), parms->X, parms->len_X);
        H0_in_offset += parms->len_X;
    }

    /* The offset also tells us the total length of the input to H{64}(). */

    /* Generate H_0 now. */
    blake2b_init(H0_input, H0_in_offset, 0, 64, H0);

    /* Construct the working memory of Argon2 now. */

    /* The best we can do to help simplify the pointer arithmetic here is to
     * set a pointer to each row of the Argon2 matrix B[][]. Each row consists
     * of many 1024-byte blocks, but at least we will be able to directly use
     * the [index] notation when accessing B[][] for the "get to row X" part
     * as described in the Argon2 RFC specification, ie the index in B[i][j].
     *
     * For the second index where B[][] is used in the specification, we will
     * use a specially defined struct that only has a 1024-byte array in it
     * and typedef'd as block1024_t. This changes the hidden multiplier
     * of the compiler's pointer arithmetic to (* 1024), making the pointer
     * arithmetic code for accessing parts of Argon2 matrix B[][] more elegant.
     */

    /* Allocate the working memory matrix of Argon2. */
    working_memory = (u8*)calloc(1, m_dash * sizeof(block1024_t));
    PRINT_ERR_AND_EXIT_IF_NULL_PTR(working_memory,
        "[ERR] Heap alloc in Argon2_MAIN for working_memory failed: ")

    /* Split the memory matrix into p rows by setting pointers to the
     * start of each row. A row has many 1024-byte blocks.
     */
    B = (block1024_t**)calloc(1, parms->p * sizeof(block1024_t*));
    PRINT_ERR_AND_EXIT_IF_NULL_PTR(B,
        "[ERR] Heap alloc in Argon2_MAIN for B failed: ")

    /* Set a pointer to the start of each row in Argon2 matrix B[][]. */
    for(uint64_t i = 0; i < parms->p; ++i){
        B[i] = (block1024_t*)(working_memory + (i * (q * sizeof(block1024_t))));
    }

    /* Now where B[x][y] is used in the RFC specification, here in this
     * implementation it too can be written as B[x][y], which would mean
     * to the compiler:
     *
     * 1. Start from the contents of memory address B, wherein is a pointer to
     *    a 1024-byte block, followed by more pointers to such blocks. Each
     *    pointer here is the START OF A ROW in the Argon2 matrix B[][].
     *
     * 2. Go +x such pointers into B, to get to the actual row x in the Argon2
     *    matrix B[][].
     *
     * 3. From this pointer to a 1024-byte block, go +y such blocks, to the
     *    exact 1024-byte block we need and dereference the pointer to it to
     *    access the 1024-byte block that we need.
     *
     * All while keeping the entire memory (all p rows of 1024-byte blocks)
     * of the Argon2 matrix B[][] contiguous in the process memory as required
     * by the RFC spec.
     */
    memcpy(B_init_buf + 0 , H0, 64);
    memcpy(B_init_buf + 64, &zero, 4);

    for(uint32_t i = 0; i < parms->p; ++i)
    {
        memcpy(B_init_buf + 64 + 4, &i, 4);
        argon2_h_dash(B_init_buf, (uint8_t*)&(B[i][0]), 1024, (64+4+4));
    }

    memcpy(B_init_buf + 64, &one, 4);

    for(uint32_t i = 0; i < parms->p; ++i)
    {
        memcpy(B_init_buf + 64 + 4, &i, 4);
        argon2_h_dash(B_init_buf, (uint8_t*)&(B[i][1]), 1024, (64+4+4));
    }

    /* Counter that keeps track of which Argon2 pass we are currently on. */
    r = 0;

    /* Each of the 4 vertical slices is computed and finished before the next
     * slice's threads can begin. All threads process their 1/4 row in that
     * slice in parallel.
     */

    /* Create p thread_id's - one for each thread we will run. */
    argon2_thread_ids = (pthread_t*)calloc(1, parms->p * sizeof(pthread_t));
    PRINT_ERR_AND_EXIT_IF_NULL_PTR(argon2_thread_ids,
        "[ERR] Heap alloc in Argon2_MAIN for argon2_thread_ids failed: ")

    /* Offset into the input buffer for the Argon2 thread function. */
    thread_in_offset = 0;

    /* Allocate input buffers for each thread.                    */
    /* Each input buffer will contain a pointer and 8 uint64_t's. */
    thread_inputs = (void**)calloc(1, parms->p * sizeof(void*));
    PRINT_ERR_AND_EXIT_IF_NULL_PTR(thread_inputs,
        "[ERR] Heap alloc in Argon2_MAIN for thread_inputs failed: ")

    for(uint32_t i = 0; i < parms->p; ++i)
    {
        thread_inputs[i] =
            calloc(1, sizeof(block1024_t*) + (8*sizeof(uint64_t)));
            PRINT_ERR_AND_EXIT_IF_NULL_PTR(thread_inputs[i],
                "[ERR] Heap alloc in Argon2_MAIN for thread_inputs[i] failed: ")
    }

label_start_pass:

    for (uint64_t sl = 0; sl < 4; ++sl)  /* slice number. */
    {
        for(uint64_t i = 0; i < parms->p; ++i)  /* lane/thread number. */
        {
            /*  This loop starts a thread for EACH ROW of 1024-byte blocks in
             *  the Argon2 matrix B[][]. Using 2 GiB memory for Argon2id, this
             *  means 21845 1024-byte blocks processed by each thread.
             *
             *  Each thread will call G() in a for-loop going over each
             *  1024-block in that segment of Argon2 matrix B[][].
             *
             *  For that reason, each thread will need INPUT:
             *
             *  - Pointer to the segment to be transformed by that thread, based
             *    on which we will take G()'s input/output 1024-byte blocks.
             *
             *  - Parameters that are constant during a thread's operatrion for
             *    computing J_1 and J_2 for Argon2i: r, l, sl, m', t, y, p, q
             *
             *  Lastly, a loop will join all threads before the the next set of
             *  threads can be started on the next vertical slice (a set of
             *  segments, each of which is a set of 1024-byte blocks of the
             *  Argon2 matrix B[][]).
             */

            /* Populate this thread's input buffer. */

            /* Offset in bytes into the thread's input buffer. */
            thread_in_offset = 0;

            /* First is a pointer to the start of the Argon2 matrix B[][]. */
            memcpy(((u8*)(thread_inputs[i])) + thread_in_offset, &B,
                   sizeof(block1024_t**));
            thread_in_offset += sizeof(block1024_t**);

            /* Second is r, the current pass number. */
            memcpy(((u8*)(thread_inputs[i])) + thread_in_offset, &r, sizeof(r));
            thread_in_offset += sizeof(r);

            /* Third is l, the current lane number. */
            memcpy(((u8*)(thread_inputs[i])) + thread_in_offset, &i, sizeof(i));
            thread_in_offset += sizeof(i);

            /* Fourth is sl, the current slice number. */
            memcpy(((u8*)(thread_inputs[i])) + thread_in_offset, &sl,
                   sizeof(sl));
            thread_in_offset += sizeof(sl);

            /* Fifth is m', the total number of 1024-byte blocks in the Argon2
             * matrix B[][].
             */
            memcpy(((u8*)(thread_inputs[i])) + thread_in_offset, &m_dash,
                   sizeof(m_dash));
            thread_in_offset += sizeof(m_dash);

            /* Sixth is t, the total number of passes. Always 1 for now. */
            memcpy(((u8*)(thread_inputs[i])) + thread_in_offset, &(parms->t),
                   sizeof(parms->t));
            thread_in_offset += sizeof(parms->t);

            /* Seventh is y, the Argon2 type. Specified by the RFC. */
            memcpy(((u8*)(thread_inputs[i])) + thread_in_offset, &(parms->y),
                   sizeof(parms->y));
            thread_in_offset += sizeof(parms->y);

            /* Eighth is p, the total number of threads Argon2 should use. */
            memcpy(((u8*)(thread_inputs[i])) + thread_in_offset, &(parms->p),
                   sizeof(parms->p));
            thread_in_offset += sizeof(parms->p);

            /* Ninth and last is q, the total number of 1024-byte blocks in 1
             * row (aka the total number of block-sized columns) in the Argon2
             * matrix B[][].
             */
            memcpy(((u8*)(thread_inputs[i])) + thread_in_offset, &q, sizeof(q));
            thread_in_offset += sizeof(q);

            /* Now that the input buffer for this thread is ready, start it. */
            pthread_create(&(argon2_thread_ids[i]), NULL,
                           argon2_transform_segment, thread_inputs[i]);
        }

        /* After the previous loop starts all threads, this loop joins them.
         * All segments of this slice of the Argon2 matrix B[][] must finish
         * before any thread can start processing its segment in the next
         * vertical slice of B[][].
         */
        for(uint64_t i = 0; i < parms->p; ++i)
            pthread_join(argon2_thread_ids[i], NULL);

        printf("------------- ARGON2: Slice %lu finished. -------------\n", sl);
    } /* End of one vertical slice of B[][]. */

    /* Finished all 4 vertical slices for a pass. Increment pass number.*/
    ++r;

    /* If Argon2 is to perform more than the zeroth pass, do them.
     *
     * NOTE: For now, I only implement one-pass Argon2id.
     */
    //if (r < parms->t)
    //    goto label_start_pass;


    /* Done with all required passes. Compute the final 1024-byte block C by
     * XORing the last block of every lane in B[][].
     */
    memcpy(final_block_C, &(B[0][q-1]), 1024);

    for(size_t ln = 1; ln < parms->p; ++ln)
    {
        uint64_t* aux_ptr64_finalblock = (uint64_t*)final_block_C;
        uint64_t* aux_ptr64_lastcolblk = (uint64_t*)(&(B[ln][q-1]));
        for(size_t xr = 0; xr < 128; ++xr)
        {
           aux_ptr64_finalblock[xr] ^= aux_ptr64_lastcolblk[xr];
        }
    }

    /* Finally, feed the final block C to function H' producing Tag-length bytes
     * of Argon2 output hash.
     */
    argon2_h_dash(final_block_C, output_tag, parms->T, 1024);

    /* Cleanup. */
    for(uint32_t i = 0; i < parms->p; ++i)
        free(thread_inputs[i]);

    free(thread_inputs);
    free(B);
    free(working_memory);
    free(H0_input);
    free(argon2_thread_ids);
    return;
}

/* Generate a Schnorr cryptographic signature from a message, according to the
 * method pioneered by Claus-Peter Schnorr. A signature validated by the
 * receiver ensures that the payload really was sent by the intended sender and
 * that the payload was not modified en route - authenticity.
 *
 * Algorithm for generating a new Schnorr signature:
 *
 * PH = BLAKE2B{64}(data);
 *  k = (BLAKE2B{64}(a || PH) mod (Q - 1)) + 1;
 *  R = G^k mod M;
 *  e = trunc{bitwidth(Q)}(BLAKE2B{64}(R || PH));
 *  s = ((k - (a * e)) mod Q;
 *
 * where M is the Diffie-Hellman modulus, Q is the prime order that exactly
 * divides (M - 1) and the generator G = 2^((M - 1) / Q) mod M,
 * and a is the private key of the message sender.
 *
 * The resulting signature itself is made up of two components (s, e).
 */
void signature_generate
    (bigint* M, bigint* Q, bigint* Gmont, u8* data, u64 data_len, u8* signature,
     bigint* private_key, u64 key_len_bytes)
{
    u32       offset = 0;
    bigint    second_btb_outnum;
    bigint    one;
    bigint    Q_minus_one;
    bigint    reduced_btb_res;
    bigint    k;
    bigint    R;
    bigint    e;
    bigint    s;
    bigint    div_res;
    bigint    aux1;
    bigint    aux2;
    bigint    aux3;
    const u64 prehash_len = 64;
    u64       len_key_PH = prehash_len + key_len_bytes;
    u64       R_used_bytes;
    u64       len_Rused_PH;
    u8        second_btb_outbuf[64];
    u8        prehash[prehash_len];
    u8*       second_btb_inbuf;
    u8*       R_with_prehash;
    u8        third_btb_outbuf[64];

    bigint_create_from_u32(&second_btb_outnum, M->size_bits, 0);
    bigint_create_from_u32(&Q_minus_one,       M->size_bits, 0);
    bigint_create_from_u32(&reduced_btb_res,   M->size_bits, 0);
    bigint_create_from_u32(&div_res,           M->size_bits, 0);
    bigint_create_from_u32(&one,               M->size_bits, 1);
    bigint_create_from_u32(&k,                 M->size_bits, 0);
    bigint_create_from_u32(&R,                 M->size_bits, 0);
    bigint_create_from_u32(&e,                 M->size_bits, 0);
    bigint_create_from_u32(&s,                 M->size_bits, 0);
    bigint_create_from_u32(&aux1,              M->size_bits, 0);
    bigint_create_from_u32(&aux2,              M->size_bits, 0);
    bigint_create_from_u32(&aux3,              M->size_bits, 0);

    /* Compute prehash PH = BLAKE2B{64}(data) */
    memset(prehash, 0, prehash_len);
    blake2b_init(data, data_len, 0, prehash_len, prehash);

    second_btb_inbuf = (u8*)calloc(1, key_len_bytes + prehash_len);
    PRINT_ERR_AND_EXIT_IF_NULL_PTR(second_btb_inbuf,
        "[ERR] Heap alloc in signature_generate for second_btb_inbuf failed: ")

    memcpy(second_btb_inbuf, private_key->bits, key_len_bytes);
    memcpy(second_btb_inbuf + key_len_bytes, prehash, prehash_len);
    blake2b_init(second_btb_inbuf, len_key_PH, 0, 64, second_btb_outbuf);

    /* Compute k = (BLAKE2B{64}(a || PH) mod (Q - 1)) + 1 */
    memcpy(second_btb_outnum.bits, second_btb_outbuf, 64);
    second_btb_outnum.used_bits = get_used_bits(second_btb_outnum.bits, 64);
    bigint_sub_fast(Q, &one, &Q_minus_one);
    bigint_div2(&second_btb_outnum, &Q_minus_one, &div_res, &reduced_btb_res);
    bigint_add_fast(&reduced_btb_res, &one, &k);

    /* Compute R = G^k mod M */
    mont_pow_mod_m(Gmont, &k, M, &R);

    R_used_bytes = R.used_bits;
    while(R_used_bytes % 8 != 0)
        ++R_used_bytes;

    R_used_bytes /= 8;

    /* Compute e = trunc{bitwidth(Q)}(BLAKE2B{64}(R || PH)) */
    R_with_prehash = (u8*)calloc(1, R_used_bytes + prehash_len);
    PRINT_ERR_AND_EXIT_IF_NULL_PTR(R_with_prehash,
        "[ERR] Heap alloc in signature_generate for R_with_prehash failed: ")

    memcpy(R_with_prehash, R.bits, R_used_bytes);
    memcpy(R_with_prehash + R_used_bytes, prehash, prehash_len);
    len_Rused_PH = R_used_bytes + prehash_len;
    blake2b_init(R_with_prehash, len_Rused_PH, 0, 64, third_btb_outbuf);
    memcpy(e.bits, third_btb_outbuf, DH_Q_BITWIDTH / 8);
    e.used_bits = get_used_bits(e.bits, DH_Q_BITWIDTH / 8);

    /* Compute s = ((k - (a * e)) mod Q */
    bigint_sub_fast(Q, private_key, &aux1);
    bigint_mul_fast(&aux1, &e, &aux2);
    bigint_add_fast(&aux2, &k, &aux3);
    bigint_div2(&aux3, Q, &div_res, &s);

    /* Output buffer of size ( (2 * sizeof(bigint)) + (2 * bytewidth(Q)) )
     * bytes must have been preallocated.
     */
    memcpy(signature + offset, &s, sizeof(bigint));
    offset += sizeof(bigint);
    memcpy(signature + offset, s.bits, DH_Q_BITWIDTH / 8);
    offset += DH_Q_BITWIDTH / 8;
    memcpy(signature + offset, &e, sizeof(bigint));
    offset += sizeof(bigint);
    memcpy(signature + offset, e.bits, DH_Q_BITWIDTH / 8);

    /* Cleanup. */
    bigint_cleanup(&second_btb_outnum);
    bigint_cleanup(&one);
    bigint_cleanup(&Q_minus_one);
    bigint_cleanup(&reduced_btb_res);
    bigint_cleanup(&k);
    bigint_cleanup(&R);
    bigint_cleanup(&s);
    bigint_cleanup(&div_res);
    bigint_cleanup(&aux1);
    bigint_cleanup(&aux2);
    bigint_cleanup(&aux3);
    bigint_cleanup(&e);
    free(second_btb_inbuf);
    free(R_with_prehash);
    return;
}

/* To validate a signature using public key A and whatever was signed using its
 * corresponding private key a, the receiver:
 *
 *  0. checks that 0 <= s < Q, and that e has the expected bitwidth (that of Q).
 *  1. Computes the prehash PH as in the first step of signature generation.
 *  2. Computes R = (G^s * A^e) mod M.
 *  3. Computes BLAKE2B{64}(R||PH), truncated to bitwidth of Q.
 *     Check that this is equal to e. If it is, validation passed.
 *     Under any other circumstance, validation fails.
 *
 *   RETURNS: 0 if signature is valid, 1 if it's invalid.
 */

/* ------------------------ PERFORMANCE PROFILING --------------------------- */
#define MAX_TIMEPOINTS 500
#define NR_TIMEPOINTS_TO_WRITE_AT 500
size_t  nr_timepoints = 0;
double  measurements[MAX_TIMEPOINTS];
FILE*   measurements_fd;
size_t  profiling_ret;
/* -------------------------------------------------------------------------- */
uint8_t signature_validate(bigint* Gmont, bigint* Amont, bigint* M, bigint* Q,
                           bigint* s, bigint* e, u8* data, u32 data_len)
{
    const u64 prehash_len = 64;
    u64       R_used_bytes;
    u64       len_Rused_PH;
    u8        retval = 0;
    u8        prehash[prehash_len];
    u8*       R_with_prehash = NULL;
    u8        blake2b_outbuf[64];
    bigint    R;
    bigint    R_aux1;
    bigint    R_aux2;
    bigint    R_aux3;
    bigint    div_res;
    bigint    val_e;

    memset(prehash, 0, prehash_len);

    bigint_create_from_u32(&R,       M->size_bits, 0);
    bigint_create_from_u32(&R_aux1,  M->size_bits, 0);
    bigint_create_from_u32(&R_aux2,  M->size_bits, 0);
    bigint_create_from_u32(&R_aux3,  M->size_bits, 0);
    bigint_create_from_u32(&div_res, M->size_bits, 0);
    bigint_create_from_u32(&val_e,   M->size_bits, 0);

    if(bigint_compare2(s, Q) != CMP_SECOND_BIGGER)
    {
        printf("[WARN] Cryptolib: sig_validate: input s != input Q.\n");
        retval = 1;
        goto label_cleanup;
    }

    /* Compute the signature validation prehash. Same as during generation. */
    blake2b_init(data, data_len, 0, prehash_len, prehash);

    /* Performance profiling. */
    struct timespec tv1, tv2;

    /* The old way with 2 calls to montgomery modular powering back to back. */

    //clock_gettime(CLOCK_MONOTONIC_RAW, &tv1)
    //mont_pow_mod_m(Gmont, s, M, &R_aux1);
    //clock_gettime(CLOCK_MONOTONIC_RAW, &tv2);

    //clock_gettime(CLOCK_MONOTONIC_RAW, &tv1)
    //mont_pow_mod_m(Amont, e, M, &R_aux2);
    //clock_gettime(CLOCK_MONOTONIC_RAW, &tv2);

    /* Use the new interleaved montgomery modular powering. It proved to boost
     * instruction-level parallelism, lowering signature validation latency
     * by 10%
     */
    clock_gettime(CLOCK_MONOTONIC_RAW, &tv1);
    dual_mont_pow_mod_m(Gmont, s, M, &R_aux1, Amont, e, M, &R_aux2);
    clock_gettime(CLOCK_MONOTONIC_RAW, &tv2);

    //clock_gettime(CLOCK_MONOTONIC_RAW, &tv1);

    bigint_mul_fast(&R_aux1, &R_aux2, &R_aux3);

    //clock_gettime(CLOCK_MONOTONIC_RAW, &tv2);

    bigint_div2(&R_aux3, M, &div_res, &R);

    if( __builtin_expect (tv2.tv_nsec > tv1.tv_nsec, true))
    {
        measurements[nr_timepoints++] =
            ((tv2.tv_nsec - tv1.tv_nsec) / (double)1000.0);

        if( __builtin_expect
                (nr_timepoints == NR_TIMEPOINTS_TO_WRITE_AT, false))
        {
            measurements_fd = fopen
                          ("./performance-analysis/last-measurements.dat", "w");

            if(measurements_fd == NULL)
            {
                printf("[ERR] Crypt: Could not open measurements file.\n");
                exit(1);
            }
            profiling_ret = fwrite(measurements, 1,
                                   nr_timepoints * sizeof(double),
                                   measurements_fd);

            if(profiling_ret != nr_timepoints * sizeof(double))
            {
                printf("[ERR] Crypt: Write to measurements file failed.\n");
                fclose(measurements_fd);
                exit(1);
            }
            else
            {
                printf("\n[OK]  Crypt: Wrote measurements %lu bytes.\n\n",
                       nr_timepoints * sizeof(double));

                fclose(measurements_fd);
            }
            memset(measurements, 0x00, MAX_TIMEPOINTS * sizeof(double));
            nr_timepoints = 0;
        }
    }

    R_used_bytes = R.used_bits;

    while(R_used_bytes % 8 != 0)
        ++R_used_bytes;

    R_used_bytes /= 8;

    /* Last step of signature validation:
     * Computes val_e = BLAKE2B{64}(R||PH), truncated to bitwidth of Q.
     * Check that this is equal to e. If it is, validation has passed.
     */
    R_with_prehash = (u8*)calloc(1, R_used_bytes + prehash_len);
    PRINT_ERR_AND_EXIT_IF_NULL_PTR(R_with_prehash,
        "[ERR] Heap alloc in signature_validate for R_with_prehash failed: ")

    memcpy(R_with_prehash, R.bits, R_used_bytes);
    memcpy(R_with_prehash + R_used_bytes, prehash, prehash_len);
    len_Rused_PH = R_used_bytes + prehash_len;
    blake2b_init(R_with_prehash, len_Rused_PH, 0, 64, blake2b_outbuf);
    memcpy(val_e.bits, blake2b_outbuf, DH_Q_BITWIDTH / 8);
    val_e.used_bits = get_used_bits(val_e.bits, DH_Q_BITWIDTH / 8);

    if( __builtin_expect( (bigint_compare2(e, &val_e) != CMP_EQUALS), false) )
    {
        printf("[WARN] Cryptolib: SIG_VAL: val_e != passed e. Ret 0.\n");
        printf("Passed e:\n");
        bigint_print_info(e);
        bigint_print_bits(e);
        printf("Computed val_e:\n");
        bigint_print_info(&val_e);
        bigint_print_bits(&val_e);
        retval = 1;
    }

label_cleanup:

    bigint_cleanup(&R);
    bigint_cleanup(&R_aux1);
    bigint_cleanup(&R_aux2);
    bigint_cleanup(&R_aux3);
    bigint_cleanup(&div_res);
    bigint_cleanup(&val_e);
    free(R_with_prehash);
    return retval;
}

/* Generate a new pseudorandom private key. */
uint8_t gen_priv_key(uint32_t len_bytes, uint8_t* buf)
{
    size_t bytes_read;
    FILE* rand_fd = fopen(DEV_URANDOM_PATH, "r");

    if(rand_fd == NULL)
    {
        printf("[ERR] Cryptolib: gen_priv_key - couldn't open urandom.\n\n");
        return 1;
    }
    if ( (bytes_read = fread((void*)buf, 1, len_bytes, rand_fd)) != len_bytes )
    {
        printf("[ERR] Cryptolib: gen_priv_key - couldn't read %u bytes "
               "from urandom.\n\n", len_bytes);
        perror("Error type: ");
        fclose(rand_fd);
        return 1;
    }

    /* Set the most significant bit to 0 to make sure the private key is always
     * less than Diffie-Hellman prime order Q.
     */
    *(buf + (len_bytes - 1)) &= ~ (1 << 7);

    printf("[OK] Cryptolib: Generated a %u-byte private key!\n\n", len_bytes);
    fclose(rand_fd);
    return 0;
}

/* Given a private key, generate its corresponding public key. */
struct bigint* gen_pub_key(bigint* privkey_bigint)
{
    u8 err = 0;

    bigint* M = get_bigint_from_dat
                    (DH_MODULUS_M_PATH, DH_M_BITWIDTH, MAX_USED_BITWIDTH);

    bigint* Gm = get_bigint_from_dat
                     (DH_G_MONT_PATH, DH_G_MONT_BITWIDTH, MAX_USED_BITWIDTH);

    bigint* R = (bigint*)calloc(1, sizeof(struct bigint));
    PRINT_ERR_AND_EXIT_IF_NULL_PTR(R,
        "[ERR] Heap alloc in gen_pub_key for R (emitted key bigint) failed: ")

    bigint_create_from_u32(R, M->size_bits, 0);
    mont_pow_mod_m(Gm, privkey_bigint, M, R);

label_cleanup:

    bigint_cleanup(M);
    bigint_cleanup(Gm);
    free(M);
    free(Gm);

    if(err)
    {
        printf("Generating a new public key encountered an error.\nCleaned "
                "everything up. Terminating now.\n");
        exit(1);
    }
    return R;
}

/* Check that a public key is of the correct form. The exact check is:
 *
 *  pub_key^(M/Q) mod M == 1
 *
 *  Return 1 for valid and 0 for invalid public key form.
 */
bool check_pubkey_form(bigint* Km, bigint* M, bigint* Q)
{
    bigint M_over_Q;
    bigint one;
    bigint div_rem;
    bigint mod_pow_res;
    bool   ret = 0;

    bigint_create_from_u32(&M_over_Q,    12800, 0);
    bigint_create_from_u32(&one,         12800, 1);
    bigint_create_from_u32(&div_rem,     12800, 0);
    bigint_create_from_u32(&mod_pow_res, 12800, 0);

    bigint_div2(M, Q, &M_over_Q, &div_rem);
    mont_pow_mod_m(Km, &M_over_Q, M, &mod_pow_res);

    if(bigint_compare2(&mod_pow_res, &one) != CMP_EQUALS)
    {
        printf("[ERR] Public key didn't pass (pub_key^(M/Q) mod M == 1)\n\n");
        ret = 1;
    }

    bigint_cleanup(&M_over_Q);
    bigint_cleanup(&one);
    bigint_cleanup(&div_rem);
    bigint_cleanup(&mod_pow_res);
    return ret;
}
