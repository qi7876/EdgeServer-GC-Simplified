/**
 * @file compressGen.h
 * @author Zuoru YANG (zryang@cse.cuhk.edu.hk)
 * @brief lz datagen - LZ data generator
 * @version 0.1
 * @date 2021-09-04
 *
 * @copyright Copyright (c) 2021
 *
 */

#ifndef COMPRESS_GEN_H
#define COMPRESS_GEN_H

#include "define.h"
#include "constVar.h"
#include <cstring>
#include <unordered_map>

// limits for length values, based on zlib
// #define MIN_LEN 1
#define MIN_LEN 3
// #define MAX_LEN 100
#define MAX_LEN 160

#define NUM_LEN (MAX_LEN - MIN_LEN + 1)

// Number of lengths to generate at a time
#define LEN_PER_CHUNK 512
// #define LEN_PER_CHUNK 128

#define COMPRESSION_SET_SIZE 21

struct pcg_state_setseq_64 { // Internals are *Private*.
    uint64_t state; // RNG state.  All values are possible.
    uint64_t inc; // Controls which RNG sequence (stream) is
                  // selected. Must *always* be odd.
};
typedef struct pcg_state_setseq_64 pcg32_random_t;

// If you *must* statically initialize it, here's one.

#define PCG32_INITIALIZER { 0x853c49e6748fea9bULL, 0xda3e39cb94b95bdbULL }

using namespace std;

class CompressGen {
private:
    pcg32_random_t pcg32_global_ = PCG32_INITIALIZER;
    inline void pcg32_srandom_r(pcg32_random_t* rng, uint64_t initstate, uint64_t initseq)
    {
        rng->state = 0U;
        rng->inc = (initseq << 1u) | 1u;
        pcg32_random_r(rng);
        rng->state += initstate;
        pcg32_random_r(rng);
    }

    inline void pcg32_srandom(uint64_t seed, uint64_t seq)
    {
        pcg32_srandom_r(&pcg32_global_, seed, seq);
    }

    inline uint32_t pcg32_random_r(pcg32_random_t* rng)
    {
        uint64_t oldstate = rng->state;
        rng->state = oldstate * 6364136223846793005ULL + rng->inc;
        uint32_t xorshifted = ((oldstate >> 18u) ^ oldstate) >> 27u;
        uint32_t rot = oldstate >> 59u;
        return (xorshifted >> rot) | (xorshifted << ((-rot) & 31));
    }

    inline uint32_t pcg32_random()
    {
        return pcg32_random_r(&pcg32_global_);
    }

    uint32_t pcg32_boundedrand_r(pcg32_random_t* rng, uint32_t bound)
    {
        uint32_t threshold = -bound % bound;
        for (;;) {
            uint32_t r = pcg32_random_r(rng);
            if (r >= threshold)
                return r % bound;
        }
    }

    uint32_t pcg32_boundedrand(uint32_t bound)
    {
        return pcg32_boundedrand_r(&pcg32_global_, bound);
    }

    inline double RandDouble()
    {
        return pcg32_random() / (UINT32_MAX + 1.0);
    }

    /**
     * @brief generate random literals
     *
     * @param ptr the pointer to the where to store literals
     * @param size the number of literal to generate
     */
    void GenerateLiterals(uint8_t* ptr, size_t size);

    /**
     * @brief gnerate random lengths
     * Generate length frequencies following a power distribution. If `len_exp` is
     * 1.0, the distribution is linear. As `len_exp` grows, the likelihood of small
     * values increases.
     *
     * @param len_freq pointers to where to store length frequencies
     * @param num the number of the lengths to generate
     */
    void GenerateLengths(uint32_t* len_freq, size_t num);

    /**
     * @brief generate compressible data
     * Data is generated by inserting sequences of either random bytes or
     * repetitions from a buffer of bytes, depending on the ratio parameter.
     *
     * @param ptr pointer to where to store generated data
     * @param size number of bytes to generate
     * @param ratio desired compression ratio
     */
    void LZGenerateData(uint8_t* ptr, size_t size, double ratio);

    double len_exp_;
    double lit_exp_;

    unordered_map<uint32_t, uint8_t*> compressBlockSet_;

public:
    /**
     * @brief Construct a new Compress Gen object
     *
     * @param len_exp exponent used for distribution of lengths
     * @param lit_exp exponent used for distribution of literals
     * @param seed for seed
     */
    CompressGen(double len_exp, double lit_exp, int seed);

    /**
     * @brief Destroy the Compress Gen object
     *
     */
    ~CompressGen();

    /**
     * @brief generate the compressible data
     *
     * @param buffer the buffer to store the
     * @param compressionRatio the compression ratio
     * @param size the expected chunk size
     */
    void GenerateCompressibleData(uint8_t* buffer, double compressionRatio, size_t size);

    /**
     * @brief generate the compressible chunk from the candidate set
     *
     * @param chunkBuffer the pointer to the chunk buffer
     * @param compressionInt the compression ratio int
     * @param chunkSize the chunk size
     */
    void GenerateChunkFromCanditdateSet(uint8_t* chunkBuffer, uint32_t compressionInt, size_t chunkSize);
};

#endif