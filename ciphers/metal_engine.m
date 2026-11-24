// =============================================================================
// Trithemius Cryptanalytic Metal GPU & Apple Accelerate Compute Engine
// Optimized for Apple Silicon (M-Series: M1/M2/M3/M4) Unified Memory Architecture
// =============================================================================

#import <Foundation/Foundation.h>
#import <Metal/Metal.h>
#import <Accelerate/Accelerate.h>

static id<MTLDevice> g_device = nil;
static id<MTLCommandQueue> g_queue = nil;
static id<MTLComputePipelineState> g_pipe_score_keys = nil;
static id<MTLComputePipelineState> g_pipe_sweep_2words = nil;
static id<MTLComputePipelineState> g_pipe_sweep_3words = nil;
static id<MTLComputePipelineState> g_pipe_surrogate = nil;

static NSString *const kMetalSource = @""
"#include <metal_stdlib>\n"
"using namespace metal;\n"
"\n"
"struct WordMeta {\n"
"    uint offset;\n"
"    uint length;\n"
"};\n"
"\n"
"// 1. Batch T-Table Key Scoring Kernel\n"
"kernel void score_keys_kernel(\n"
"    device const float *t_table        [[buffer(0)]], // m * 29\n"
"    device const uchar *keys           [[buffer(1)]], // num_keys * period\n"
"    device float *scores               [[buffer(2)]], // num_keys\n"
"    constant uint &period              [[buffer(3)]],\n"
"    constant uint &num_keys            [[buffer(4)]],\n"
"    uint id                            [[thread_position_in_grid]])\n"
"{\n"
"    if (id >= num_keys) return;\n"
"    float sum = 0.0f;\n"
"    uint base = id * period;\n"
"    for (uint j = 0; j < period; ++j) {\n"
"        uchar c = keys[base + j] % 29;\n"
"        sum += t_table[j * 29 + c];\n"
"    }\n"
"    scores[id] = sum / float(period);\n"
"}\n"
"\n"
"// 2. Parallel 2-Word Compound Phrase Sweep Kernel\n"
"kernel void sweep_2words_kernel(\n"
"    device const float *t_table        [[buffer(0)]], // m * 29\n"
"    device const uchar *words_chars     [[buffer(1)]], // flat char array\n"
"    device const WordMeta *word_metas  [[buffer(2)]], // num_words\n"
"    constant uint &num_words           [[buffer(3)]],\n"
"    constant uint &period              [[buffer(4)]],\n"
"    constant float &threshold          [[buffer(5)]],\n"
"    constant uint &max_hits            [[buffer(6)]],\n"
"    device atomic_uint *hit_count      [[buffer(7)]],\n"
"    device uint2 *out_pairs            [[buffer(8)]],\n"
"    device float *out_scores           [[buffer(9)]],\n"
"    uint id                            [[thread_position_in_grid]])\n"
"{\n"
"    uint total_pairs = num_words * num_words;\n"
"    if (id >= total_pairs) return;\n"
"\n"
"    uint i = id / num_words;\n"
"    uint j = id % num_words;\n"
"\n"
"    WordMeta w1 = word_metas[i];\n"
"    WordMeta w2 = word_metas[j];\n"
"    uint comb_len = w1.length + w2.length;\n"
"    if (comb_len == 0) return;\n"
"\n"
"    float sum = 0.0f;\n"
"    for (uint k = 0; k < period; ++k) {\n"
"        uint p_idx = k % comb_len;\n"
"        uchar c;\n"
"        if (p_idx < w1.length) {\n"
"            c = words_chars[w1.offset + p_idx];\n"
"        } else {\n"
"            c = words_chars[w2.offset + (p_idx - w1.length)];\n"
"        }\n"
"        sum += t_table[k * 29 + (c % 29)];\n"
"    }\n"
"    float score = sum / float(period);\n"
"\n"
"    if (score >= threshold) {\n"
"        uint slot = atomic_fetch_add_explicit(hit_count, 1, memory_order_relaxed);\n"
"        if (slot < max_hits) {\n"
"            out_pairs[slot] = uint2(i, j);\n"
"            out_scores[slot] = score;\n"
"        }\n"
"    }\n"
"}\n"
"\n"
"// 3. Parallel 3-Word Compound Phrase Sweep Kernel\n"
"kernel void sweep_3words_kernel(\n"
"    device const float *t_table        [[buffer(0)]], // m * 29\n"
"    device const uchar *words_chars     [[buffer(1)]],\n"
"    device const WordMeta *word_metas  [[buffer(2)]],\n"
"    constant uint &num_words           [[buffer(3)]],\n"
"    constant uint &period              [[buffer(4)]],\n"
"    constant float &threshold          [[buffer(5)]],\n"
"    constant uint &max_hits            [[buffer(6)]],\n"
"    device atomic_uint *hit_count      [[buffer(7)]],\n"
"    device uint3 *out_triplets         [[buffer(8)]],\n"
"    device float *out_scores           [[buffer(9)]],\n"
"    uint id                            [[thread_position_in_grid]])\n"
"{\n"
"    uint w_sq = num_words * num_words;\n"
"    uint total_triplets = w_sq * num_words;\n"
"    if (id >= total_triplets) return;\n"
"\n"
"    uint i = id / w_sq;\n"
"    uint rem = id % w_sq;\n"
"    uint j = rem / num_words;\n"
"    uint l = rem % num_words;\n"
"\n"
"    WordMeta w1 = word_metas[i];\n"
"    WordMeta w2 = word_metas[j];\n"
"    WordMeta w3 = word_metas[l];\n"
"    uint comb_len = w1.length + w2.length + w3.length;\n"
"    if (comb_len == 0) return;\n"
"\n"
"    float sum = 0.0f;\n"
"    for (uint k = 0; k < period; ++k) {\n"
"        uint p_idx = k % comb_len;\n"
"        uchar c;\n"
"        if (p_idx < w1.length) {\n"
"            c = words_chars[w1.offset + p_idx];\n"
"        } else if (p_idx < w1.length + w2.length) {\n"
"            c = words_chars[w2.offset + (p_idx - w1.length)];\n"
"        } else {\n"
"            c = words_chars[w3.offset + (p_idx - w1.length - w2.length)];\n"
"        }\n"
"        sum += t_table[k * 29 + (c % 29)];\n"
"    }\n"
"    float score = sum / float(period);\n"
"\n"
"    if (score >= threshold) {\n"
"        uint slot = atomic_fetch_add_explicit(hit_count, 1, memory_order_relaxed);\n"
"        if (slot < max_hits) {\n"
"            out_triplets[slot] = uint3(i, j, l);\n"
"            out_scores[slot] = score;\n"
"        }\n"
"    }\n"
"}\n"
"\n"
"// 4. LCG Pseudo-Random Shuffle Scorer for Monte Carlo Null-Distribution\n"
"kernel void surrogate_shuffle_kernel(\n"
"    device const uchar *ciphertext     [[buffer(0)]], // length N\n"
"    device const float *unigram_logp   [[buffer(1)]], // 29\n"
"    constant uint &n                   [[buffer(2)]],\n"
"    constant uint &period              [[buffer(3)]],\n"
"    constant uint &num_trials          [[buffer(4)]],\n"
"    constant uint &base_seed           [[buffer(5)]],\n"
"    device float *out_scores           [[buffer(6)]],\n"
"    uint id                            [[thread_position_in_grid]])\n"
"{\n"
"    if (id >= num_trials) return;\n"
"    uint rng = base_seed + id * 1973u + 9277u;\n"
"    \n"
"    float total_score = 0.0f;\n"
"    for (uint col = 0; col < period; ++col) {\n"
"        float col_sum = 0.0f;\n"
"        uint count = 0;\n"
"        for (uint pos = col; pos < n; pos += period) {\n"
"            // LCG permutation shift\n"
"            rng = rng * 1664525u + 1013904223u;\n"
"            uchar c = (ciphertext[pos] + (rng % 29u)) % 29u;\n"
"            col_sum += unigram_logp[c];\n"
"            count++;\n"
"        }\n"
"        if (count > 0) total_score += (col_sum / float(count));\n"
"    }\n"
"    out_scores[id] = total_score / float(period);\n"
"}\n";

int metal_init(void) {
    @autoreleasepool {
        if (g_pipe_score_keys && g_pipe_sweep_2words && g_pipe_sweep_3words && g_pipe_surrogate) {
            return 0;
        }
        g_device = MTLCreateSystemDefaultDevice();
        if (!g_device) return -1;
        g_queue = [g_device newCommandQueue];
        if (!g_queue) return -2;

        NSError *err = nil;
        id<MTLLibrary> lib = [g_device newLibraryWithSource:kMetalSource options:nil error:&err];
        if (!lib) {
            NSLog(@"Metal shader compilation error: %@", err);
            return -3;
        }

        id<MTLFunction> fn_score = [lib newFunctionWithName:@"score_keys_kernel"];
        g_pipe_score_keys = [g_device newComputePipelineStateWithFunction:fn_score error:&err];

        id<MTLFunction> fn_2w = [lib newFunctionWithName:@"sweep_2words_kernel"];
        g_pipe_sweep_2words = [g_device newComputePipelineStateWithFunction:fn_2w error:&err];

        id<MTLFunction> fn_3w = [lib newFunctionWithName:@"sweep_3words_kernel"];
        g_pipe_sweep_3words = [g_device newComputePipelineStateWithFunction:fn_3w error:&err];

        id<MTLFunction> fn_surr = [lib newFunctionWithName:@"surrogate_shuffle_kernel"];
        g_pipe_surrogate = [g_device newComputePipelineStateWithFunction:fn_surr error:&err];

        if (!g_pipe_score_keys || !g_pipe_sweep_2words || !g_pipe_sweep_3words || !g_pipe_surrogate) {
            return -4;
        }
        return 0;
    }
}

const char* metal_get_device_name(void) {
    if (!g_device) metal_init();
    if (!g_device) return "No Metal GPU Device";
    return [[g_device name] UTF8String];
}

uint64_t metal_get_max_buffer_size(void) {
    if (!g_device) metal_init();
    if (!g_device) return 0;
    return [g_device maxBufferLength];
}

// -----------------------------------------------------------------------------
// 1. Batch T-Table Key Scoring
// -----------------------------------------------------------------------------
int metal_score_keys_batch(
    const float *t_table,
    const unsigned char *keys,
    int num_keys,
    int period,
    float *out_scores)
{
    @autoreleasepool {
        int rc = metal_init();
        if (rc != 0) return rc;

        id<MTLBuffer> bufTable = [g_device newBufferWithBytes:t_table length:period * 29 * sizeof(float) options:MTLResourceStorageModeShared];
        id<MTLBuffer> bufKeys = [g_device newBufferWithBytes:keys length:num_keys * period * sizeof(unsigned char) options:MTLResourceStorageModeShared];
        id<MTLBuffer> bufScores = [g_device newBufferWithLength:num_keys * sizeof(float) options:MTLResourceStorageModeShared];

        uint32_t u_period = period;
        uint32_t u_num_keys = num_keys;
        id<MTLBuffer> bufPeriod = [g_device newBufferWithBytes:&u_period length:sizeof(uint32_t) options:MTLResourceStorageModeShared];
        id<MTLBuffer> bufCount = [g_device newBufferWithBytes:&u_num_keys length:sizeof(uint32_t) options:MTLResourceStorageModeShared];

        id<MTLCommandBuffer> cmd = [g_queue commandBuffer];
        id<MTLComputeCommandEncoder> enc = [cmd computeCommandEncoder];
        [enc setComputePipelineState:g_pipe_score_keys];
        [enc setBuffer:bufTable offset:0 atIndex:0];
        [enc setBuffer:bufKeys offset:0 atIndex:1];
        [enc setBuffer:bufScores offset:0 atIndex:2];
        [enc setBuffer:bufPeriod offset:0 atIndex:3];
        [enc setBuffer:bufCount offset:0 atIndex:4];

        MTLSize grid = MTLSizeMake(num_keys, 1, 1);
        NSUInteger maxThreads = g_pipe_score_keys.maxTotalThreadsPerThreadgroup;
        if (maxThreads > (NSUInteger)num_keys) maxThreads = num_keys;
        MTLSize tg = MTLSizeMake(maxThreads, 1, 1);

        [enc dispatchThreads:grid threadsPerThreadgroup:tg];
        [enc endEncoding];

        [cmd commit];
        [cmd waitUntilCompleted];

        memcpy(out_scores, [bufScores contents], num_keys * sizeof(float));
        return 0;
    }
}

// -----------------------------------------------------------------------------
// 2. Parallel 2-Word Compound Phrase Sweep
// -----------------------------------------------------------------------------
int metal_sweep_2words(
    const float *t_table,
    const unsigned char *words_chars,
    int total_chars,
    const unsigned int *offsets,
    const unsigned int *lengths,
    int num_words,
    int period,
    float threshold,
    int max_hits,
    unsigned int *out_i,
    unsigned int *out_j,
    float *out_scores,
    int *out_num_hits)
{
    @autoreleasepool {
        int rc = metal_init();
        if (rc != 0) return rc;

        struct WordMeta { uint32_t offset; uint32_t length; };
        struct WordMeta *metas = (struct WordMeta*)malloc(num_words * sizeof(struct WordMeta));
        for (int i = 0; i < num_words; ++i) {
            metas[i].offset = offsets[i];
            metas[i].length = lengths[i];
        }

        id<MTLBuffer> bufTable = [g_device newBufferWithBytes:t_table length:period * 29 * sizeof(float) options:MTLResourceStorageModeShared];
        id<MTLBuffer> bufChars = [g_device newBufferWithBytes:words_chars length:total_chars * sizeof(unsigned char) options:MTLResourceStorageModeShared];
        id<MTLBuffer> bufMetas = [g_device newBufferWithBytes:metas length:num_words * sizeof(struct WordMeta) options:MTLResourceStorageModeShared];

        uint32_t u_num_words = num_words;
        uint32_t u_period = period;
        float f_thresh = threshold;
        uint32_t u_max_hits = max_hits;
        uint32_t zero = 0;

        id<MTLBuffer> bufNumWords = [g_device newBufferWithBytes:&u_num_words length:sizeof(uint32_t) options:MTLResourceStorageModeShared];
        id<MTLBuffer> bufPeriod = [g_device newBufferWithBytes:&u_period length:sizeof(uint32_t) options:MTLResourceStorageModeShared];
        id<MTLBuffer> bufThresh = [g_device newBufferWithBytes:&f_thresh length:sizeof(float) options:MTLResourceStorageModeShared];
        id<MTLBuffer> bufMaxHits = [g_device newBufferWithBytes:&u_max_hits length:sizeof(uint32_t) options:MTLResourceStorageModeShared];
        id<MTLBuffer> bufCount = [g_device newBufferWithBytes:&zero length:sizeof(uint32_t) options:MTLResourceStorageModeShared];

        id<MTLBuffer> bufPairs = [g_device newBufferWithLength:max_hits * 2 * sizeof(uint32_t) options:MTLResourceStorageModeShared];
        id<MTLBuffer> bufScores = [g_device newBufferWithLength:max_hits * sizeof(float) options:MTLResourceStorageModeShared];

        id<MTLCommandBuffer> cmd = [g_queue commandBuffer];
        id<MTLComputeCommandEncoder> enc = [cmd computeCommandEncoder];
        [enc setComputePipelineState:g_pipe_sweep_2words];
        [enc setBuffer:bufTable offset:0 atIndex:0];
        [enc setBuffer:bufChars offset:0 atIndex:1];
        [enc setBuffer:bufMetas offset:0 atIndex:2];
        [enc setBuffer:bufNumWords offset:0 atIndex:3];
        [enc setBuffer:bufPeriod offset:0 atIndex:4];
        [enc setBuffer:bufThresh offset:0 atIndex:5];
        [enc setBuffer:bufMaxHits offset:0 atIndex:6];
        [enc setBuffer:bufCount offset:0 atIndex:7];
        [enc setBuffer:bufPairs offset:0 atIndex:8];
        [enc setBuffer:bufScores offset:0 atIndex:9];

        uint64_t total_pairs = (uint64_t)num_words * (uint64_t)num_words;
        MTLSize grid = MTLSizeMake(total_pairs, 1, 1);
        NSUInteger maxThreads = g_pipe_sweep_2words.maxTotalThreadsPerThreadgroup;
        if (maxThreads > total_pairs) maxThreads = total_pairs;
        MTLSize tg = MTLSizeMake(maxThreads, 1, 1);

        [enc dispatchThreads:grid threadsPerThreadgroup:tg];
        [enc endEncoding];

        [cmd commit];
        [cmd waitUntilCompleted];

        uint32_t actual_hits = *(uint32_t*)[bufCount contents];
        if (actual_hits > (uint32_t)max_hits) actual_hits = max_hits;
        *out_num_hits = actual_hits;

        uint32_t *pairs_ptr = (uint32_t*)[bufPairs contents];
        float *scores_ptr = (float*)[bufScores contents];
        for (uint32_t k = 0; k < actual_hits; ++k) {
            out_i[k] = pairs_ptr[k * 2];
            out_j[k] = pairs_ptr[k * 2 + 1];
            out_scores[k] = scores_ptr[k];
        }

        free(metas);
        return 0;
    }
}

// -----------------------------------------------------------------------------
// 3. Parallel 3-Word Compound Phrase Sweep
// -----------------------------------------------------------------------------
int metal_sweep_3words(
    const float *t_table,
    const unsigned char *words_chars,
    int total_chars,
    const unsigned int *offsets,
    const unsigned int *lengths,
    int num_words,
    int period,
    float threshold,
    int max_hits,
    unsigned int *out_i,
    unsigned int *out_j,
    unsigned int *out_l,
    float *out_scores,
    int *out_num_hits)
{
    @autoreleasepool {
        int rc = metal_init();
        if (rc != 0) return rc;

        struct WordMeta { uint32_t offset; uint32_t length; };
        struct WordMeta *metas = (struct WordMeta*)malloc(num_words * sizeof(struct WordMeta));
        for (int i = 0; i < num_words; ++i) {
            metas[i].offset = offsets[i];
            metas[i].length = lengths[i];
        }

        id<MTLBuffer> bufTable = [g_device newBufferWithBytes:t_table length:period * 29 * sizeof(float) options:MTLResourceStorageModeShared];
        id<MTLBuffer> bufChars = [g_device newBufferWithBytes:words_chars length:total_chars * sizeof(unsigned char) options:MTLResourceStorageModeShared];
        id<MTLBuffer> bufMetas = [g_device newBufferWithBytes:metas length:num_words * sizeof(struct WordMeta) options:MTLResourceStorageModeShared];

        uint32_t u_num_words = num_words;
        uint32_t u_period = period;
        float f_thresh = threshold;
        uint32_t u_max_hits = max_hits;
        uint32_t zero = 0;

        id<MTLBuffer> bufNumWords = [g_device newBufferWithBytes:&u_num_words length:sizeof(uint32_t) options:MTLResourceStorageModeShared];
        id<MTLBuffer> bufPeriod = [g_device newBufferWithBytes:&u_period length:sizeof(uint32_t) options:MTLResourceStorageModeShared];
        id<MTLBuffer> bufThresh = [g_device newBufferWithBytes:&f_thresh length:sizeof(float) options:MTLResourceStorageModeShared];
        id<MTLBuffer> bufMaxHits = [g_device newBufferWithBytes:&u_max_hits length:sizeof(uint32_t) options:MTLResourceStorageModeShared];
        id<MTLBuffer> bufCount = [g_device newBufferWithBytes:&zero length:sizeof(uint32_t) options:MTLResourceStorageModeShared];

        id<MTLBuffer> bufTriplets = [g_device newBufferWithLength:max_hits * 3 * sizeof(uint32_t) options:MTLResourceStorageModeShared];
        id<MTLBuffer> bufScores = [g_device newBufferWithLength:max_hits * sizeof(float) options:MTLResourceStorageModeShared];

        id<MTLCommandBuffer> cmd = [g_queue commandBuffer];
        id<MTLComputeCommandEncoder> enc = [cmd computeCommandEncoder];
        [enc setComputePipelineState:g_pipe_sweep_3words];
        [enc setBuffer:bufTable offset:0 atIndex:0];
        [enc setBuffer:bufChars offset:0 atIndex:1];
        [enc setBuffer:bufMetas offset:0 atIndex:2];
        [enc setBuffer:bufNumWords offset:0 atIndex:3];
        [enc setBuffer:bufPeriod offset:0 atIndex:4];
        [enc setBuffer:bufThresh offset:0 atIndex:5];
        [enc setBuffer:bufMaxHits offset:0 atIndex:6];
        [enc setBuffer:bufCount offset:0 atIndex:7];
        [enc setBuffer:bufTriplets offset:0 atIndex:8];
        [enc setBuffer:bufScores offset:0 atIndex:9];

        uint64_t total_triplets = (uint64_t)num_words * (uint64_t)num_words * (uint64_t)num_words;
        MTLSize grid = MTLSizeMake(total_triplets, 1, 1);
        NSUInteger maxThreads = g_pipe_sweep_3words.maxTotalThreadsPerThreadgroup;
        if (maxThreads > total_triplets) maxThreads = total_triplets;
        MTLSize tg = MTLSizeMake(maxThreads, 1, 1);

        [enc dispatchThreads:grid threadsPerThreadgroup:tg];
        [enc endEncoding];

        [cmd commit];
        [cmd waitUntilCompleted];

        uint32_t actual_hits = *(uint32_t*)[bufCount contents];
        if (actual_hits > (uint32_t)max_hits) actual_hits = max_hits;
        *out_num_hits = actual_hits;

        uint32_t *trip_ptr = (uint32_t*)[bufTriplets contents];
        float *scores_ptr = (float*)[bufScores contents];
        for (uint32_t k = 0; k < actual_hits; ++k) {
            out_i[k] = trip_ptr[k * 3];
            out_j[k] = trip_ptr[k * 3 + 1];
            out_l[k] = trip_ptr[k * 3 + 2];
            out_scores[k] = scores_ptr[k];
        }

        free(metas);
        return 0;
    }
}

// -----------------------------------------------------------------------------
// 4. Parallel Monte Carlo Surrogate Shuffle Scorer
// -----------------------------------------------------------------------------
int metal_surrogate_shuffles(
    const unsigned char *ciphertext,
    int n,
    const float *unigram_logp,
    int period,
    int num_trials,
    unsigned int base_seed,
    float *out_scores)
{
    @autoreleasepool {
        int rc = metal_init();
        if (rc != 0) return rc;

        id<MTLBuffer> bufCipher = [g_device newBufferWithBytes:ciphertext length:n * sizeof(unsigned char) options:MTLResourceStorageModeShared];
        id<MTLBuffer> bufLogP = [g_device newBufferWithBytes:unigram_logp length:29 * sizeof(float) options:MTLResourceStorageModeShared];
        id<MTLBuffer> bufScores = [g_device newBufferWithLength:num_trials * sizeof(float) options:MTLResourceStorageModeShared];

        uint32_t u_n = n;
        uint32_t u_period = period;
        uint32_t u_trials = num_trials;
        uint32_t u_seed = base_seed;

        id<MTLBuffer> bufN = [g_device newBufferWithBytes:&u_n length:sizeof(uint32_t) options:MTLResourceStorageModeShared];
        id<MTLBuffer> bufP = [g_device newBufferWithBytes:&u_period length:sizeof(uint32_t) options:MTLResourceStorageModeShared];
        id<MTLBuffer> bufTr = [g_device newBufferWithBytes:&u_trials length:sizeof(uint32_t) options:MTLResourceStorageModeShared];
        id<MTLBuffer> bufSd = [g_device newBufferWithBytes:&u_seed length:sizeof(uint32_t) options:MTLResourceStorageModeShared];

        id<MTLCommandBuffer> cmd = [g_queue commandBuffer];
        id<MTLComputeCommandEncoder> enc = [cmd computeCommandEncoder];
        [enc setComputePipelineState:g_pipe_surrogate];
        [enc setBuffer:bufCipher offset:0 atIndex:0];
        [enc setBuffer:bufLogP offset:0 atIndex:1];
        [enc setBuffer:bufN offset:0 atIndex:2];
        [enc setBuffer:bufP offset:0 atIndex:3];
        [enc setBuffer:bufTr offset:0 atIndex:4];
        [enc setBuffer:bufSd offset:0 atIndex:5];
        [enc setBuffer:bufScores offset:0 atIndex:6];

        MTLSize grid = MTLSizeMake(num_trials, 1, 1);
        NSUInteger maxThreads = g_pipe_surrogate.maxTotalThreadsPerThreadgroup;
        if (maxThreads > (NSUInteger)num_trials) maxThreads = num_trials;
        MTLSize tg = MTLSizeMake(maxThreads, 1, 1);

        [enc dispatchThreads:grid threadsPerThreadgroup:tg];
        [enc endEncoding];

        [cmd commit];
        [cmd waitUntilCompleted];

        memcpy(out_scores, [bufScores contents], num_trials * sizeof(float));
        return 0;
    }
}
