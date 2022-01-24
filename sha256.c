#include <arm_neon.h>
#include <inttypes.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

// Started from crypto/sha256.

enum {
  DIGEST_SIZE = 32,
  BLOCK_SIZE = 64,
};

typedef struct digest {
  uint32x4_t h[2];
  uint8_t x[BLOCK_SIZE];
  int nx;
  uint64_t len;
} digest;

static const uint32_t K[16][4] = {
    {0x428A2F98, 0x71374491, 0xB5C0FBCF, 0xE9B5DBA5},
    {0x3956C25B, 0x59F111F1, 0x923F82A4, 0xAB1C5ED5},
    {0xD807AA98, 0x12835B01, 0x243185BE, 0x550C7DC3},
    {0x72BE5D74, 0x80DEB1FE, 0x9BDC06A7, 0xC19BF174},
    {0xE49B69C1, 0xEFBE4786, 0x0FC19DC6, 0x240CA1CC},
    {0x2DE92C6F, 0x4A7484AA, 0x5CB0A9DC, 0x76F988DA},
    {0x983E5152, 0xA831C66D, 0xB00327C8, 0xBF597FC7},
    {0xC6E00BF3, 0xD5A79147, 0x06CA6351, 0x14292967},
    {0x27B70A85, 0x2E1B2138, 0x4D2C6DFC, 0x53380D13},
    {0x650A7354, 0x766A0ABB, 0x81C2C92E, 0x92722C85},
    {0xA2BFE8A1, 0xA81A664B, 0xC24B8B70, 0xC76C51A3},
    {0xD192E819, 0xD6990624, 0xF40E3585, 0x106AA070},
    {0x19A4C116, 0x1E376C08, 0x2748774C, 0x34B0BCB5},
    {0x391C0CB3, 0x4ED8AA4A, 0x5B9CCA4F, 0x682E6FF3},
    {0x748F82EE, 0x78A5636F, 0x84C87814, 0x8CC70208},
    {0x90BEFFFA, 0xA4506CEB, 0xBEF9A3F7, 0xC67178F2},
};

static void sha256_blocks(uint32x4_t h[2], const uint8_t *p, int nblocks) {
  uint32x4_t h0 = h[0];
  uint32x4_t h1 = h[1];

  for (int i = 0; i < nblocks; i++) {
    uint32x4_t h2 = h0;
    uint32x4_t h3 = h1;
    uint32x4_t t0 = h2;

    uint32x4_t m0 = vreinterpretq_u32_u8(vrev32q_u8(vld1q_u8(&p[0])));
    uint32x4_t m1 = vreinterpretq_u32_u8(vrev32q_u8(vld1q_u8(&p[16])));
    uint32x4_t m2 = vreinterpretq_u32_u8(vrev32q_u8(vld1q_u8(&p[32])));
    uint32x4_t m3 = vreinterpretq_u32_u8(vrev32q_u8(vld1q_u8(&p[48])));

#define HASH_UPDATE                \
  h2 = vsha256hq_u32(h2, h3, t1);  \
  h3 = vsha256h2q_u32(h3, t0, t1); \
  t0 = h2

    uint32x4_t t1 = vaddq_u32(m0, vld1q_u32(K[0]));
    m0 = vsha256su0q_u32(m0, m1);
    HASH_UPDATE;

    t1 = vaddq_u32(m1, vld1q_u32(K[1]));
    m1 = vsha256su0q_u32(m1, m2);
    m0 = vsha256su1q_u32(m0, m2, m3);
    HASH_UPDATE;

    t1 = vaddq_u32(m2, vld1q_u32(K[2]));
    m2 = vsha256su0q_u32(m2, m3);
    m1 = vsha256su1q_u32(m1, m3, m0);
    HASH_UPDATE;

    t1 = vaddq_u32(m3, vld1q_u32(K[3]));
    m3 = vsha256su0q_u32(m3, m0);
    m2 = vsha256su1q_u32(m2, m0, m1);
    HASH_UPDATE;

    t1 = vaddq_u32(m0, vld1q_u32(K[4]));
    m0 = vsha256su0q_u32(m0, m1);
    m3 = vsha256su1q_u32(m3, m1, m2);
    HASH_UPDATE;

    t1 = vaddq_u32(m1, vld1q_u32(K[5]));
    m1 = vsha256su0q_u32(m1, m2);
    m0 = vsha256su1q_u32(m0, m2, m3);
    HASH_UPDATE;

    t1 = vaddq_u32(m2, vld1q_u32(K[6]));
    m2 = vsha256su0q_u32(m2, m3);
    m1 = vsha256su1q_u32(m1, m3, m0);
    HASH_UPDATE;

    t1 = vaddq_u32(m3, vld1q_u32(K[7]));
    m3 = vsha256su0q_u32(m3, m0);
    m2 = vsha256su1q_u32(m2, m0, m1);
    HASH_UPDATE;

    t1 = vaddq_u32(m0, vld1q_u32(K[8]));
    m0 = vsha256su0q_u32(m0, m1);
    m3 = vsha256su1q_u32(m3, m1, m2);
    HASH_UPDATE;

    t1 = vaddq_u32(m1, vld1q_u32(K[9]));
    m1 = vsha256su0q_u32(m1, m2);
    m0 = vsha256su1q_u32(m0, m2, m3);
    HASH_UPDATE;

    t1 = vaddq_u32(m2, vld1q_u32(K[10]));
    m2 = vsha256su0q_u32(m2, m3);
    m1 = vsha256su1q_u32(m1, m3, m0);
    HASH_UPDATE;

    t1 = vaddq_u32(m3, vld1q_u32(K[11]));
    m3 = vsha256su0q_u32(m3, m0);
    m2 = vsha256su1q_u32(m2, m0, m1);
    HASH_UPDATE;

    t1 = vaddq_u32(m0, vld1q_u32(K[12]));
    HASH_UPDATE;
    m3 = vsha256su1q_u32(m3, m1, m2);

    t1 = vaddq_u32(m1, vld1q_u32(K[13]));
    HASH_UPDATE;

    t1 = vaddq_u32(m2, vld1q_u32(K[14]));
    HASH_UPDATE;

    t1 = vaddq_u32(m3, vld1q_u32(K[15]));
    HASH_UPDATE;

    h0 = vaddq_u32(h0, h2);
    h1 = vaddq_u32(h1, h3);

    p += BLOCK_SIZE;
  }

  // Save state
  h[0] = h0;
  h[1] = h1;
}

static const uint32_t init[2][4] = {
    {0x6A09E667, 0xBB67AE85, 0x3C6EF372, 0xA54FF53A},
    {0x510E527F, 0x9B05688C, 0x1F83D9AB, 0x5BE0CD19},
};

void sha256_reset(digest *d) {
  memset(d, 0, sizeof(*d));

  d->h[0] = vld1q_u32(init[0]);
  d->h[1] = vld1q_u32(init[1]);
}

void sha256_update(digest *d, const uint8_t *p, size_t p_len) {
  d->len += p_len;

  if (d->nx > 0) {
    size_t n = sizeof(d->x) - d->nx;
    if (n > p_len) {
      n = p_len;
    }
    memcpy(&d->x[d->nx], p, n);
    d->nx += n;
    if (d->nx == BLOCK_SIZE) {
      sha256_blocks(d->h, d->x, 1);
      d->nx = 0;
    }
    p += n;
    p_len -= n;
  }

  if (p_len >= BLOCK_SIZE) {
    size_t n = p_len & ~(BLOCK_SIZE - 1);
    sha256_blocks(d->h, p, n / BLOCK_SIZE);
    p += n;
    p_len -= n;
  }

  if (p_len > 0) {
    size_t n = sizeof(d->x) - d->nx;
    if (n > p_len) {
      n = p_len;
    }
    memcpy(&d->x[d->nx], p, n);
    d->nx = n;
  }
}

static void sha256_checksum(digest *d, uint8_t dst[DIGEST_SIZE]) {
  uint64_t len = d->len;

  uint8_t tmp[64] = {0};
  tmp[0] = 0x80;
  if ((len % 64) < 56) {
    sha256_update(d, tmp, 56 - (len % 64));
  } else {
    sha256_update(d, tmp, 64 + 56 - (len % 64));
  }

  len <<= 3;
  tmp[0] = (uint8_t)(len >> 56);
  tmp[1] = (uint8_t)(len >> 48);
  tmp[2] = (uint8_t)(len >> 40);
  tmp[3] = (uint8_t)(len >> 32);
  tmp[4] = (uint8_t)(len >> 24);
  tmp[5] = (uint8_t)(len >> 16);
  tmp[6] = (uint8_t)(len >> 8);
  tmp[7] = (uint8_t)len;
  sha256_update(d, tmp, 8);

  if (d->nx != 0) {
    fprintf(stderr, "d->nx !=0\n");
    abort();
  }

  vst1q_u8(&dst[0], vrev32q_u8(vreinterpretq_u8_u32(d->h[0])));
  vst1q_u8(&dst[DIGEST_SIZE / 2], vrev32q_u8(vreinterpretq_u8_u32(d->h[1])));
}

void sha256_sum(const digest *d, uint8_t dst[DIGEST_SIZE]) {
  digest d0 = *d;
  sha256_checksum(&d0, dst);
}

__attribute__((always_inline)) static inline uint64_t now() {
#if defined(__APPLE__)
  struct timespec ts;
  clock_gettime(CLOCK_REALTIME, &ts);
  return ts.tv_sec * (uint64_t)1000000000L + ts.tv_nsec;
#else
  return clock_gettime_nsec_np(CLOCK_UPTIME_RAW);
#endif	// defined(__APPLE__)
}

int main(int argc, const char **argv) {
  const uint8_t buf[8192] = {0};
  uint8_t sum[DIGEST_SIZE] = {0};
  digest d = {0};

  const size_t sizes[] = {0, 8, 1024, sizeof(buf)};
  const char sums[][64] = {
      "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
      "af5570f5a1810b7af78caf4bc70a660f0df51e42baf91d4de5b2328de0e83dfc",
      "5f70bf18a086007016e948b04aed3b82103a36bea41755b6cddfaf10ace3c6ef",
      "9f1dcbc35c350d6027f98be0f5c8b43b42ca52b7604459c0c42be3aa88913d47",
  };

  int N = sizeof(sizes) / sizeof(sizes[0]);
  for (int i = 0; i < N; i++) {
    enum {
      one_sec = 1000000000,
    };
    uint64_t elapsed = 0;
    int iters = 0;
    while (elapsed < one_sec) {
      uint64_t start = now();

      sha256_reset(&d);
      sha256_update(&d, buf, sizes[i]);
      sha256_sum(&d, sum);

      uint64_t stop = now();
      if (stop > start) {
	elapsed += stop - start;
	iters++;
      }
    }

    fprintf(stderr, "size=%zu\n", sizes[i]);
    fprintf(stderr, "iters=%d\n", iters);
    fprintf(stderr, "%" PRIu64 " ns/op\n", elapsed / iters);
    fprintf(stderr, "%0.2f MB/s\n",
	    ((double)((uint64_t)iters * sizes[i])) / 1e6);

    fprintf(stderr, "G: ");
    for (int i = 0; i < DIGEST_SIZE; i++) {
      fprintf(stderr, "%02x", sum[i]);
    }
    fprintf(stderr, "\nW: ");
    for (int j = 0; j < 64; j++) {
      fprintf(stderr, "%c", sums[i][j]);
    }
    fprintf(stderr, "\n\n");

    __asm__ __volatile__("" : : "r,m"(buf) : "memory");
  }
  return 0;
}
