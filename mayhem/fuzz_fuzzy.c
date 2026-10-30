/* libFuzzer harness for the fuzzy string-similarity algorithms behind levenshtein(), jaro_winkler(),
 * ngram_cosine() and the fuzzy contains() option. Input: [algo][n] first-string \0 second-string. */
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include "fuzzy_algorithms.h"

int
LLVMFuzzerTestOneInput (const uint8_t *data, size_t size)
{
  if (size < 2)
    return 0;
  int algo = 1 + data[0] % 3;
  int n = data[1] % 6;
  data += 2;
  size -= 2;

  char *buf = malloc (size + 1);
  memcpy (buf, data, size);
  buf[size] = 0;
  const char *s1 = buf;
  const char *s2 = buf + strlen (buf);
  if (s2 < buf + size)
    s2++;

  if (fuzzy_work_ok ((long) strlen (s1), (long) strlen (s2), algo))
    {
      (void) fuzzy_similarity (s1, s2, algo, n);
      (void) fuzzy_distance (s1, s2, algo);
      (void) levenshtein_distance (s1, s2);
      (void) jaro_winkler_similarity (s1, s2);
      (void) ngram_cosine_similarity (s1, s2, n);
    }
  (void) fuzzy_algo_id_from_name (s1);
  free (buf);
  return 0;
}
