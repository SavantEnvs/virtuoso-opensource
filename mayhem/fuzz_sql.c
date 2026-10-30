/* In-process libFuzzer harness: feeds each input to the embedded Virtuoso server's SQL/SPARQL compiler
 * and executor as an unprivileged user. The database is stateful (DDL, sequences and the registry
 * commit outside the transaction), so a crash can depend on earlier inputs; fuzz_sql_compile is the
 * stateless counterpart. */
#include "sql_common.h"

#define MAX_ROWS 64

static void
run_input (client_connection_t *cli, const char *text)
{
  caddr_t err = NULL;
  cli_set_start_times (cli);
  query_t *qr = sql_compile (text, cli, &err, SQLC_DEFAULT);
  if (!err && qr)
    {
      local_cursor_t *lc = NULL;
      int n = 0;
      err = qr_quick_exec (qr, cli, "", &lc, 0);
      if (!err && lc)
        {
          while (n++ < MAX_ROWS && lc_next (lc))
            ;
        }
      if (lc)
        lc_free (lc);
    }
  free_err (err);
  if (qr)
    qr_free (qr);
  IN_TXN;
  lt_rollback (cli->cli_trx, TRX_CONT);
  LEAVE_TXN;
}
