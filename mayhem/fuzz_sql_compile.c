/* Stateless in-process libFuzzer harness: compiles each input with SQLC_DO_NOT_STORE_PROC (the mode
 * explain() uses) and describes its result set the way SQLPrepare does, but never executes it. Nothing
 * is stored in the schema and nothing is committed, so every crash replays from its one input on a
 * fresh server. */
#include "sql_common.h"
#include "sqlpar.h"

/* Even without storing, compiling CREATE [XML] VIEW registers the view definition in the in-memory
 * schema (replacing the one of an existing table), which later inputs would see. */
static int
registers_view (const char *text, client_connection_t *cli)
{
  caddr_t err = NULL;
  ST *tree = (ST *) sql_compile (text, cli, &err, SQLC_PARSE_ONLY);
  int found = 0;
  free_err (err);
  if (!tree)
    return 0;
  if (ST_P (tree, SCHEMA_ELEMENT_LIST))
    {
      ST **list = (ST **) tree->_.op.arg_1;
      int inx;
      DO_BOX (ST *, elt, inx, list)
        {
          if (VIEW_DEF == elt->type || XML_VIEW == elt->type)
            found = 1;
        }
      END_DO_BOX;
    }
  dk_free_tree ((caddr_t) tree);
  return found;
}

static void
run_input (client_connection_t *cli, const char *text)
{
  caddr_t err = NULL;
  cli_set_start_times (cli);
  if (!registers_view (text, cli))
    {
      query_t *qr = sql_compile (text, cli, &err, SQLC_DO_NOT_STORE_PROC);
      if (!err && qr && !qr->qr_proc_name)
        {
          caddr_t derr = NULL;
          stmt_compilation_t *comp = qr_describe_1 (qr, &derr, cli);
          if (comp)
            dk_free_tree ((caddr_t) comp);
          free_err (derr);
        }
      free_err (err);
      if (qr && !qr->qr_proc_name)
        qr_free (qr);
    }
  IN_TXN;
  lt_rollback (cli->cli_trx, TRX_CONT);
  LEAVE_TXN;
}
