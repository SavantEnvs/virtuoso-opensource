/* Shared by the fuzz_sql* harnesses: boots the embedded Virtuoso server in-process and hands every
 * input to run_input() (defined by the harness) on a Virtuoso thread as the unprivileged user "fz". */
#ifndef SQL_COMMON_H
#define SQL_COMMON_H

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <pthread.h>
#include <semaphore.h>
#include <errno.h>
#include <dirent.h>

#include "libutil.h"
#include "Dk.h"
#include "sqlnode.h"
#include "sqlfn.h"
#include "eqlcomp.h"
#include "security.h"
#include "wifn.h"
#include "wi.h"

extern int VirtuosoServerMain (int argc, char **argv);

static sem_t req_sem, done_sem;
static client_connection_t *fz_cli;
static const char *cur_text;

/* The server's timers deliver signals to arbitrary threads; a sem_wait that returns early on EINTR
 * would run the worker on a stale (already freed) input. */
static void
sem_wait_retry (sem_t *sem)
{
  while (-1 == sem_wait (sem) && EINTR == errno)
    ;
}

static void
free_err (caddr_t err)
{
  if (err)
    dk_free_tree (err);
}

static void
run_dba (client_connection_t *cli, const char *text)
{
  caddr_t err = NULL;
  query_t *qr = sql_compile (text, cli, &err, SQLC_DEFAULT);
  if (!err && qr)
    {
      local_cursor_t *lc = NULL;
      err = qr_quick_exec (qr, cli, "", &lc, 0);
      if (lc)
        lc_free (lc);
    }
  free_err (err);
  if (qr)
    qr_free (qr);
}

static void run_input (client_connection_t *cli, const char *text);

static int
worker_main (void *arg)
{
  client_connection_t *dba_cli = client_connection_create ();
  dba_cli->cli_user = sec_id_to_user (U_ID_DBA);
  local_start_trx (dba_cli);
  run_dba (dba_cli, "DB.DBA.USER_CREATE ('fz', 'fz')");
  run_dba (dba_cli, "DB.DBA.USER_GRANT_ROLE ('fz', 'SPARQL_SELECT')");
  run_dba (dba_cli, "DB.DBA.USER_GRANT_ROLE ('fz', 'SPARQL_UPDATE')");
  fz_cli = client_connection_create ();
  local_start_trx (fz_cli);
  fz_cli->cli_user = sec_name_to_user ("fz");
  fz_cli->cli_charset = CHARSET_UTF8;
  cli_set_default_qual (fz_cli);
  SET_THR_ATTR (THREAD_CURRENT_THREAD, TA_IMMEDIATE_CLIENT, fz_cli);
  sqlc_set_client (fz_cli);
  sem_post (&done_sem);
  for (;;)
    {
      sem_wait_retry (&req_sem);
      run_input (fz_cli, cur_text);
      sem_post (&done_sem);
    }
  return 0;
}

static char ini_arg[320];
static int fz_port;

static void *
server_main (void *arg)
{
  char *argv[] = { "virtuoso-t", "+foreground", "+configfile", ini_arg, NULL };
  VirtuosoServerMain (4, argv);
  return NULL;
}

static void
write_ini (FILE *f, const char *dir, int port)
{
  fprintf (f,
    "[Database]\nDatabaseFile=%s/virtuoso.db\nErrorLogFile=%s/virtuoso.log\nLockFile=%s/virtuoso.lck\n"
    "TransactionFile=%s/virtuoso.trx\nxa_persistent_file=%s/virtuoso.pxa\nErrorLogLevel=7\nFileExtend=200\n"
    "MaxCheckpointRemap=2000\nStriping=0\nTempStorage=TempDatabase\n"
    "[TempDatabase]\nDatabaseFile=%s/virtuoso-temp.db\nTransactionFile=%s/virtuoso-temp.trx\n"
    "MaxCheckpointRemap=2000\nStriping=0\n"
    "[Parameters]\nServerPort=%d\nLiteMode=0\nDisableUnixSocket=1\nDisableTcpSocket=1\n"
    "MaxClientConnections=10\nCheckpointInterval=0\nO_DIRECT=0\nCaseMode=2\nMaxStaticCursorRows=5000\n"
    "AllowOSCalls=0\nSchedulerInterval=10\nDirsAllowed=%s\nThreadCleanupInterval=0\nThreadThreshold=10\n"
    "ResourcesCleanupInterval=0\nSingleCPU=0\nMaxMemPoolSize=200000000\nIndexTreeMaps=64\n"
    "MaxQueryMem=512M\nThreadsPerQuery=2\nAsyncQueueMaxThreads=4\nNumberOfBuffers=2000\nMaxDirtyBuffers=1200\n",
    dir, dir, dir, dir, dir, dir, dir, port, dir);
}

/* The server keeps its files open, so unlinking them once it is online frees the ~60 MB database
 * on every way out of the process (exit, crash, kill). Left behind, every execution of the target
 * (fuzzing, corpus and crash replays) leaks one directory, the scratch disk fills up, and a later
 * server bootstrap dies with a NULL extent map (em_new_dp) or a failed xslt_init. */
static void
unlink_server_dir (const char *dir)
{
  DIR *d = opendir (dir);
  struct dirent *e;
  char path[600];
  if (!d)
    return;
  while ((e = readdir (d)))
    {
      if (!strcmp (e->d_name, ".") || !strcmp (e->d_name, ".."))
        continue;
      snprintf (path, sizeof (path), "%s/%s", dir, e->d_name);
      unlink (path);
    }
  closedir (d);
  rmdir (dir);
}

/* With TCP disabled the server listens (and connects to itself) on the unix socket /tmp/virt_<port>:
 * a port per process keeps concurrent targets on one node from rebinding each other's socket, and
 * removing it once online leaves nothing behind in /tmp. */
static void
unlink_server_socket (void)
{
  char path[100];
  snprintf (path, sizeof (path), UNIXSOCK_ADD_ADDR "%d", fz_port);
  unlink (path);
}

int
LLVMFuzzerInitialize (int *argc, char ***argv)
{
  const char *tmp = getenv ("TMPDIR");
  char dir[256];
  snprintf (dir, sizeof (dir), "%s/vfuzz.XXXXXX", tmp && *tmp ? tmp : "/tmp");
  if (!mkdtemp (dir))
    return 1;
  char ini_path[320];
  snprintf (ini_path, sizeof (ini_path), "%s/virtuoso.ini", dir);
  FILE *f = fopen (ini_path, "w");
  if (!f)
    return 1;
  fz_port = 10000 + (int) (getpid () % 50000);
  write_ini (f, dir, fz_port);
  fclose (f);
  snprintf (ini_arg, sizeof (ini_arg), "%s", ini_path);

  pthread_attr_t attr;
  pthread_t t;
  pthread_attr_init (&attr);
  pthread_attr_setstacksize (&attr, 16 << 20);
  pthread_create (&t, &attr, server_main, NULL);
  while (!virtuoso_server_initialized)
    usleep (10000);

  sem_init (&req_sem, 0, 0);
  sem_init (&done_sem, 0, 0);
  PrpcThreadAllocate (worker_main, 8 << 20, NULL);
  sem_wait_retry (&done_sem);
  unlink_server_dir (dir);
  unlink_server_socket ();
  return 0;
}

int
LLVMFuzzerTestOneInput (const unsigned char *data, size_t size)
{
  char *text = malloc (size + 1);
  memcpy (text, data, size);
  text[size] = 0;
  cur_text = text;
  sem_post (&req_sem);
  sem_wait_retry (&done_sem);
  free (text);
  return 0;
}

#endif
