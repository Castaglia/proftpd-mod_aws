/*
 * ProFTPD - mod_aws S3 FSIO API
 * Copyright (c) 2016-2017 TJ Saunders
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Suite 500, Boston, MA 02110-1335, USA.
 *
 * As a special exemption, TJ Saunders and other respective copyright holders
 * give permission to link this program with OpenSSL, and distribute the
 * resulting executable, without including the source code for OpenSSL in the
 * source distribution.
 */

#include "mod_aws.h"
#include "../utils.h"
#include "s3/conn.h"
#include "s3/bucket.h"
#include "s3/object.h"
#include "s3/fsio.h"

/* Compatibility hack for older ProFTPD versions. */
#ifndef FSIO_FILE_FSTAT
# define FSIO_FILE_FSTAT		(-1)
#endif /* FSIO_FILE_FSTAT */

static const char *trace_channel = "aws.s3.fsio";

#define AWS_S3_FSIO_DEFAULT_BLOCKSZ			4096

struct s3_fsio {
  struct s3_conn *s3;
  const char *bucket_name;
  const char *object_prefix;
  size_t object_prefixlen;
};

struct s3_fh {
  /* Is this handle intended for reads, writes, or both? */
  int read_only;

  /* open(2) flags used for this file handle. */
  int open_flags;

  /* Cached stat(2), for easy reference. */
  struct stat st;

  /* Number of bytes read/written; used for knowing, at close, whether to end a
   * multipart upload.
   */
  off_t nread;
  off_t nwritten;

  /* XXX Do we use fh->fh_buf for buffering of reads/writes, or our own
   * separate pr_buffer_t?
   */
};

static void store_stat_kv(pr_table_t *tab, char *k, const char *v) {
  int res;

  res = pr_table_add(tab, k, v, 0);
  if (res < 0) {
    pr_trace_msg(trace_channel, 2, "error stashing '%s' in table: %s", k,
      strerror(errno));
  }
}

/* Obtain the data for struct stat from a table of the metadata for an S3
 * object.  For interoperability, we look for/use the same metadata keys
 * that s3fs, s3cmd, and others use:
 *
 *  st.st_size  <-> Content-Length
 *  st.st_mode  <-> x-amz-meta-mode, x-amz-meta-permissions
 *  st.st_atime <-> x-amz-meta-atime
 *  st.st_mtime <-> x-amz-meta-mtime
 *  st.st_uid   <-> x-amz-meta-uid, x-amz-meta-owner
 *  st.st_gid   <-> x-amz-meta-gid, x-amz-meta-group
 *
 * And then there are xattrs.  Sigh.
 */
int aws_s3_fsio_stat2table(pool *p, struct stat *st, pr_table_t *tab) {
  const char *k, *v;

  if (p == NULL ||
      st == NULL ||
      tab == NULL) {
    errno = EINVAL;
    return -1;
  }

  k = AWS_S3_FSIO_METADATA_KEY_MODE;
  v = aws_utils_str_mode2s(p, st->st_mode);
  store_stat_kv(tab, pstrdup(p, k), v);

  k = AWS_S3_FSIO_METADATA_KEY_MTIME;
  v = aws_utils_str_ul2s(p, (unsigned long) st->st_mtime);
  store_stat_kv(tab, pstrdup(p, k), v);

  k = AWS_S3_FSIO_METADATA_KEY_ATIME;
  v = aws_utils_str_ul2s(p, (unsigned long) st->st_atime);
  store_stat_kv(tab, pstrdup(p, k), v);

  k = AWS_S3_FSIO_METADATA_KEY_SIZE;
  v = aws_utils_str_off2s(p, st->st_size);
  store_stat_kv(tab, pstrdup(p, k), v);

  k = AWS_S3_FSIO_METADATA_KEY_UID;
  v = pr_uid2str(p, st->st_uid);
  store_stat_kv(tab, pstrdup(p, k), v);
  /* Note: Should we also store the UID using AWS_S3_FSIO_METADATA_KEY_OWNER? */

  k = AWS_S3_FSIO_METADATA_KEY_GID;
  v = pr_gid2str(p, st->st_gid);
  store_stat_kv(tab, pstrdup(p, k), v);
  /* Note: Should we also store the GID using AWS_S3_FSIO_METADATA_KEY_GROUP? */

  return 0;
}

/* Note: Let the filesystem provide the following, via the shadow entry for the
 * file:
 *
 *  st.st_dev
 *  st.st_ino
 *  st.st_nlink
 */
int aws_s3_fsio_table2stat(pool *p, pr_table_t *tab, struct stat *st,
    unsigned int *st_bits) {
  const char *k, *v;

  if (p == NULL ||
      tab == NULL ||
      st == NULL ||
      st_bits == NULL) {
    errno = EINVAL;
    return -1;
  }

  if (pr_table_count(tab) == 0) {
    pr_trace_msg(trace_channel, 17,
      "empty stat table, not setting stat fields");

    errno = ENOENT;
    return -1;
  }

  *st_bits = 0;

  k = AWS_S3_FSIO_METADATA_KEY_MODE;
  v = pr_table_get(tab, k, NULL);
  if (v != NULL) {
    mode_t mode;

    if (aws_utils_str_s2mode(p, v, &mode) == 0) {
      st->st_mode = mode;
      (*st_bits) |= AWS_S3_FSIO_METADATA_HAVE_MODE;
      pr_trace_msg(trace_channel, 15, "using mode %04o for %s key", mode, k);

    } else {
      pr_trace_msg(trace_channel, 7, "unable to convert '%s' to mode: %s", v,
        strerror(errno));
    }
  }

  k = AWS_S3_FSIO_METADATA_KEY_MTIME;
  v = pr_table_get(tab, k, NULL);
  if (v != NULL) {
    time_t mtime;

    if (aws_utils_str_s2ul(p, v, (unsigned long *) &mtime) == 0) {
      st->st_mtime = mtime;
      (*st_bits) |= AWS_S3_FSIO_METADATA_HAVE_MTIME;
      pr_trace_msg(trace_channel, 15, "using mtime %lu for %s key",
        (unsigned long) mtime, k);

    } else {
      pr_trace_msg(trace_channel, 7, "unable to convert '%s' to mtime: %s", v,
        strerror(errno));
    }
  }

  k = AWS_S3_FSIO_METADATA_KEY_ATIME;
  v = pr_table_get(tab, k, NULL);
  if (v != NULL) {
    time_t atime;

    if (aws_utils_str_s2ul(p, v, (unsigned long *) &atime) == 0) {
      st->st_atime = atime;
      (*st_bits) |= AWS_S3_FSIO_METADATA_HAVE_ATIME;
      pr_trace_msg(trace_channel, 15, "using atime %lu for %s key",
        (unsigned long) atime, k);

    } else {
      pr_trace_msg(trace_channel, 7, "unable to convert '%s' to atime: %s", v,
        strerror(errno));
    }
  }

  k = AWS_S3_FSIO_METADATA_KEY_SIZE;
  v = pr_table_get(tab, k, NULL);
  if (v != NULL) {
    off_t size;

    if (aws_utils_str_s2off(p, v, &size) == 0) {
      st->st_size = size;
      (*st_bits) |= AWS_S3_FSIO_METADATA_HAVE_SIZE;
      pr_trace_msg(trace_channel, 15, "using size %" PR_LU " for %s key",
        (pr_off_t) size, k);

    } else {
      pr_trace_msg(trace_channel, 7, "unable to convert '%s' to size: %s", v,
        strerror(errno));
    }
  }

  k = AWS_S3_FSIO_METADATA_KEY_UID;
  v = pr_table_get(tab, k, NULL);
  if (v != NULL) {
    uid_t uid;

    if (pr_str2uid(v, &uid) == 0) {
      st->st_uid = uid;
      (*st_bits) |= AWS_S3_FSIO_METADATA_HAVE_UID;
      pr_trace_msg(trace_channel, 15, "using UID %lu for %s key",
        (unsigned long) uid, k);

    } else {
      pr_trace_msg(trace_channel, 7, "unable to convert '%s' to UID: %s", v,
        strerror(errno));
    }
  }

  k = AWS_S3_FSIO_METADATA_KEY_GID;
  v = pr_table_get(tab, k, NULL);
  if (v != NULL) {
    gid_t gid;

    if (pr_str2gid(v, &gid) == 0) {
      st->st_gid = gid;
      (*st_bits) |= AWS_S3_FSIO_METADATA_HAVE_GID;
      pr_trace_msg(trace_channel, 15, "using GID %lu for %s key",
        (unsigned long) gid, k);

    } else {
      pr_trace_msg(trace_channel, 7, "unable to convert '%s' to GID: %s", v,
        strerror(errno));
    }
  }

  st->st_blksize = AWS_S3_FSIO_DEFAULT_BLOCKSZ;
  st->st_blocks = (st->st_size / st->st_blksize) + 1;

  return 0;
}

/* Get the "next" FS in line, for working with the underlying disk.  We walk
 * the next pointers ourselves, making sure to honor the mount point.
 *
 * XXX Use the FSIO_FILE/DIR_ op codes here, for also searching for the function
 * pointer to the desired FSIO operation, and reduce duplication of while
 * loops in our callbacks.
 *
 * XXX Found/file/fix bug in core FSIO API.  Specifically, multiple non-root
 * FSIO objects are NOT chained, by mount point, as one would expect.  Right
 * now, ALL custom FSIO object next pointer points to the root FSIO.
 */
static pr_fs_t *get_next_fs(pr_fs_t *fs, int opcode) {
  pr_fs_t *next_fs;

  next_fs = fs->fs_next;
  if (next_fs == NULL) {
    return fs;
  }

  /* XXX Check mount points? */

  while (next_fs != NULL &&
         next_fs->fs_next != NULL) {
    int use_fs = TRUE;

    pr_signals_handle();

    switch (opcode) {
      case FSIO_FILE_STAT:
        if (next_fs->stat == NULL) {
          use_fs = FALSE;
        }
        break;

      case FSIO_FILE_FSTAT:
        if (next_fs->fstat == NULL) {
          use_fs = FALSE;
        }
        break;

      case FSIO_FILE_LSTAT:
        if (next_fs->lstat == NULL) {
          use_fs = FALSE;
        }
        break;

      case FSIO_FILE_READ:
        if (next_fs->read == NULL) {
          use_fs = FALSE;
        }
        break;

      case FSIO_FILE_WRITE:
        if (next_fs->write == NULL) {
          use_fs = FALSE;
        }
        break;

      case FSIO_FILE_OPEN:
        if (next_fs->open == NULL) {
          use_fs = FALSE;
        }
        break;

      case FSIO_FILE_CLOSE:
        if (next_fs->close == NULL) {
          use_fs = FALSE;
        }
        break;

      case FSIO_FILE_UNLINK:
        if (next_fs->unlink == NULL) {
          use_fs = FALSE;
        }
        break;

      default:
        pr_trace_msg(trace_channel, 1,
          "unsupported FSIO opcode (%d), ignoring", opcode);
        break;
    }

    if (use_fs == TRUE) {
      break;
    }

    next_fs = next_fs->fs_next;
  }

  return next_fs;
}

/* FSIO Support/Helpers */

/* Note that for a given file, we can only set SOME of its metadata, not
 * all of it.  Namely, we can try to set the time fields, the permissions,
 * and maybe the ownership.  It's best-effort, so ignore EACCES/EPERM.
 */
static int set_shadow(pool *p, pr_fh_t *fh, int fd, const char *path,
    struct stat *st, unsigned int st_bits) {
  pr_fs_t *next_fs;
  int res;

  if ((st_bits & AWS_S3_FSIO_METADATA_HAVE_UID) ||
      (st_bits & AWS_S3_FSIO_METADATA_HAVE_GID)) {
    uid_t uid = -1;
    gid_t gid = -1;

    if (st_bits & AWS_S3_FSIO_METADATA_HAVE_UID) {
      uid = st->st_uid;
    }

    if (st_bits & AWS_S3_FSIO_METADATA_HAVE_GID) {
      gid = st->st_gid;
    }

    next_fs = get_next_fs(fh->fh_fs, FSIO_FILE_CHOWN);
    if (fd < 0) {
      res = (next_fs->chown)(next_fs, path, uid, gid);

    } else {
      res = (next_fs->fchown)(fh, fd, uid, gid);
    }

    if (res < 0 &&
        errno != EACCES &&
        errno != EPERM) {
      return -1;
    }
  }

  if (st_bits & AWS_S3_FSIO_METADATA_HAVE_MODE) {
    mode_t mode;

    mode = st->st_mode & ~S_IFMT;
    next_fs = get_next_fs(fh->fh_fs, FSIO_FILE_CHMOD);
    if (fd < 0) {
      res = (next_fs->chmod)(next_fs, path, mode);

    } else {
      res = (next_fs->fchmod)(fh, fd, mode);
    }

    if (res < 0 &&
        errno != EACCES &&
        errno != EPERM) {
      return -1;
    }
  }

  if ((st_bits & AWS_S3_FSIO_METADATA_HAVE_ATIME) ||
      (st_bits & AWS_S3_FSIO_METADATA_HAVE_MTIME)) {
    struct timeval tvs[2];

    tvs[0].tv_sec = tvs[1].tv_sec = time(NULL);
    tvs[0].tv_usec = tvs[1].tv_usec = 0;

    if (st_bits & AWS_S3_FSIO_METADATA_HAVE_ATIME) {
      tvs[0].tv_sec = st->st_atime;
    }

    if (st_bits & AWS_S3_FSIO_METADATA_HAVE_MTIME) {
      tvs[1].tv_sec = st->st_mtime;
    }

    next_fs = get_next_fs(fh->fh_fs, FSIO_FILE_UTIMES);
    if (fd < 0) {
      res = (next_fs->utimes)(next_fs, path, tvs);

    } else {
      res = (next_fs->futimes)(fh, fd, tvs);
    }

    if (res < 0 &&
        errno != EACCES &&
        errno != EPERM) {
      return -1;
    }
  }

  return 0;
}

/* Map from open(2) flags to access(2) modes. */
static int access_modes_for_open_flags(int flags) {
  int modes = 0;

  /* Mask off any flags other than O_RDONLY, O_WRONLY, and O_RDWR.  The other
   * open(2) flags have no bearing on access(2) checks.
   */
  flags &= (O_RDONLY|O_WRONLY|O_RDWR);

  if (flags == O_RDONLY) {
    modes = R_OK;

  } else {
    if (flags & O_WRONLY) {
      modes = W_OK;
    }

    if (flags & O_RDWR) {
      modes = R_OK|W_OK;
    }
  }

  return modes;
}

static int create_shadow(pool *p, pr_fh_t *fh, const char *path, int flags,
    struct stat *st, unsigned int st_bits) {
  pr_fs_t *next_fs;
  int fd = -1;

  if (st != NULL) {
    /* To perform an access(2)-like check, the S3 object data must have at
     * least the UID, GID, and mode bits.
     */
    if ((st_bits & AWS_S3_FSIO_METADATA_HAVE_UID) &&
        (st_bits & AWS_S3_FSIO_METADATA_HAVE_GID) &&
        (st_bits & AWS_S3_FSIO_METADATA_HAVE_MODE)) {
      int amode, res;

      amode = access_modes_for_open_flags(flags);
      res = pr_fs_have_access(st, amode, session.uid, session.gid,
        session.gids);
      if (res < 0) {
        return -1;
      }
    }
  }

  next_fs = get_next_fs(fh->fh_fs, FSIO_FILE_OPEN);
  fd = (next_fs->open)(fh, path, flags);
  if (fd < 0) {
    return -1;
  }

  if (st != NULL) {
    int res;

    res = set_shadow(p, fh, fd, path, st, st_bits);
    if (res < 0) {
      int xerrno = errno;

      next_fs = get_next_fs(fh->fh_fs, FSIO_FILE_CLOSE);
      (void) (next_fs->close)(fh, fd);

      next_fs = get_next_fs(fh->fh_fs, FSIO_FILE_UNLINK);
      (void) (next_fs->unlink)(next_fs, path);

      errno = xerrno;
      return -1;
    }
  }

  return fd;
}

static void delete_shadow(pool *p, pr_fs_t *fs, const char *path) {
  pr_fs_t *next_fs;
  int res;

  (void) p;

  next_fs = get_next_fs(fs, FSIO_FILE_UNLINK);
  res = (next_fs->unlink)(next_fs, path);
  if (res < 0) {
    if (errno != ENOENT) {
      pr_trace_msg(trace_channel, 1,
        "error deleting local shadow copy of '%s': %s", path, strerror(errno));
    }

  } else {
    pr_trace_msg(trace_channel, 15,
      "no S3 object found for path '%s', local shadow copy deleted", path);
  }
}

static int object_stat(pool *p, struct s3_fsio *s3fs, const char *path,
    struct stat *st, const char *desc) {
  int res;
  pr_table_t *object_metadata;
  const char *object_key;

  object_metadata = pr_table_alloc(p, 0);
  object_key = pstrcat(p, s3fs->object_prefix, path, NULL);

  pr_trace_msg(trace_channel, 19,
    "using bucket %s, object key %s for %s on path %s", s3fs->bucket_name,
    object_key, desc, path);

  res = aws_s3_object_stat(p, s3fs->s3, s3fs->bucket_name, object_key,
    object_metadata);
  if (res == 0) {
    unsigned int st_bits;

    res = aws_s3_fsio_table2stat(p, object_metadata, st, &st_bits);
    if (res < 0) {
      pr_trace_msg(trace_channel, 4,
        "error converting S3 object metadata (bucket %s, object %s) "
        "to struct stat: %s", s3fs->bucket_name, object_key, strerror(errno));
    }

    res = 0;
  }

  return res;
}

static const char *make_object_key(pool *p, struct s3_fsio *s3fs,
    const char *path) {
  const char *object_key;

  if (path[0] == '/') {
    object_key = pstrcat(p, s3fs->object_prefix, path+1, NULL);

  } else {
    object_key = pstrcat(p, s3fs->object_prefix, path, NULL);
  }

  return object_key;
}

/* FSIO Callbacks */

static int s3_fsio_stat(pr_fs_t *fs, const char *path, struct stat *st) {
  int res, xerrno, have_shadow = TRUE;
  struct s3_fsio *s3fs;
  pr_fs_t *next_fs;
  pool *tmp_pool;

  s3fs = fs->fs_data;
  next_fs = get_next_fs(fs, FSIO_FILE_STAT);
  res = (next_fs->stat)(next_fs, path, st);
  xerrno = errno;

  if (res < 0) {
    if (xerrno == ENOENT) {
      /* XXX Possibly check here to see if there is an S3 object for this path;
       * if so, create/mirror that s3 object onto local disk?  This is also
       * why having x-amz-meta-mode store the file type is important: would
       * we need to create a file, or directory, etc on disk?
       */

      have_shadow = FALSE;
    }

    return -1;
  }

  /* Now that we have the on-disk stat data, check for the S3 object and get
   * its stat data.
   */

  tmp_pool = make_sub_pool(fs->fs_pool);
  res = object_stat(tmp_pool, s3fs, path, st, "stat(2)");
  xerrno = errno;

  if (res < 0 &&
      xerrno == ENOENT) {

    /* If we DON'T have the S3 object, but DO have the local shadow copy, then
     * we need to unlink the local shadow copy. S3 is authoritative.
     */
    if (have_shadow == TRUE) {
      delete_shadow(tmp_pool, next_fs, path);
    }
  }

  destroy_pool(tmp_pool);
  errno = xerrno;
  return 0;
}

static int s3_fsio_fstat(pr_fh_t *fh, int fd, struct stat *st) {
  int res, xerrno;
  struct s3_fsio *s3fs;
  pr_fs_t *next_fs;
  pool *tmp_pool;

  s3fs = fh->fh_fs->fs_data;
  next_fs = get_next_fs(fh->fh_fs, FSIO_FILE_FSTAT);
  res = (next_fs->fstat)(fh, fd, st);
  xerrno = errno;

  if (res < 0) {
    if (xerrno == ENOENT) {
      /* XXX Possibly check here to see if there is an S3 object for this path;
       * if so, create/mirror that s3 object onto local disk?  This is also
       * why having x-amz-meta-mode store the file type is important: would
       * we need to create a file, or directory, etc on disk?
       */
    }

    return -1;
  }

/* XXX TODO Use cached stat in fh->fh_data->s3fh? */

  /* Now that we have the on-disk stat data, check for the S3 object and get
   * its stat data.
   */

  tmp_pool = make_sub_pool(fh->fh_fs->fs_pool);
  res = object_stat(tmp_pool, s3fs, fh->fh_path, st, "fstat(2)");
  destroy_pool(tmp_pool);

  return 0;
}

static int s3_fsio_lstat(pr_fs_t *fs, const char *path, struct stat *st) {
  int res, xerrno;
  struct s3_fsio *s3fs;
  pr_fs_t *next_fs;
  pool *tmp_pool;

  s3fs = fs->fs_data;
  next_fs = get_next_fs(fs, FSIO_FILE_LSTAT);
  res = (next_fs->lstat)(next_fs, path, st);
  xerrno = errno;

  if (res < 0) {
    if (xerrno == ENOENT) {
      /* XXX Possibly check here to see if there is an S3 object for this path;
       * if so, create/mirror that s3 object onto local disk?  This is also
       * why having x-amz-meta-mode store the file type is important: would
       * we need to create a file, or directory, etc on disk?
       */
    }

    return -1;
  }

  /* Now that we have the on-disk stat data, check for the S3 object and get
   * its stat data.
   */

  tmp_pool = make_sub_pool(fs->fs_pool);
  res = object_stat(tmp_pool, s3fs, path, st, "lstat(2)");
  destroy_pool(tmp_pool);

  return 0;
}

static int s3_fsio_rename(pr_fs_t *fs, const char *src, const char *dst) {

  /* XXX TODO:
   *  IF within bucket, implemented as COPY + DELETE.
   *  IF into bucket, implemented as an upload + unlink(2).
   *  If out of bucket, implemented as download + DELETE.
   */

  errno = ENOSYS;
  return -1;
}

static int s3_fsio_unlink(pr_fs_t *fs, const char *path) {
  int res, xerrno;
  struct s3_fsio *s3fs;
  pr_fs_t *next_fs;
  pool *tmp_pool;
  const char *object_key;

  s3fs = fs->fs_data;
  next_fs = get_next_fs(fs, FSIO_FILE_UNLINK);

  tmp_pool = make_sub_pool(fs->fs_pool);
  object_key = make_object_key(tmp_pool, s3fs, path);
  res = aws_s3_object_delete(tmp_pool, s3fs->s3, s3fs->bucket_name, object_key);
  xerrno = errno;
  destroy_pool(tmp_pool);

  /* HTTP DELETE almost always succeeds with AWS S3, even if the deleted S3
   * object never existed in the first place.  Thus we cannot use that for
   * providing a valid existence check here.
   */
  if (res < 0) {
    pr_trace_msg(trace_channel, 3, "error deleting S3 object for path '%s': %s",
      path, strerror(xerrno));
  }

  res = (next_fs->unlink)(next_fs, path);
  return res;
}

static int fsio_open_readonly(pool *p, struct s3_fsio *s3fs,
    const char *object_key, pr_fh_t *fh, const char *path, int flags) {
  int fd = -1, res, xerrno;
  pr_fs_t *next_fs;
  struct stat st, *pst = NULL;
  unsigned int st_bits = 0;
  pr_table_t *object_metadata;
  struct s3_fh *s3fh;

  object_metadata = pr_table_alloc(p, 0);

  res = aws_s3_object_stat(p, s3fs->s3, s3fs->bucket_name, object_key,
    object_metadata);
  xerrno = errno;

  if (res < 0) {
    if (xerrno == ENOENT) {
      /* Make sure no local shadow copy exists. */
      delete_shadow(p, fh->fh_fs, path);
    }

    errno = xerrno;
    return -1;
  }

  next_fs = get_next_fs(fh->fh_fs, FSIO_FILE_STAT);
  res = (next_fs->stat)(next_fs, path, &st);
  xerrno = errno;

  memset(&st, 0, sizeof(struct stat));
  if (aws_s3_fsio_table2stat(p, object_metadata, &st, &st_bits) == 0) {
    pst = &st;
  }

  if (res < 0) {
    if (xerrno != ENOENT) {
      /* We have the S3 object, but can't open the local file for reading. */
      errno = xerrno;
      return -1;
    }

    /* Make a local shadow file. */
    fd = create_shadow(p, fh, path, O_CREAT|O_WRONLY, pst, st_bits);
    if (fd < 0) {
      return -1;
    }

    /* Note that we close our just-opened fd here because we need to re-open
     * it a little later with the O_RDONLY flag.
     */

    next_fs = get_next_fs(fh->fh_fs, FSIO_FILE_CLOSE);
    (void) (next_fs->close)(fh, fd);
    fd = -1;

  } else {
    /* Ensure that the local shadow has the correct stat(2) data.  S3 is
     * considered authoritative.
     */
    if (pst != NULL) {
      res = set_shadow(p, fh, -1, path, pst, st_bits);
      if (res < 0) {
        return -1;
      }
    }
  }

  next_fs = get_next_fs(fh->fh_fs, FSIO_FILE_OPEN);
  fd = (next_fs->open)(fh, path, flags);
  if (fd < 0) {
    return -1;
  }

  s3fh = pcalloc(fh->fh_pool, sizeof(struct s3_fh));
  s3fh->read_only = TRUE;
  s3fh->open_flags = flags;

  if (pst != NULL) {
    /* Note that we cache the stat here, converted from the S3 object metadata,
     * for use in e.g. pr_fsio_fstat() et al, so that what the engine sees
     * is not the filesystem view, but the S3 view.
     */
    memcpy(&(s3fh->st), pst, sizeof(struct stat));
  }

  fh->fh_data = s3fh;

  /* XXX Perform the prefetch/read-ahead here, since we know it's going to be
   * a read-only handle?
   */

  return fd;
}

static int s3_fsio_open(pr_fh_t *fh, const char *path, int flags) {
  int res, xerrno, readonly = TRUE;
  struct s3_fsio *s3fs;
  struct s3_fh *s3fh;
  pr_fs_t *next_fs;
  pool *tmp_pool;
  struct stat st;
  const char *object_key;
  pr_table_t *object_metadata;

  s3fs = fh->fh_fs->fs_data;

  /* There are some flags which do not make sense for this FS.
   *
   * For example, we COULD twiddle O_NONBLOCK off.  BUT we might want to
   * use that for determining when/how to flush reads/writes, for example
   */

  if ((flags & O_WRONLY) ||
      (flags & O_RDWR)) {
    readonly = FALSE;

  } else {
    readonly = TRUE;
  }

  /* Make sure the caller specified one of O_RDONLY, O_WRONLY, or O_RDWR.
   * Usually we'd like open(2) handle this sanity check, but we also need the
   * above flags to determine our S3 semantics.
   */
  if (readonly == TRUE &&
      flags != O_RDONLY) {
    errno = EINVAL;
    return -1;
  }

  tmp_pool = make_sub_pool(fh->fh_pool);
  object_key = make_object_key(tmp_pool, s3fs, path);

  /* XXX Store flags in fh->fh_data! */

  if (readonly == TRUE) {
    res = fsio_open_readonly(tmp_pool, s3fs, object_key, fh, path, flags);
    xerrno = errno;

    destroy_pool(tmp_pool);

    errno = xerrno;
    return res;
  }

  object_metadata = pr_table_alloc(tmp_pool, 0);

  if (flags & O_CREAT) {
    int fd;

    if (flags & O_EXCL) {
      res = aws_s3_object_stat(tmp_pool, s3fs->s3, s3fs->bucket_name,
        object_key, object_metadata);
      xerrno = errno;

      if (res == 0) {
        destroy_pool(tmp_pool);
        errno = EEXIST;
        return -1;
      }
    }

    /* In order to populate the object_metadata table, we'll first need
     * to open(2) the fd in question, then do an fstat(2) on it, and
     * convert that stat info to a metadata table.  Whee!
     *
     * OR we can simply synthesize the stat info from session:
     *
     *  st.st_size == ???
     *  st.st_uid = session.fsuid;
     *  st.st_gid = session.fsgid;
     *  st.st_atime = st.st_mtime = time();
     *  st.st_mode = PR_OPEN_MODE & Umask?
     *
     * Except that we DO want the local shadow copy to be created, so
     * synthesizing is not the route we'll take.
     */

    fd = create_shadow(tmp_pool, fh, path, flags, &st, 0);
    xerrno = errno;

    next_fs = get_next_fs(fh->fh_fs, FSIO_FILE_FSTAT);
    xerrno = errno;

  } else {
    res = aws_s3_object_stat(tmp_pool, s3fs->s3, s3fs->bucket_name,
      object_key, object_metadata);
    xerrno = errno;

    if (res < 0) {
      /* Make sure no local shadow copy exists. */
      delete_shadow(tmp_pool, fh->fh_fs, path);

      destroy_pool(tmp_pool);
      errno = xerrno;
      return -1;
    }

    if (flags & O_APPEND) {
/* XXX Can't append to existing object; we'd need to COPY it and DELETE old
 * object?
 */
    }
  }

  /* XXX TODO:
   *  If reading, do stat() of requested object for existence.  (If exists,
   *    also ensure that local shadow copy exists?)
   *  If writing, first open local file.  Then start multipart upload.
   *
   *  To get the object_metadata, open the fd FIRST (using next_fs), then
   *  use fstat() on it to get the stat data!
   *
   *  To handle:
   *    O_RDONLY
   *    O_WRONLY
   *    O_RDWR
   *
   *    O_TRUNC (delete existing S3 object?)
   *    O_CREAT (or not)
   *    O_APPEND
   *    O_EXCL
   *
   *    open() on a directory path?
   */
  errno = ENOSYS;
  return -1;
}

static int s3_fsio_close(pr_fh_t *fh, int fd) {
  int res, xerrno;
  struct s3_fsio *s3fs;
  struct s3_fh *s3fh;
  pr_fs_t *next_fs;
  pool *tmp_pool;
  const char *object_key;

  next_fs = get_next_fs(fh->fh_fs, FSIO_FILE_CLOSE);

  s3fh = fh->fh_data;
  if (s3fh->read_only) {
    return (next_fs->close)(fh, fd);
  }

  s3fs = fh->fh_fs->fs_data;

  /* XXX TODO:
   *  If writing, ...
   */

  errno = ENOSYS;
  return -1;
}

static int s3_fsio_read(pr_fh_t *fh, int fd, char *buf, size_t bufsz) {
  /* XXX If fh_data flags show this as NOT open for reading, then EPERM */
  /* XXX aws_s3_object_get().  Double-buffering into fh->fh_buf? */
  errno = ENOSYS;
  return -1;
}

static int s3_fsio_write(pr_fh_t *fh, int fd, const char *buf, size_t bufsz) {
  /* XXX If fh_data flags show this as NOT open for writing, then EPERM */
  /* XXX aws_s3_object_put()?.  Double-buffering via fh->fh_buf? */
  errno = ENOSYS;
  return -1;
}

static off_t s3_fsio_lseek(pr_fh_t *fh, int fd, off_t offset, int flags) {
  errno = ENOSYS;
  return (off_t) -1;
}

static int s3_fsio_link(pr_fs_t *fs, const char *target_path,
    const char *link_path) {
  pr_trace_msg(trace_channel, 3,
    "creation of hard links via link(2) not allowed within an S3 FS");
  errno = EPERM;
  return -1;
}

static int s3_fsio_symlink(pr_fs_t *fs, const char *target_path,
    const char *link_path) {
  pr_trace_msg(trace_channel, 3,
    "creation of symlinks via symlink(2) not allowed within an S3 FS");
  errno = EPERM;
  return -1;
}

static int s3_fsio_ftruncate(pr_fh_t *fh, int fd, off_t offset) {
  errno = ENOSYS;
  return -1;
}

static int s3_fsio_truncate(pr_fs_t *fs, const char *path, off_t offset) {
  errno = ENOSYS;
  return -1;
}

static int s3_fsio_chmod(pr_fs_t *fs, const char *path, mode_t perms) {
  /* XXX TODO: Implement as COPY, with new metadata. */

  errno = ENOSYS;
  return -1;
}

static int s3_fsio_fchmod(pr_fh_t *fh, int fd, mode_t perms) {
  errno = ENOSYS;
  return -1;
}

static int s3_fsio_chown(pr_fs_t *fs, const char *path, uid_t uid, gid_t gid) {
  /* XXX TODO: Implement as COPY, with new metadata. */

  errno = ENOSYS;
  return -1;
}

static int s3_fsio_fchown(pr_fh_t *fh, int fd, uid_t uid, gid_t gid) {
  errno = ENOSYS;
  return -1;
}

static int s3_fsio_lchown(pr_fs_t *fs, const char *path, uid_t uid, gid_t gid) {
  errno = ENOSYS;
  return -1;
}

static int s3_fsio_access(pr_fs_t *fs, const char *path, int mode, uid_t uid,
    gid_t gid, array_header *suppl_gids) {
  errno = ENOSYS;
  return -1;
}

static int s3_fsio_faccess(pr_fh_t *fh, int mode, uid_t uid, gid_t gid,
    array_header *suppl_gids) {
  errno = ENOSYS;
  return -1;
}

static int s3_fsio_utimes(pr_fs_t *fs, const char *path, struct timeval *tvs) {
  /* XXX TODO: Implement as COPY, with new metadata. */

  errno = ENOSYS;
  return -1;
}

static int s3_fsio_futimes(pr_fh_t *fh, int fd, struct timeval *tvs) {
  return s3_fsio_utimes(fh->fh_fs, fh->fh_path, tvs);
}

static int s3_fsio_fsync(pr_fh_t *fh, int fd) {
  errno = ENOSYS;
  return -1;
}

static ssize_t s3_fsio_getxattr(pool *p, pr_fs_t *fs, const char *path,
    const char *name, void *val, size_t valsz) {
  errno = ENOSYS;
  return -1;
}

static ssize_t s3_fsio_lgetxattr(pool *p, pr_fs_t *fs, const char *path,
    const char *name, void *val, size_t valsz) {
  errno = ENOSYS;
  return -1;
}

static ssize_t s3_fsio_fgetxattr(pool *p, pr_fh_t *fh, int fd,
    const char *name, void *val, size_t valsz) {
  errno = ENOSYS;
  return -1;
}

static int s3_fsio_listxattr(pool *p, pr_fs_t *fs, const char *path,
    array_header **xattrs) {
  errno = ENOSYS;
  return -1;
}

static int s3_fsio_llistxattr(pool *p, pr_fs_t *fs, const char *path,
    array_header **xattrs) {
  errno = ENOSYS;
  return -1;
}

static int s3_fsio_flistxattr(pool *p, pr_fh_t *fh, int fd,
    array_header **xattrs) {
  errno = ENOSYS;
  return -1;
}

static int s3_fsio_removexattr(pool *p, pr_fs_t *fs, const char *path,
    const char *name) {
  errno = ENOSYS;
  return -1;
}

static int s3_fsio_lremovexattr(pool *p, pr_fs_t *fs, const char *path,
    const char *name) {
  errno = ENOSYS;
  return -1;
}

static int s3_fsio_fremovexattr(pool *p, pr_fh_t *fh, int fd,
    const char *name) {
  errno = ENOSYS;
  return -1;
}

static int s3_fsio_setxattr(pool *p, pr_fs_t *fs, const char *path,
    const char *name, void *val, size_t valsz, int flags) {
  errno = ENOSYS;
  return -1;
}

static int s3_fsio_lsetxattr(pool *p, pr_fs_t *fs, const char *path,
    const char *name, void *val, size_t valsz, int flags) {
  errno = ENOSYS;
  return -1;
}

static int s3_fsio_fsetxattr(pool *p, pr_fh_t *fh, int fd, const char *name,
    void *val, size_t valsz, int flags) {
  errno = ENOSYS;
  return -1;
}

static int s3_fsio_chdir(pr_fs_t *fs, const char *path) {
  /* XXX TODO: Rely on local shadow copy implementation for this? */

  errno = ENOSYS;
  return -1;
}

static int s3_fsio_chroot(pr_fs_t *fs, const char *path) {
  /* XXX TODO: Rely on local shadow copy implementation for this? */

  errno = ENOSYS;
  return -1;
}

static void *s3_fsio_opendir(pr_fs_t *fs, const char *path) {
  /* XXX TODO: Rely on local shadow copy implementation for this? */
  /* XXX What if no local shadow copy, but there IS a bucket/directory for
   * the name, with objects?
   */

  errno = ENOSYS;
  return NULL;
}

static int s3_fsio_closedir(pr_fs_t *fs, void *dirh) {
  /* XXX TODO: Rely on local shadow copy implementation for this? */

  errno = ENOSYS;
  return -1;
}

static struct dirent *s3_fsio_readdir(pr_fs_t *fs, void *dirh) {
  /* XXX TODO: Rely on local shadow copy implementation for MOST of this,
   * however we would need an object_stat() per entry to get the rest of
   * the object metadata.
   */

  errno = ENOSYS;
  return NULL;
}

static int s3_fsio_mkdir(pr_fs_t *fs, const char *path, mode_t perms) {
  /* XXX TODO: First, make the local shadow copy directory.  Then, create
   * an S3 object, whose name ends in "/" (to be treated as a directory/folder
   * by the AWS Console), and whose Content-Type is "application/x-directory"
   * (for interoperability with e.g. s3fs).
   */

  errno = ENOSYS;
  return -1;
}

static int s3_fsio_rmdir(pr_fs_t *fh, const char *path) {
  /* XXX TODO: First, delete the S3 object (ensure it's a directory object?),
   * then remove the local shadow copy directory.
   */

  errno = ENOSYS;
  return -1;
}

/* TODO: Add support for:
 *
 * Storage class
 * Server-side encryption
 * Compression
 * Expiration
 */
static struct s3_fsio *get_s3fs(pool *p, struct s3_conn *s3,
    const char *bucket_name, const char *object_prefix) {
  struct s3_fsio *s3fs;
  size_t object_prefixlen;

  s3fs = pcalloc(p, sizeof(struct s3_fsio));
  s3fs->s3 = s3;
  s3fs->bucket_name = pstrdup(p, bucket_name);

  /* Make sure that the prefix ends with "/".  This allows the rest of the
   * code to use pstrcat() when constructing the S3 object keys, rather than
   * having to worry about using pdircat() or not.
   */
  object_prefixlen = strlen(object_prefix);
  if (object_prefixlen == 0) {
    object_prefix = "/";
    object_prefixlen = 1;
  }

  if (object_prefix[object_prefixlen-1] == '/') {
    s3fs->object_prefix = pstrdup(p, object_prefix);
    s3fs->object_prefixlen = object_prefixlen;

  } else {
    s3fs->object_prefix = pstrcat(p, object_prefix, "/", NULL);
    s3fs->object_prefixlen = object_prefixlen + 1;
  }

  return s3fs;
}

pr_fs_t *aws_s3_fsio_get_fs(pool *p, const char *path, struct s3_conn *s3,
    const char *bucket_name, const char *object_prefix) {
  pr_fs_t *fs;
  struct s3_fsio *s3fs;
  size_t path_len;

  if (p == NULL ||
      path == NULL ||
      s3 == NULL ||
      bucket_name == NULL ||
      object_prefix == NULL) {
    errno = EINVAL;
    return NULL;
  }

  path_len = strlen(path);
  if (path[path_len-1] != '/') {
    path = pstrcat(p, path, "/", NULL);
  }

  fs = pr_register_fs(p, "aws.s3", path);
  if (fs == NULL) {
    return NULL;
  }

  /* File operations
   *
   * Note that some operations are deliberately omitted, as they are best
   * handled by the underlying FSIO/filesystem:
   *
   *  - readlink
   */

  fs->stat = s3_fsio_stat;
  fs->fstat = s3_fsio_fstat;
  fs->lstat = s3_fsio_lstat;
  fs->rename = s3_fsio_rename;
  fs->unlink = s3_fsio_unlink;
  fs->open = s3_fsio_open;
  fs->close = s3_fsio_close; 
  fs->read = s3_fsio_read;
  fs->write = s3_fsio_write;
  fs->lseek = s3_fsio_lseek;
  fs->link = s3_fsio_link;
  fs->symlink = s3_fsio_symlink;
  fs->ftruncate = s3_fsio_ftruncate;
  fs->truncate = s3_fsio_truncate;
  fs->chmod = s3_fsio_chmod;
  fs->fchmod = s3_fsio_fchmod;
  fs->chown = s3_fsio_chown;
  fs->fchown = s3_fsio_fchown;
#if PROFTPD_VERSION_NUMBER >= 0x0001030407
  fs->lchown = s3_fsio_lchown;
#endif /* ProFTPD 1.3.4c or later */
  fs->access = s3_fsio_access;
  fs->faccess = s3_fsio_faccess;
  fs->utimes = s3_fsio_utimes;
  fs->futimes = s3_fsio_futimes;
  fs->fsync = s3_fsio_fsync;

  /* Extended attributes */
  fs->getxattr = s3_fsio_getxattr;
  fs->fgetxattr = s3_fsio_fgetxattr;
  fs->lgetxattr = s3_fsio_lgetxattr;
  fs->listxattr = s3_fsio_listxattr;
  fs->flistxattr = s3_fsio_flistxattr;
  fs->llistxattr = s3_fsio_llistxattr;
  fs->removexattr = s3_fsio_removexattr;
  fs->fremovexattr = s3_fsio_fremovexattr;
  fs->lremovexattr = s3_fsio_lremovexattr;
  fs->setxattr = s3_fsio_setxattr;
  fs->fsetxattr = s3_fsio_fsetxattr;
  fs->lsetxattr = s3_fsio_lsetxattr;

  /* Directory operations */
  fs->chdir = s3_fsio_chdir;
  fs->chroot = s3_fsio_chroot;
  fs->opendir = s3_fsio_opendir;
  fs->readdir = s3_fsio_readdir;
  fs->closedir = s3_fsio_closedir;
  fs->mkdir = s3_fsio_mkdir;
  fs->rmdir = s3_fsio_rmdir;

  s3fs = get_s3fs(fs->fs_pool, s3, bucket_name, object_prefix);
  fs->fs_data = s3fs;

  return fs;
}
