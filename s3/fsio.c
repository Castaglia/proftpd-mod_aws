/*
 * ProFTPD - mod_aws S3 FSIO API
 * Copyright (c) 2016 TJ Saunders
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

static const char *trace_channel = "aws.s3.fsio";

#define AWS_S3_FSIO_DEFAULT_BLOCKSZ			4096

struct s3_fsio {
  struct s3_conn *s3;
  const char *bucket_name;
  const char *object_prefix;
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
int aws_s3_fsio_table2stat(pool *p, pr_table_t *tab, struct stat *st) {
  const char *k, *v;

  if (p == NULL ||
      tab == NULL ||
      st == NULL) {
    errno = EINVAL;
    return -1;
  }

  if (pr_table_count(tab) == 0) {
    pr_trace_msg(trace_channel, 17,
      "empty stat table, not setting stat fields");

    /* Nothing to be done. */
    return 0;
  }

  k = AWS_S3_FSIO_METADATA_KEY_MODE;
  v = pr_table_get(tab, k, NULL);
  if (v != NULL) {
    mode_t mode;

    if (aws_utils_str_s2mode(p, v, &mode) == 0) {
      st->st_mode = mode;

    } else {
      pr_trace_msg(trace_channel, 7, "unable to convert '%s' to mode: %s", v,
        strerror(errno));
    }

  } else {
    pr_trace_msg(trace_channel, 5, "stat table missing expected '%k' key", k);
  }

  k = AWS_S3_FSIO_METADATA_KEY_MTIME;
  v = pr_table_get(tab, k, NULL);
  if (v != NULL) {
    time_t mtime;

    if (aws_utils_str_s2ul(p, v, (unsigned long *) &mtime) == 0) {
      st->st_mtime = mtime;

    } else {
      pr_trace_msg(trace_channel, 7, "unable to convert '%s' to time: %s", v,
        strerror(errno));
    }

  } else {
    pr_trace_msg(trace_channel, 5, "stat table missing expected '%k' key", k);
  }

  k = AWS_S3_FSIO_METADATA_KEY_ATIME;
  v = pr_table_get(tab, k, NULL);
  if (v != NULL) {
    time_t atime;

    if (aws_utils_str_s2ul(p, v, (unsigned long *) &atime) == 0) {
      st->st_atime = atime;

    } else {
      pr_trace_msg(trace_channel, 7, "unable to convert '%s' to time: %s", v,
        strerror(errno));
    }

  } else {
    pr_trace_msg(trace_channel, 5, "stat table missing expected '%k' key", k);
  }

  k = AWS_S3_FSIO_METADATA_KEY_SIZE;
  v = pr_table_get(tab, k, NULL);
  if (v != NULL) {
    off_t size;

    if (aws_utils_str_s2off(p, v, &size) == 0) {
      st->st_size = size;

    } else {
      pr_trace_msg(trace_channel, 7, "unable to convert '%s' to size: %s", v,
        strerror(errno));
    }

  } else {
    pr_trace_msg(trace_channel, 5, "stat table missing expected '%k' key", k);
  }

  k = AWS_S3_FSIO_METADATA_KEY_UID;
  v = pr_table_get(tab, k, NULL);
  if (v != NULL) {
    uid_t uid;

    if (pr_str2uid(v, &uid) == 0) {
      st->st_uid = uid;

    } else {
      pr_trace_msg(trace_channel, 7, "unable to convert '%s' to UID: %s", v,
        strerror(errno));
    }

  } else {
    pr_trace_msg(trace_channel, 5, "stat table missing expected '%k' key", k);
  }

  k = AWS_S3_FSIO_METADATA_KEY_GID;
  v = pr_table_get(tab, k, NULL);
  if (v != NULL) {
    gid_t gid;

    if (pr_str2gid(v, &gid) == 0) {
      st->st_gid = gid;

    } else {
      pr_trace_msg(trace_channel, 7, "unable to convert '%s' to GID: %s", v,
        strerror(errno));
    }

  } else {
    pr_trace_msg(trace_channel, 5, "stat table missing expected '%k' key", k);
  }

  st->st_blksize = AWS_S3_FSIO_DEFAULT_BLOCKSZ;
  st->st_blocks = (st->st_size / st->st_blksize) + 1;

  return 0;
}

/* FSIO Callbacks */

static int s3_fsio_stat(pr_fs_t *fs, const char *path, struct stat *st) {
  struct s3_fsio *s3fs;

  s3fs = fs->fs_data;

  /* XXX TODO: FIRST, stat(2) the path on disk.  Note that this may require
   * some juggling of the FSIO registration entries, in order to get the
   * "next" FS in line.  Or maybe we walk the fs->next pointers ourselves
   * (being sure to honor the mount point?), until we reach "system"?
   */

  errno = ENOSYS;
  return -1;
}

static int s3_fsio_fstat(pr_fh_t *fh, int fd, struct stat *st) {
  errno = ENOSYS;
  return -1;
}

static int s3_fsio_lstat(pr_fs_t *fs, const char *path, struct stat *st) {
  errno = ENOSYS;
  return -1;
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
  errno = ENOSYS;
  return -1;
}

static int s3_fsio_open(pr_fh_t *fh, const char *path, int flags) {
  /* XXX TODO:
   *  If reading, do stat() of requested object for existence.  (If exists,
   *    also ensure that local shadow copy exists?)
   *  If writing, first open local file.  Then start multipart upload.
   */
  errno = ENOSYS;
  return -1;
}

static int s3_fsio_close(pr_fh_t *fh, int fd) {
  /* XXX TODO:
   *  If reading, ...
   *  If writing, ...
   */

  errno = ENOSYS;
  return -1;
}

static int s3_fsio_read(pr_fh_t *fh, int fd, char *buf, size_t bufsz) {
  errno = ENOSYS;
  return -1;
}

static int s3_fsio_write(pr_fh_t *fh, int fd, const char *buf, size_t bufsz) {
  errno = ENOSYS;
  return -1;
}

static off_t s3_fsio_lseek(pr_fh_t *fh, int fd, off_t offset, int flags) {
  errno = ENOSYS;
  return (off_t) -1;
}

static int s3_fsio_link(pr_fs_t *fs, const char *target_path,
    const char *link_path) {
  /* XXX TODO: Rely on local shadow copy implementation for this? */

  errno = ENOSYS;
  return -1;
}

static int s3_fsio_readlink(pr_fs_t *fs, const char *path, char *buf,
    size_t bufsz) {
  /* XXX TODO: Rely on local shadow copy implementation for this? */

  errno = ENOSYS;
  return -1;
}

static int s3_fsio_symlink(pr_fs_t *fs, const char *target_path,
    const char *link_path) {
  /* XXX TODO: Rely on local shadow copy implementation for this? */

  errno = ENOSYS;
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
  errno = ENOSYS;
  return -1;
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

  s3fs = pcalloc(p, sizeof(struct s3_fsio));
  s3fs->s3 = s3;
  s3fs->bucket_name = pstrdup(p, bucket_name);
  s3fs->object_prefix = pstrdup(p, object_prefix);

  return s3fs;
}

pr_fs_t *aws_s3_fsio_get_fs(pool *p, const char *path, struct s3_conn *s3,
    const char *bucket_name, const char *object_prefix) {
  pr_fs_t *fs;
  struct s3_fsio *s3fs;

  if (p == NULL ||
      path == NULL ||
      s3 == NULL ||
      bucket_name == NULL ||
      object_prefix == NULL) {
    errno = EINVAL;
    return NULL;
  }

  fs = pr_register_fs(p, "aws.s3", path);
  if (fs == NULL) {
    return NULL;
  }

  /* File operations */
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
  fs->readlink = s3_fsio_readlink;
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
