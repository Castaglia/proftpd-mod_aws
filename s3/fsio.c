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
#include "s3/conn.h"
#include "s3/bucket.h"
#include "s3/object.h"
#include "s3/fsio.h"

static const char *trace_channel = "aws.s3.fsio";

struct s3_fsio {
  struct s3_conn *s3;
  const char *bucket_name;
  const char *object_prefix;
};

/* FSIO Callbacks */

static int s3_fsio_stat(pr_fs_t *fs, const char *path, struct stat *st) {
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
  errno = ENOSYS;
  return -1;
}

static int s3_fsio_unlink(pr_fs_t *fs, const char *path) {
  errno = ENOSYS;
  return -1;
}

static int s3_fsio_open(pr_fh_t *fh, const char *path, int flags) {
  errno = ENOSYS;
  return -1;
}

static int s3_fsio_close(pr_fh_t *fh, int fd) {
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
  errno = ENOSYS;
  return -1;
}

static int s3_fsio_readlink(pr_fs_t *fs, const char *path, char *buf,
    size_t bufsz) {
  errno = ENOSYS;
  return -1;
}

static int s3_fsio_symlink(pr_fs_t *fs, const char *target_path,
    const char *link_path) {
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
  errno = ENOSYS;
  return -1;
}

static int s3_fsio_fchmod(pr_fh_t *fh, int fd, mode_t perms) {
  errno = ENOSYS;
  return -1;
}

static int s3_fsio_chown(pr_fs_t *fs, const char *path, uid_t uid, gid_t gid) {
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
  errno = ENOSYS;
  return -1;
}

static int s3_fsio_chroot(pr_fs_t *fs, const char *path) {
  errno = ENOSYS;
  return -1;
}

static void *s3_fsio_opendir(pr_fs_t *fs, const char *path) {
  errno = ENOSYS;
  return NULL;
}

static int s3_fsio_closedir(pr_fs_t *fs, void *dirh) {
  errno = ENOSYS;
  return -1;
}

static struct dirent *s3_fsio_readdir(pr_fs_t *fs, void *dirh) {
  errno = ENOSYS;
  return NULL;
}

static int s3_fsio_mkdir(pr_fs_t *fs, const char *path, mode_t perms) {
  errno = ENOSYS;
  return -1;
}

static int s3_fsio_rmdir(pr_fs_t *fh, const char *path) {
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
    const char *bucket_name) {
  pr_fs_t *fs;
  struct s3_fsio *s3fs;

  if (p == NULL ||
      path == NULL ||
      s3 == NULL) {
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

  s3fs = get_s3fs(fs->fs_pool, s3, bucket_name, NULL);
  fs->fs_data = s3fs;

  return fs;
}
