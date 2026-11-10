/**
 * @file daemon_setup.cpp
 * @brief The set-up of the daemon: the drop of privileges.
 *
 * Split from softflowd.cpp. See daemon_setup.hpp.
 */
#include "softflowd_cpp/daemon_setup.hpp"
#include "softflowd_cpp/log.hpp"

#include <cerrno>
#include <cstdlib>
#include <cstring>

#include <grp.h>
#include <pwd.h>
#include <syslog.h>
#include <unistd.h>

namespace softflowd_cpp {

#ifndef PRIVDROP_USER
/** The unprivileged user of a daemon (original: PRIVDROP_USER of softflowd.h). */
#define PRIVDROP_USER "nobody"
#endif
#ifndef PRIVDROP_CHROOT_DIR
/** The empty directory that a daemon changes its root to (original: PRIVDROP_CHROOT_DIR of softflowd.h). */
#define PRIVDROP_CHROOT_DIR "/var/empty"
#endif

/**
 * @brief Changes the root directory of a daemon to an empty one, and its user to an unprivileged one.
 *
 * It exits with 1 when it fails.
 *
 * @original drop_privs (). A daemon changes its root directory to an empty one
 * and its user to an unprivileged one once it has what it needs from the
 * system: the capture, the sockets and the files. Exits on failure.
 */
void
drop_privs () {
  struct passwd *pw = getpwnam (PRIVDROP_USER);
  if (pw == nullptr) {
    logit (LOG_ERR, "Unable to find unprivileged user \"%s\"", PRIVDROP_USER);
    std::exit (1);
  }
  if (chdir (PRIVDROP_CHROOT_DIR) != 0) {
    logit (LOG_ERR, "Unable to chdir to chroot directory \"%s\": %s",
           PRIVDROP_CHROOT_DIR, std::strerror (errno));
    std::exit (1);
  }
  if (chroot (PRIVDROP_CHROOT_DIR) != 0) {
    logit (LOG_ERR, "Unable to chroot to directory \"%s\": %s",
           PRIVDROP_CHROOT_DIR, std::strerror (errno));
    std::exit (1);
  }
  if (chdir ("/") != 0) {
    logit (LOG_ERR, "Unable to chdir to chroot root: %s", std::strerror (errno));
    std::exit (1);
  }
  if (setgroups (1, &pw->pw_gid) != 0) {
    logit (LOG_ERR, "Couldn't setgroups (%u): %s",
           static_cast<unsigned int> (pw->pw_gid), std::strerror (errno));
    std::exit (1);
  }
#ifdef __linux__
  if (setresgid (pw->pw_gid, pw->pw_gid, pw->pw_gid) == -1) {
#else
  if (setregid (pw->pw_gid, pw->pw_gid) == -1) {
#endif
    logit (LOG_ERR, "Couldn't set gid (%u): %s",
           static_cast<unsigned int> (pw->pw_gid), std::strerror (errno));
    std::exit (1);
  }
#ifdef __linux__
  if (setresuid (pw->pw_uid, pw->pw_uid, pw->pw_uid) == -1) {
#else
  if (setreuid (pw->pw_uid, pw->pw_uid) == -1) {
#endif
    logit (LOG_ERR, "Couldn't set uid (%u): %s",
           static_cast<unsigned int> (pw->pw_uid), std::strerror (errno));
    std::exit (1);
  }
}

}  // namespace softflowd_cpp
