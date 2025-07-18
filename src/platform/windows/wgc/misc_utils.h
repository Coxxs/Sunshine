/**
 * @file src/platform/windows/wgc/misc_utils.h
 * @brief Minimal utility functions for WGC helper without heavy dependencies
 */

#pragma once

#include <string>
#include <windows.h>

namespace platf {

  namespace wgc {

    /**
     * @brief Check if a process with the given name is running.
     * @param processName The name of the process to check for.
     * @return `true` if the process is running, `false` otherwise.
     */
    bool is_process_running(const std::wstring &processName);

    /**
     * @brief Check if we're on the secure desktop (UAC prompt or login screen).
     * @return `true` if we're on the secure desktop, `false` otherwise.
     */
    bool is_secure_desktop_active();

    /**
     * @brief Check if the current process is running with system-level privileges.
     * @return `true` if the current process has system-level privileges, `false` otherwise.
     */
    bool is_running_as_system();

    /**
     * @brief Obtain the current sessions user's primary token with elevated privileges.
     * @param elevated Specify whether to elevate the process.
     * @return The user's token. If user has admin capability it will be elevated, otherwise it will be a limited token. On error, `nullptr`.
     */
    HANDLE retrieve_users_token(bool elevated);

  }  // namespace wgc

}  // namespace platf
