

#include "shared_memory.h"

#include <aclapi.h>
#include <chrono>
#include <combaseapi.h>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <memory>
#include <src/utility.h>
#include <string>
#include <thread>
#include <vector>
#include <windows.h>
#ifndef SUNSHINE_WGC_HELPER_BUILD
  #include "src/logging.h"
#else
  // Include boost log headers for WGC helper build
  #include <boost/log/core.hpp>
  #include <boost/log/expressions.hpp>
  #include <boost/log/sources/record_ostream.hpp>
  #include <boost/log/sources/severity_logger.hpp>

enum severity_level {
  trace,
  debug,
  info,
  warning,
  error,
  fatal
};

extern boost::log::sources::severity_logger<severity_level> g_logger;
  #define BOOST_LOG(level) BOOST_LOG_SEV(g_logger, level)
#endif
#include "misc_utils.h"

// Helper functions for proper string conversion
std::string wide_to_utf8(const std::wstring &wstr) {
  if (wstr.empty()) {
    return std::string();
  }
  int size_needed = WideCharToMultiByte(CP_UTF8, 0, &wstr[0], (int) wstr.size(), NULL, 0, NULL, NULL);
  std::string strTo(size_needed, 0);
  WideCharToMultiByte(CP_UTF8, 0, &wstr[0], (int) wstr.size(), &strTo[0], size_needed, NULL, NULL);
  return strTo;
}

std::wstring utf8_to_wide(const std::string &str) {
  if (str.empty()) {
    return std::wstring();
  }
  int size_needed = MultiByteToWideChar(CP_UTF8, 0, &str[0], (int) str.size(), NULL, 0);
  std::wstring wstrTo(size_needed, 0);
  MultiByteToWideChar(CP_UTF8, 0, &str[0], (int) str.size(), &wstrTo[0], size_needed);
  return wstrTo;
}

// --- SharedSessionManager Implementation ---
SecuredPipeCoordinator::SecuredPipeCoordinator(IAsyncPipeFactory *pipeFactory):
    _pipeFactory(pipeFactory) {}

std::unique_ptr<IAsyncPipe> SecuredPipeCoordinator::prepare_client(std::unique_ptr<IAsyncPipe> pipe) {
  SecureClientMessage msg {};  // Zero-initialize

  std::vector<uint8_t> bytes;
  auto start = std::chrono::steady_clock::now();
  bool received = false;

  while (std::chrono::steady_clock::now() - start < std::chrono::seconds(3)) {
    pipe->receive(bytes);
    if (!bytes.empty()) {
      received = true;
      break;
    }
    std::this_thread::sleep_for(std::chrono::milliseconds(50));
  }

  if (!received) {
    BOOST_LOG(error) << "Did not receive handshake message in time.";
    pipe->disconnect();
    return nullptr;
  }

  if (bytes.size() < sizeof(SecureClientMessage)) {
    BOOST_LOG(error) << "Received incomplete handshake message.";
    pipe->disconnect();
    return nullptr;
  }

  std::memcpy(&msg, bytes.data(), sizeof(SecureClientMessage));
  pipe->disconnect();

  // Convert wide string to string using proper conversion
  std::wstring wpipeNasme(msg.pipe_name);
  std::wstring weventName(msg.event_name);
  std::string pipeNameStr = wide_to_utf8(wpipeNasme);
  std::string eventNameStr = wide_to_utf8(weventName);

  return _pipeFactory->create(pipeNameStr, eventNameStr, false, true);
}

std::unique_ptr<IAsyncPipe> SecuredPipeCoordinator::prepare_server(std::unique_ptr<IAsyncPipe> pipe) {
  std::string pipe_name = generateGuid();
  std::string event_name = generateGuid();

  std::wstring wpipe_name = utf8_to_wide(pipe_name);
  std::wstring wevent_name = utf8_to_wide(event_name);

  SecureClientMessage message {};
  wcsncpy_s(message.pipe_name, wpipe_name.c_str(), _TRUNCATE);
  wcsncpy_s(message.event_name, wevent_name.c_str(), _TRUNCATE);

  std::vector<uint8_t> bytes(sizeof(SecureClientMessage));
  std::memcpy(bytes.data(), &message, sizeof(SecureClientMessage));
  pipe->send(bytes);

  pipe->disconnect();

  return _pipeFactory->create(pipe_name, event_name, true, true);
}

std::string SecuredPipeCoordinator::generateGuid() {
  GUID guid;
  if (CoCreateGuid(&guid) != S_OK) {
    return {};
  }

  WCHAR guidStr[39];  // "{...}" format, 38 chars + null
  if (StringFromGUID2(guid, guidStr, 39) == 0) {
    return {};
  }

  // Convert WCHAR to std::string using proper conversion
  std::wstring wstr(guidStr);
  return wide_to_utf8(wstr);
}

bool AsyncPipeFactory::create_security_descriptor(SECURITY_DESCRIPTOR &desc) {
  HANDLE token = nullptr;
  TOKEN_USER *tokenUser = nullptr;
  PSID user_sid = nullptr;
  PSID system_sid = nullptr;
  PACL pDacl = nullptr;

  // Use RAII-style cleanup to ensure resources are freed
  auto fg = util::fail_guard([&]() {
    if (tokenUser) {
      free(tokenUser);
    }
    if (token) {
      CloseHandle(token);
    }
    if (system_sid) {
      FreeSid(system_sid);
    }
    if (pDacl) {
      LocalFree(pDacl);
    }
  });

  BOOL isSystem = platf::wgc::is_running_as_system();

  if (isSystem) {
    token = platf::wgc::retrieve_users_token(false);
  } else {
    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &token)) {
      BOOST_LOG(error) << "OpenProcessToken failed in create_security_descriptor, error=" << GetLastError();
      return false;
    }
  }

  // Extract user SID from token
  DWORD len = 0;
  GetTokenInformation(token, TokenUser, nullptr, 0, &len);
  if (GetLastError() != ERROR_INSUFFICIENT_BUFFER) {
    BOOST_LOG(error) << "GetTokenInformation (size query) failed in create_security_descriptor, error=" << GetLastError();
    return false;
  }

  tokenUser = (TOKEN_USER *) malloc(len);
  if (!tokenUser || !GetTokenInformation(token, TokenUser, tokenUser, len, &len)) {
    BOOST_LOG(error) << "GetTokenInformation (fetch) failed in create_security_descriptor, error=" << GetLastError();
    return false;
  }
  user_sid = tokenUser->User.Sid;

  // Create SYSTEM SID if needed
  if (isSystem) {
    SID_IDENTIFIER_AUTHORITY ntAuthority = SECURITY_NT_AUTHORITY;
    if (!AllocateAndInitializeSid(&ntAuthority, 1, SECURITY_LOCAL_SYSTEM_RID, 0, 0, 0, 0, 0, 0, 0, &system_sid)) {
      BOOST_LOG(error) << "AllocateAndInitializeSid failed in create_security_descriptor, error=" << GetLastError();
      return false;
    }
  }

  // Initialize security descriptor
  if (!InitializeSecurityDescriptor(&desc, SECURITY_DESCRIPTOR_REVISION)) {
    BOOST_LOG(error) << "InitializeSecurityDescriptor failed in create_security_descriptor, error=" << GetLastError();
    return false;
  }

  // Set owner
  if (isSystem && system_sid) {
    if (!SetSecurityDescriptorOwner(&desc, system_sid, FALSE)) {
      BOOST_LOG(error) << "SetSecurityDescriptorOwner (system_sid) failed in create_security_descriptor, error=" << GetLastError();
    }
  } else if (user_sid) {
    if (!SetSecurityDescriptorOwner(&desc, user_sid, FALSE)) {
      BOOST_LOG(error) << "SetSecurityDescriptorOwner (user_sid) failed in create_security_descriptor, error=" << GetLastError();
    }
  }

  // Build DACL: allow SYSTEM and user full access
  EXPLICIT_ACCESS ea[2] = {};
  int aceCount = 0;
  if (isSystem && system_sid) {
    ea[aceCount].grfAccessPermissions = GENERIC_ALL;
    ea[aceCount].grfAccessMode = SET_ACCESS;
    ea[aceCount].grfInheritance = NO_INHERITANCE;
    ea[aceCount].Trustee.TrusteeForm = TRUSTEE_IS_SID;
    ea[aceCount].Trustee.TrusteeType = TRUSTEE_IS_USER;
    ea[aceCount].Trustee.ptstrName = (LPTSTR) system_sid;
    aceCount++;
  }
  if (user_sid) {
    ea[aceCount].grfAccessPermissions = GENERIC_ALL;
    ea[aceCount].grfAccessMode = SET_ACCESS;
    ea[aceCount].grfInheritance = NO_INHERITANCE;
    ea[aceCount].Trustee.TrusteeForm = TRUSTEE_IS_SID;
    ea[aceCount].Trustee.TrusteeType = TRUSTEE_IS_USER;
    ea[aceCount].Trustee.ptstrName = (LPTSTR) user_sid;
    aceCount++;
  }
  if (aceCount > 0) {
    DWORD err = SetEntriesInAcl(aceCount, ea, nullptr, &pDacl);
    if (err == ERROR_SUCCESS) {
      if (!SetSecurityDescriptorDacl(&desc, TRUE, pDacl, FALSE)) {
        BOOST_LOG(error) << "SetSecurityDescriptorDacl failed in create_security_descriptor, error=" << GetLastError();
      }
    } else {
      BOOST_LOG(error) << "SetEntriesInAcl failed in create_security_descriptor, error=" << err;
    }
  }
}

// --- AsyncPipeFactory Implementation ---
std::unique_ptr<IAsyncPipe> AsyncPipeFactory::create(
  const std::string &pipeName,
  const std::string &eventName,
  bool isServer,
  bool isSecured
) {
  BOOST_LOG(info) << "AsyncPipeFactory::create called with pipeName='"
                  << pipeName << "', eventName='" << eventName
                  << "', isServer=" << isServer
                  << ", isSecured=" << isSecured;

  auto wPipeBase = utf8_to_wide(pipeName);
  std::wstring fullPipeName = L"\\\\.\\pipe\\" + wPipeBase;  // ← fixed
  std::wstring wEventName = utf8_to_wide(eventName);

  // Build SECURITY_ATTRIBUTES only if requested …
  SECURITY_ATTRIBUTES *pSecAttr = nullptr;
  SECURITY_ATTRIBUTES secAttr {};
  SECURITY_DESCRIPTOR secDesc {};
  if (isSecured) {
    if (!create_security_descriptor(secDesc)) {
      BOOST_LOG(error) << "Failed to init security descriptor";
      return nullptr;
    }
    secAttr = {sizeof(secAttr), &secDesc, FALSE};
    pSecAttr = &secAttr;
    BOOST_LOG(info) << "Security attributes prepared.";
  }

  // Create event (manual‑reset, non‑signaled)
  HANDLE hEvent = CreateEventW(pSecAttr, TRUE, FALSE, wEventName.c_str());
  if (!hEvent) {
    DWORD err = GetLastError();
    BOOST_LOG(error) << "CreateEventW failed (" << err << ")";
    return nullptr;
  }

  HANDLE hPipe = INVALID_HANDLE_VALUE;
  if (isServer) {
    hPipe = CreateNamedPipeW(
      fullPipeName.c_str(),
      PIPE_ACCESS_DUPLEX | FILE_FLAG_OVERLAPPED,
      PIPE_TYPE_BYTE | PIPE_READMODE_BYTE | PIPE_WAIT,
      1,
      65536,
      65536,
      0,
      pSecAttr
    );
  } else {
    hPipe = CreateFileW(
      fullPipeName.c_str(),
      GENERIC_READ | GENERIC_WRITE,
      0,
      nullptr,  // ← always nullptr
      OPEN_EXISTING,
      FILE_FLAG_OVERLAPPED,
      nullptr
    );
  }

  if (hPipe == INVALID_HANDLE_VALUE) {
    DWORD err = GetLastError();
    BOOST_LOG(error) << (isServer ? "CreateNamedPipeW" : "CreateFileW")
                     << " failed (" << err << ")";
    CloseHandle(hEvent);
    return nullptr;
  }

  auto pipeObj = std::make_unique<AsyncPipe>(hPipe, hEvent);
  if (pipeObj) {
    pipeObj->connect();
  }
  BOOST_LOG(info) << "Returning AsyncPipe for '" << pipeName << "'";
  return pipeObj;
}

SecuredPipeFactory::SecuredPipeFactory():
    _pipeFactory(std::make_unique<AsyncPipeFactory>()),
    _coordinator(_pipeFactory.get()) {}

std::unique_ptr<IAsyncPipe> SecuredPipeFactory::create(const std::string &pipeName, const std::string &eventName, bool isServer, bool isSecured) {
  auto first_pipe = _pipeFactory->create(pipeName, eventName, isServer, isSecured);
  if (!first_pipe) {
    return nullptr;
  }
  if (isServer) {
    return _coordinator.prepare_server(std::move(first_pipe));
  }
  return _coordinator.prepare_client(std::move(first_pipe));
}

// --- AsyncPipe Implementation ---
AsyncPipe::AsyncPipe(HANDLE pipe, HANDLE event):
    _pipe(pipe),
    _event(event),
    _connected(false),
    _running(false) {}

AsyncPipe::~AsyncPipe() {
  disconnect();
}

void AsyncPipe::send(std::vector<uint8_t> bytes) {
  if (!_connected || _pipe == INVALID_HANDLE_VALUE) {
    return;
  }
  OVERLAPPED overlapped = {0};
  overlapped.hEvent = _event;
  DWORD bytesWritten = 0;
  BOOL result = WriteFile(_pipe, bytes.data(), static_cast<DWORD>(bytes.size()), &bytesWritten, &overlapped);
  if (!result && GetLastError() == ERROR_IO_PENDING) {
    // Wait for completion
    WaitForSingleObject(_event, INFINITE);
    GetOverlappedResult(_pipe, &overlapped, &bytesWritten, FALSE);
  }
}

void AsyncPipe::receive(std::vector<uint8_t> &bytes) {
  if (!_connected || _pipe == INVALID_HANDLE_VALUE) {
    return;
  }
  bytes.resize(4096);
  OVERLAPPED overlapped = {0};
  overlapped.hEvent = _event;
  DWORD bytesRead = 0;
  BOOL result = ReadFile(_pipe, bytes.data(), static_cast<DWORD>(bytes.size()), &bytesRead, &overlapped);
  if (!result && GetLastError() == ERROR_IO_PENDING) {
    // Wait for completion
    WaitForSingleObject(_event, INFINITE);
    GetOverlappedResult(_pipe, &overlapped, &bytesRead, FALSE);
  }
  bytes.resize(bytesRead);
}

void AsyncPipe::connect() {
  if (_pipe == INVALID_HANDLE_VALUE) {
    return;
  }
  if (!_connected) {
    // For server pipes, use ConnectNamedPipe
    // For client pipes, the connection is already established by CreateFileW
    if (ConnectNamedPipe(_pipe, nullptr) || GetLastError() == ERROR_PIPE_CONNECTED || GetLastError() == ERROR_INVALID_FUNCTION) {
      _connected = true;
    }
  }
}

void AsyncPipe::disconnect() {
  if (_pipe != INVALID_HANDLE_VALUE) {
    FlushFileBuffers(_pipe);
    DisconnectNamedPipe(_pipe);
    CloseHandle(_pipe);
    _pipe = INVALID_HANDLE_VALUE;
  }
  if (_event) {
    CloseHandle(_event);
    _event = nullptr;
  }
  _connected = false;
}

bool AsyncPipe::is_connected() {
  return _connected;
}

// --- AsyncNamedPipe Implementation ---
AsyncNamedPipe::AsyncNamedPipe(std::unique_ptr<IAsyncPipe> pipe):
    _pipe(std::move(pipe)),
    _running(false) {}

AsyncNamedPipe::~AsyncNamedPipe() {
  stop();
}

bool AsyncNamedPipe::start(MessageCallback onMessage, ErrorCallback onError) {
  _onMessage = onMessage;
  _onError = onError;
  _running = true;
  _worker = std::thread(&AsyncNamedPipe::workerThread, this);
  return true;
}

void AsyncNamedPipe::stop() {
  _running = false;
  if (_worker.joinable()) {
    _worker.join();
  }
}

void AsyncNamedPipe::asyncSend(const std::vector<uint8_t> &message) {
  if (_pipe) {
    _pipe->send(message);
  }
}

bool AsyncNamedPipe::isConnected() const {
  return _pipe && _pipe->is_connected();
}

void AsyncNamedPipe::workerThread() {
  while (_running) {
    std::vector<uint8_t> bytes;
    if (_pipe && _pipe->is_connected()) {
      _pipe->receive(bytes);
    } else if (!_pipe) {
      break;  // Exit if pipe is gone
    }

    if (!_running) {
      break;  // Check running flag again after blocking call
    }

    if (!bytes.empty() && _onMessage) {
      _onMessage(bytes);
    }
  }
}
