

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
#include "wgc_logger.h"
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
    pipe->receive(bytes, true);
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

  // Send ACK (1 byte)
  std::vector<uint8_t> ack(1, 0xA5);
  pipe->send(ack, true);

  // Convert wide string to string using proper conversion
  std::wstring wpipeNasme(msg.pipe_name);
  std::wstring weventName(msg.event_name);
  std::string pipeNameStr = wide_to_utf8(wpipeNasme);
  std::string eventNameStr = wide_to_utf8(weventName);

  // Disconnect control pipe only after ACK is sent
  pipe->disconnect();

  // Retry logic for opening the data pipe
  std::unique_ptr<IAsyncPipe> data_pipe = nullptr;
  auto retry_start = std::chrono::steady_clock::now();
  const auto retry_timeout = std::chrono::seconds(5);
  
  while (std::chrono::steady_clock::now() - retry_start < retry_timeout) {
    // Use non-secured pipe for now to avoid security descriptor issues
    data_pipe = _pipeFactory->create(pipeNameStr, eventNameStr, false, false);
    if (data_pipe) {
      break;
    }
    
    BOOST_LOG(debug) << "Retrying data pipe connection...";
    std::this_thread::sleep_for(std::chrono::milliseconds(100));
  }

  if (!data_pipe) {
    BOOST_LOG(error) << "Failed to connect to data pipe after retries";
  }

  return data_pipe;
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
  pipe->send(bytes, true); // Synchronous send

  // Wait for client ACK (1 byte)
  std::vector<uint8_t> ack;
  auto start = std::chrono::steady_clock::now();
  bool got_ack = false;
  while (std::chrono::steady_clock::now() - start < std::chrono::seconds(3)) {
    pipe->receive(ack, true);
    if (ack.size() == 1 && ack[0] == 0xA5) {
      got_ack = true;
      break;
    }
    std::this_thread::sleep_for(std::chrono::milliseconds(10));
  }
  if (!got_ack) {
    BOOST_LOG(error) << "Handshake ACK timeout";
    pipe->disconnect();
    return nullptr;
  }

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

  // Validate the user SID
  if (!IsValidSid(user_sid)) {
    BOOST_LOG(error) << "Invalid user SID in create_security_descriptor";
    return false;
  }

  // Create SYSTEM SID if needed
  if (isSystem) {
    SID_IDENTIFIER_AUTHORITY ntAuthority = SECURITY_NT_AUTHORITY;
    if (!AllocateAndInitializeSid(&ntAuthority, 1, SECURITY_LOCAL_SYSTEM_RID, 0, 0, 0, 0, 0, 0, 0, &system_sid)) {
      BOOST_LOG(error) << "AllocateAndInitializeSid failed in create_security_descriptor, error=" << GetLastError();
      return false;
    }
    
    // Validate the system SID
    if (!IsValidSid(system_sid)) {
      BOOST_LOG(error) << "Invalid system SID in create_security_descriptor";
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
        return false;
      }
    } else {
      BOOST_LOG(error) << "SetEntriesInAcl failed in create_security_descriptor, error=" << err;
      return false;
    }
  }
  
  return true; // Success
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
    // Wait for the server to be ready
    if (!WaitNamedPipeW(fullPipeName.c_str(), 3000)) {
      BOOST_LOG(error) << "WaitNamedPipe timed out";
      CloseHandle(hEvent);
      return nullptr;
    }
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

  auto pipeObj = std::make_unique<AsyncPipe>(hPipe, hEvent, isServer);
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
AsyncPipe::AsyncPipe(HANDLE pipe, HANDLE event, bool isServer):
    _pipe(pipe),
    _event(event),
    _connected(false),
    _isServer(isServer),
    _running(false) {}

AsyncPipe::~AsyncPipe() {
  disconnect();
}

void AsyncPipe::send(std::vector<uint8_t> bytes) {
  send(bytes, false);
}

void AsyncPipe::send(const std::vector<uint8_t>& bytes, bool block) {
  if (!_connected || _pipe == INVALID_HANDLE_VALUE) {
    return;
  }
  OVERLAPPED ovl = {0};
  ovl.hEvent = CreateEventW(nullptr, TRUE, FALSE, nullptr);
  ResetEvent(ovl.hEvent);
  DWORD bytesWritten = 0;
  BOOL result = WriteFile(_pipe, bytes.data(), static_cast<DWORD>(bytes.size()), &bytesWritten, &ovl);
  if (!result && GetLastError() == ERROR_IO_PENDING && block) {
    WaitForSingleObject(ovl.hEvent, INFINITE);
    GetOverlappedResult(_pipe, &ovl, &bytesWritten, FALSE);
  }
  CloseHandle(ovl.hEvent);
}

void AsyncPipe::receive(std::vector<uint8_t> &bytes) {
  receive(bytes, false);
}

void AsyncPipe::receive(std::vector<uint8_t> &bytes, bool block) {
  if (!_connected || _pipe == INVALID_HANDLE_VALUE) {
    return;
  }
  bytes.resize(4096);
  OVERLAPPED ovl = {0};
  ovl.hEvent = CreateEventW(nullptr, TRUE, FALSE, nullptr);
  ResetEvent(ovl.hEvent);
  DWORD bytesRead = 0;
  BOOL result = ReadFile(_pipe, bytes.data(), static_cast<DWORD>(bytes.size()), &bytesRead, &ovl);
  if (!result && GetLastError() == ERROR_IO_PENDING && block) {
    WaitForSingleObject(ovl.hEvent, INFINITE);
    GetOverlappedResult(_pipe, &ovl, &bytesRead, FALSE);
  }
  CloseHandle(ovl.hEvent);
  bytes.resize(bytesRead);
}

void AsyncPipe::connect() {
  if (_pipe == INVALID_HANDLE_VALUE) {
    return;
  }

  if (_isServer) {
    // For server pipes, use ConnectNamedPipe with proper overlapped I/O
    OVERLAPPED ovl = {0};
    ovl.hEvent = _event; // Use the existing event handle
    
    // Reset the event before using it
    ResetEvent(_event);
    
    BOOL result = ConnectNamedPipe(_pipe, &ovl);
    if (result) {
      _connected = true;
    } else {
      DWORD err = GetLastError();
      if (err == ERROR_PIPE_CONNECTED) {
        // Client already connected
        _connected = true;
      } else if (err == ERROR_IO_PENDING) {
        // Wait for the connection to complete
        DWORD waitResult = WaitForSingleObject(ovl.hEvent, 5000); // 5 second timeout
        if (waitResult == WAIT_OBJECT_0) {
          DWORD transferred = 0;
          if (GetOverlappedResult(_pipe, &ovl, &transferred, FALSE)) {
            _connected = true;
          } else {
            BOOST_LOG(error) << "GetOverlappedResult failed in connect, error=" << GetLastError();
          }
        } else {
          BOOST_LOG(error) << "ConnectNamedPipe timeout or wait failed, waitResult=" << waitResult << ", error=" << GetLastError();
        }
      } else {
        BOOST_LOG(error) << "ConnectNamedPipe failed, error=" << err;
      }
    }
  } else {
    // For client handles created with CreateFileW, the connection already exists
    _connected = true;
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
