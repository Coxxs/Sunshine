

#include "shared_memory.h"

#include <chrono>
#include <combaseapi.h>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <string>
#include <thread>
#include <vector>
#include <windows.h>

// --- SharedSessionManager Implementation ---
SecuredPipeCoordinator::SecuredPipeCoordinator(IAsyncPipeFactory *pipeFactory):
    _pipeFactory(pipeFactory) {}

IAsyncPipe *SecuredPipeCoordinator::prepare_client(IAsyncPipe *pipe) {
  SecureClientMessage msg;

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

  if (received && bytes.size() >= sizeof(SecureClientMessage)) {
    SecureClientMessage msg2;
    std::memcpy(&msg2, bytes.data(), sizeof(SecureClientMessage));
    msg = msg2;
  }

  pipe->disconnect();

  // Convert wide string to string
  std::wstring wpipeNasme(msg.pipe_name);
  std::wstring weventName(msg.event_name);
  std::string pipeNameStr(wpipeNasme.begin(), wpipeNasme.end());
  std::string eventNameStr(weventName.begin(), weventName.end());

  return _pipeFactory->create(pipeNameStr, eventNameStr, false, true);
}

IAsyncPipe *SecuredPipeCoordinator::prepare_server(IAsyncPipe *pipe) {
  std::string pipe_name = generateGuid();
  std::string event_name = generateGuid();

  std::wstring wpipe_name(pipe_name.begin(), pipe_name.end());
  std::wstring wevent_name(event_name.begin(), event_name.end());

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
  char buffer[64];
  snprintf(buffer, sizeof(buffer), "%08lX-%04X-%04X-%04X-%012llX", guid.Data1, guid.Data2, guid.Data3, (guid.Data4[0] << 8) | guid.Data4[1], ((static_cast<unsigned long long>(guid.Data4[2]) << 40) | (static_cast<unsigned long long>(guid.Data4[3]) << 32) | (static_cast<unsigned long long>(guid.Data4[4]) << 24) | (static_cast<unsigned long long>(guid.Data4[5]) << 16) | (static_cast<unsigned long long>(guid.Data4[6]) << 8) | (static_cast<unsigned long long>(guid.Data4[7]))));
  return std::string(buffer);
}

// --- AsyncPipeFactory Implementation ---
IAsyncPipe *AsyncPipeFactory::create(const std::string &pipeName, const std::string &eventName, bool isServer, bool isSecured) {
  std::wstring wPipeName(pipeName.begin(), pipeName.end());
  std::wstring wEventName(eventName.begin(), eventName.end());

  SECURITY_ATTRIBUTES *pSecAttr = nullptr;
  SECURITY_ATTRIBUTES secAttr {};
  SECURITY_DESCRIPTOR secDesc {};
  if (isSecured) {
    secAttr.nLength = sizeof(SECURITY_ATTRIBUTES);
    secAttr.bInheritHandle = FALSE;
    secAttr.lpSecurityDescriptor = &secDesc;
    InitializeSecurityDescriptor(&secDesc, SECURITY_DESCRIPTOR_REVISION);
    SetSecurityDescriptorDacl(&secDesc, TRUE, nullptr, FALSE);
    pSecAttr = &secAttr;
  }

  HANDLE hEvent = CreateEventW(pSecAttr, TRUE, FALSE, wEventName.c_str());
  if (!hEvent) {
    return nullptr;
  }

  HANDLE hPipe = INVALID_HANDLE_VALUE;
  if (isServer) {
    hPipe = CreateNamedPipeW(
      wPipeName.c_str(),
      PIPE_ACCESS_DUPLEX | FILE_FLAG_OVERLAPPED,
      PIPE_TYPE_BYTE | PIPE_READMODE_BYTE | PIPE_WAIT,
      1,
      4096,
      4096,
      0,
      pSecAttr
    );
  } else {
    hPipe = CreateFileW(
      wPipeName.c_str(),
      GENERIC_READ | GENERIC_WRITE,
      0,
      pSecAttr,
      OPEN_EXISTING,
      0,
      nullptr
    );
  }

  if (hPipe == INVALID_HANDLE_VALUE) {
    CloseHandle(hEvent);
    return nullptr;
  }

  return new AsyncPipe(hPipe, hEvent);
}


SecuredPipeFactory::SecuredPipeFactory()
    : _pipeFactory(new AsyncPipeFactory()),
      _coordinator(_pipeFactory) {}


IAsyncPipe* SecuredPipeFactory::create(const std::string &pipeName, const std::string &eventName, bool isServer, bool isSecured) {
  auto first_pipe = _pipeFactory->create(pipeName, eventName, isServer, isSecured);
  if (isServer) {
    return _coordinator.prepare_server(first_pipe);
  }
  return _coordinator.prepare_client(first_pipe);
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
    if (ConnectNamedPipe(_pipe, nullptr) || GetLastError() == ERROR_PIPE_CONNECTED) {
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
AsyncNamedPipe::AsyncNamedPipe(IAsyncPipe *pipe):
    _pipe(pipe),
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
    if (_pipe) {
      _pipe->receive(bytes);
    }
    if (!bytes.empty() && _onMessage) {
      _onMessage(bytes);
    }
    std::this_thread::sleep_for(std::chrono::milliseconds(10));
  }
}
