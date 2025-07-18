#pragma once
#include <atomic>
#include <cstdint>
#include <functional>
#include <string>
#include <thread>
#include <vector>
#include <windows.h>

class IAsyncPipe {
public:
  virtual ~IAsyncPipe() = default;
  virtual void send(std::vector<uint8_t> bytes) = 0;
  virtual void receive(std::vector<uint8_t> &bytes) = 0;
  virtual void connect() = 0;
  virtual void disconnect() = 0;
  virtual bool is_connected() = 0;
};

class AsyncNamedPipe {
public:
  using MessageCallback = std::function<void(const std::vector<uint8_t> &)>;
  using ErrorCallback = std::function<void(const std::string &)>;

  AsyncNamedPipe(IAsyncPipe *pipe);
  ~AsyncNamedPipe();

  bool start(MessageCallback onMessage, ErrorCallback onError);
  void stop();
  void asyncSend(const std::vector<uint8_t> &message);
  bool isConnected() const;

private:
  void workerThread();

  IAsyncPipe *_pipe;
  std::atomic<bool> _running;
  std::thread _worker;
  MessageCallback _onMessage;
  ErrorCallback _onError;
};

class AsyncPipe: public IAsyncPipe {
public:
  AsyncPipe(HANDLE pipe = INVALID_HANDLE_VALUE, HANDLE event = nullptr);
  ~AsyncPipe() override;

  void send(std::vector<uint8_t> bytes) override;
  void receive(std::vector<uint8_t> &bytes) override;
  void connect() override;
  void disconnect() override;
  bool is_connected() override;

private:
  HANDLE _pipe;
  HANDLE _event;
  std::atomic<bool> _connected;
  std::atomic<bool> _running;
};

class IAsyncPipeFactory {
public:
  virtual ~IAsyncPipeFactory() = default;
  virtual IAsyncPipe *create(const std::string &pipeName, const std::string &eventName, bool isServer, bool isSecured) = 0;
};

struct SecureClientMessage {
  wchar_t pipe_name[32];
  wchar_t event_name[32];
};

class SecuredPipeCoordinator {
public:
  SecuredPipeCoordinator(IAsyncPipeFactory *pipeFactory);
  IAsyncPipe *prepare_client(IAsyncPipe *pipe);
  IAsyncPipe *prepare_server(IAsyncPipe *pipe);

private:
  std::string generateGuid();
  IAsyncPipeFactory *_pipeFactory;
};

class SecuredPipeFactory: public IAsyncPipeFactory {
public:
  SecuredPipeFactory();
  IAsyncPipe *create(const std::string &pipeName, const std::string &eventName, bool isServer, bool isSecured) override;

private:
  IAsyncPipeFactory* _pipeFactory;
  SecuredPipeCoordinator _coordinator;
};


class AsyncPipeFactory: public IAsyncPipeFactory {
public:
  IAsyncPipe *create(const std::string &pipeName, const std::string &eventName, bool isServer, bool isSecured) override;
  void create_security_descriptor(SECURITY_DESCRIPTOR &desc);
};
