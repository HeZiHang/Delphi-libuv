unit uLibUV.Win;

interface

uses Windows, Iocp.WinSock2;

const
  LIBFILE = 'libuv.dll';


type
  uv_handle_type = (UV_UNKNOWN_HANDLE = 0, UV_ASYNC, UV_CHECK, UV_FS_EVENT_, UV_FS_POLL, UV_HANDLE, UV_IDLE, UV_NAMED_PIPE, UV_POLL, UV_PREPARE, UV_PROCESS, UV_STREAM, UV_TCP, UV_TIMER, UV_TTY,
    UV_UDP, UV_SIGNAL, UV_FILE_, UV_HANDLE_TYPE_MAX);

  uv_req_type = (UV_UNKNOWN_REQ = 0, UV_REQ, UV_CONNECT, UV_WRITE_, UV_SHUTDOWN_, UV_UDP_SEND_, UV_FS, UV_WORK, UV_GETADDRINFO_, UV_GETNAMEINFO_, UV_ACCEPT_, UV_FS_EVENT_REQ, UV_POLL_REQ,
    UV_PROCESS_EXIT, UV_READ, UV_UDP_RECV, UV_WAKEUP, UV_SIGNAL_REQ, UV_REQ_TYPE_MAX);

  uv_os_sock_t = TSOCKET;
  puv_os_sock_t = ^uv_os_sock_t;
  uv_os_fd_t = THANDLE;
  puv_os_fd_t = ^uv_os_fd_t;

  uv_thread_t = THANDLE;
  puv_thread_t = ^uv_thread_t;

  uv_sem_t = THANDLE;
  puv_sem_t = ^uv_sem_t;
  uv_mutex_t = TRTLCriticalSection;
  puv_mutex_t = ^uv_mutex_t;

  uv_file = Integer;

  uv_uid_t = Byte;
  uv_gid_t = Byte;

  uv_lib_t = record
    handle: HMODULE;
    errmsg: PAnsiChar;
  end;

  puv_lib_t = ^uv_lib_t;

  SRWLOCK = record
    Ptr: Pointer;
  end;

  uv_rwlock_t = record
    case Integer of
      0:
        (state_: record num_readers_: UInt;
          num_readers_lock_: TRTLCriticalSection;
          write_semaphore_: THANDLE;
        end;);
      1:
        (unused1_: record unused_: SRWLOCK;
        end;);
      2:
        (unused2_: record unused1_, unused2_: uv_mutex_t;
        end;)
  end;

  puv_rwlock_t = ^uv_rwlock_t;

  uv_cond_t = record
    case Integer of
      0:
        (cond_var: CONDITION_VARIABLE);
      1:
        (fallback: record waiters_count: UInt;
          waiters_count_lock: TRTLCriticalSection;
          signal_event: THANDLE;
          broadcast_event: THANDLE;
        end;);
  end;

  puv_cond_t = ^uv_cond_t;

  uv_barrier_t = record
    n: UInt;
    count: UInt;
    mutex: uv_mutex_t;
    turnstile1: uv_sem_t;
    turnstile2: uv_sem_t;
  end;

  puv_barrier_t = ^uv_barrier_t;

  uv_once_t = record
    ran: Byte;
    event: THANDLE;
  end;

  puv_once_t = ^uv_once_t;

  uv_key_t = record
    tls_index: DWORD;
  end;

  puv_key_t = ^uv_key_t;

  uv_shutdown_private_fields = record

  end;

  uv_req_private = record
    case Integer of
      0:
        (io: record overlapped: overlapped;
          queued_bytes: size_t;
        end;);
  end;

  paddrinfo = Iocp.WinSock2.paddrinfo;
  psockaddr = Iocp.WinSock2.psockaddr;
  PSockAddrIn = Iocp.WinSock2.PSockAddrIn;
  psockaddr_in6 = Iocp.WinSock2.psockaddr_in6;

  NTSTATUS = DWORD;

  _AFD_POLL_HANDLE_INFO = record
    handle: THANDLE;
    Events: ULONG;
    Status: NTSTATUS;
  end;

  AFD_POLL_HANDLE_INFO = _AFD_POLL_HANDLE_INFO;
  PAFD_POLL_HANDLE_INFO = &AFD_POLL_HANDLE_INFO;

  _AFD_POLL_INFO = record
    Timeout: LARGE_INTEGER;
    NumberOfHandles, Exclusive: ULONG;
    Handles: array [0 .. 0] of AFD_POLL_HANDLE_INFO;
  end;

  AFD_POLL_INFO = _AFD_POLL_INFO;
  PAFD_POLL_INFO = ^AFD_POLL_INFO;

implementation

end.
