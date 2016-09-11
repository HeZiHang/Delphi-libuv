unit uLibUV;

interface

uses Windows, uLibUV.Win, Iocp.WinSock2;

const
  DLLFILE = 'libuv.dll';

type
  puv_loop_t = ^uv_loop_t;

  puv__work = ^uv__work;

  uv__work = record
    work: procedure(w: puv__work); cdecl;
    done: procedure(w: puv__work; status: Integer); cdecl;
    loop: puv_loop_t;
    wq: array [0 .. 1] of Pointer;
  end;

  uv_loop_s = record
  end;

  uv_loop_t = uv_loop_s;

  puv_handle_t = ^uv_handle_s;
  puv_shutdown_t = ^uv_shutdown_s;

  uv_buf_t = record
    len: ULONG;
    base: PByte;
  end;

  puv_buf_t = ^uv_buf_t;
  uv_buf_array = array [0 .. 0] of uv_buf_t;
  puv_buf_array = ^uv_buf_array;

  (* Request types. *)
  uv_req_s = record
    data: Pointer;
    &type: uv_req_type;
    active_queue: array [0 .. 1] of Pointer;
    reserved: array [0 .. 3] of Pointer;
    u: uv_req_private;
  end;

  uv_req_t = uv_req_s;
  puv_req_t = ^uv_req_t;

  uv_dirent_type_t = (UV_DIRENT_UNKNOWN, UV_DIRENT_FILE, UV_DIRENT_DIR, UV_DIRENT_LINK, UV_DIRENT_FIFO, UV_DIRENT_SOCKET, UV_DIRENT_CHAR, UV_DIRENT_BLOCK);

  TAnsiCharArray = array [0 .. 0] of PAnsiChar;
  PAnsiCharArray = ^TAnsiCharArray;

{$IFDEF MSWINDOWS}

  uv_handle_private_fields = record
    endgame_next: puv_handle_t;
    flags: UInt;
  end;

{$ENDIF}

  puv_stream_t = ^uv_stream_t;

  uv_close_cb = procedure(handle: puv_handle_t); cdecl;

  uv_handle_s = record
    data: Pointer;
    loop: puv_loop_t;
    &type: uv_handle_type;
    close_cb: uv_close_cb;
    handle_queue: array [0 .. 1] of Pointer;

    u: record
      case Integer of
        0:
          (fd: Integer;);
        1:
          (reserved: array [0 .. 3] of Pointer;);
    end;

    &private: uv_handle_private_fields;
  end;

  uv_handle_t = uv_handle_s;

  uv_connection_cb = procedure(server: puv_stream_t; status: Integer); cdecl;

  puv_udp_send_t = ^uv_udp_send_t;
  puv_udp_t = ^uv_udp_t;
  puv_write_t = ^uv_write_t;
  uv_udp_send_cb = procedure(req: puv_udp_send_t; status: Integer); cdecl;
  uv_udp_recv_cb = procedure(handle: puv_udp_t; nread: ssize_t; buf: puv_buf_t; addr: psockaddr; flags: UInt); cdecl;
  uv_alloc_cb = procedure(handle: puv_handle_t; suggested_size: size_t; buf: puv_buf_t); cdecl;
  uv_read_cb = procedure(stream: puv_stream_t; nread: ssize_t; buf: puv_buf_t); cdecl;
  uv_write_cb = procedure(req: puv_write_t; status: Integer); cdecl;
  puv_poll_t = ^uv_poll_t;
  uv_poll_cb = procedure(handle: puv_poll_t; status: Integer; events: Integer); cdecl;
  puv_timer_t = ^uv_timer_t;
  uv_timer_cb = procedure(handle: puv_timer_t); cdecl;
  puv_prepare_t = ^uv_prepare_t;
  uv_prepare_cb = procedure(handle: puv_prepare_t); cdecl;
  puv_connect_t = ^uv_connect_t;
  uv_connect_cb = procedure(req: puv_connect_t; status: Integer); cdecl;
  puv_check_t = ^uv_check_t;
  uv_check_cb = procedure(handle: puv_check_t); cdecl;
  puv_idle_t = ^uv_idle_t;
  uv_idle_cb = procedure(handle: puv_idle_t); cdecl;
  puv_async_t = ^uv_async_t;
  uv_async_cb = procedure(handle: puv_async_t); cdecl;
  puv_process_t = ^uv_process_t;
  uv_exit_cb = procedure(process: puv_process_t; exit_status: Int64; term_signal: Integer); cdecl;
  puv_fs_event_t = ^uv_fs_event_t;
  uv_fs_event_cb = procedure(handle: puv_fs_event_t; filename: pchar; events: Integer; status: Integer); cdecl;
  puv_signal_t = ^uv_signal_t;
  uv_signal_cb = procedure(handle: puv_signal_t; signum: Integer); cdecl;
  puv_fs_t = ^uv_fs_t;
  uv_fs_cb = procedure(req: puv_fs_t); cdecl;
  puv_work_t = ^uv_work_t;
  uv_work_cb = procedure(req: puv_work_t); cdecl;
  uv_after_work_cb = procedure(req: puv_work_t; status: Integer); cdecl;

{$IFDEF MSWINDOWS}

  uv_write_private_fields = record
    ipc_header: Integer;
    write_buffer: uv_buf_t;
    wait_handle, event_handle: THandle;
  end;
{$ENDIF}

  uv_write_s = record
    req: uv_req_t;
    cb: uv_write_cb;
    send_handle: puv_stream_t;
    handle: puv_stream_t;
    &private: uv_write_private_fields;
  end;

  uv_write_t = uv_write_s;

{$IFDEF MSWINDOWS}
  puv_pipe_accept_t = ^uv_pipe_accept_t;

  uv_pipe_accept_t = record
    req: uv_req_t;
    pipeHandle: THandle;
    next_pending: puv_pipe_accept_t;
  end;

  puv_tcp_accept_t = ^uv_tcp_accept_t;

  uv_tcp_accept_t = record
    req: uv_req_t;
    accept_socket: TSOCKET;
    accept_buffer: array [0 .. sizeof(TSockAddrStorage) * 2 + 32 - 1] of AnsiChar;
    event_handle: THandle;
    wait_handle: THandle;
    next_pending: puv_tcp_accept_t;
  end;

  uv_read_t = record
    req: uv_req_t;
    event_handle: THandle;
    wait_handle: THandle;
  end;

  uv_stream_connection_fields = record
    write_reqs_pending: UInt;
    shutdown_req: puv_shutdown_t;
  end;

  uv_stream_server_fields = record
    connection_cb: uv_connection_cb;
  end;

  uv_stream_private = record
    reqs_pending: UInt;
    activecnt: Integer;
    read_req: uv_read_t;

    stream: record
      case Integer of
        0:
          (conn: uv_stream_connection_fields;);
        1:
          (serv: uv_stream_server_fields;);
    end;
  end;

  uv_tcp_server_fields = record
    accept_reqs: puv_tcp_accept_t;
    processed_accepts: UInt;
    pending_accepts: puv_tcp_accept_t;
    func_acceptex: LPFN_ACCEPTEX;
  end;

  uv_tcp_connection_fields = record
    read_buffer: uv_buf_t;
    func_connectex: LPFN_CONNECTEX;
  end;

  uv_tcp_private_fields = record
    socket: TSOCKET;
    delayed_error: Integer;

    tcp: record
      case Integer of
        0:
          (serv: uv_tcp_server_fields;);
        1:
          (conn: uv_tcp_connection_fields;);
    end;
  end;

  uv_udp_private_fields = record
    socket: TSOCKET;
    reqs_pending: UInt;
    activecnt: Integer;
    recv_req: uv_req_t;
    recv_buffer: uv_buf_t;
    recv_from: TSockAddrStorage;
    recv_from_len: Integer;
    recv_cb: uv_udp_recv_cb;
    alloc_cb: uv_alloc_cb;
    func_wsarecv: LPFN_WSARECV;
    func_wsarecvfrom: LPFN_WSARECVFROM;
  end;

  uv_pipe_server_fields = record
    pending_instances: Integer;
    accept_reqs: puv_pipe_accept_t;
    pending_accepts: puv_pipe_accept_t;
  end;

  uv_pipe_connection_fields = record
    eof_timer: puv_timer_t;
    ipc_header_write_req: uv_write_t;
    ipc_pid: Integer;
    remaining_ipc_rawdata_bytes: UInt64;

    pending_ipc_info: record
      queue: array [0 .. 1] of Pointer;
      queue_len: Integer;
    end;

    non_overlapped_writes_tail: puv_write_t;
    readfile_mutex: uv_mutex_t;
    [volatile]
    readfile_thread: THandle;
  end;

  uv_pipe_private_fields = record
    handle: THandle;
    name: PWideChar;

    pipe: record
      case Integer of
        0:
          (serv: uv_pipe_server_fields;);
        1:
          (conn: uv_pipe_connection_fields;);
    end;
  end;

  // half-duplex so read-state can safely overlap write-state.
  uv_tty_private_fields = record
    handle: THandle;

    tty: record
      case Integer of
        0:
          (rd: record
            // Used for readable TTY handles
            // TODO: remove me in v2.x.
            unused_: THandle;
            read_line_buffer: uv_buf_t;
            read_raw_wait: THandle;
            // Fields used for translating win keystrokes into vt100 characters
            last_key: array [0 .. 7] of AnsiChar;
            last_key_offset, last_key_len: Byte;
            last_utf16_high_surrogate: WideChar;
            last_input_record: INPUT_RECORD;
          end;);
        1:
          (wr: record
            // Used for writable TTY handles
            // utf8-to-utf16 conversion state
            utf8_codepoint: UInt;
            utf8_bytes_left: Byte;
            // eol conversion state
            previous_eol: Byte;
            // ansi parser state
            ansi_parser_state, ansi_csi_argc: Byte;
            ansi_csi_argv: array [0 .. 3] of Word;
            saved_position: COORD;
            saved_attributes: Word;
          end;);
    end;
  end;

  uv_pool_private_fields = record
    socket: TSOCKET;
    // Used in fast mode
    peer_socket: TSOCKET;
    afd_poll_info_1: AFD_POLL_INFO;
    afd_poll_info_2: AFD_POLL_INFO;
    // Used in fast and slow mode.
    poll_req_1: uv_req_t;
    poll_req_2: uv_req_t;
    submitted_events_1, submitted_events_2, mask_events_1, mask_events_2, events: Byte;
  end;

  uv_timer_private_fields = record
    tree_entry: record
      rbe_left, rbe_right, rbe_parent: puv_timer_t;
      rbe_color: Integer;
    end;

    due: UInt64;
    &repeat: UInt64;
    start_id: UInt64;
    timer_cb: uv_timer_cb;
  end;

  uv_prepare_private_fields = record
    prepare_prev, prepare_next: puv_prepare_t;
    prepare_n: uv_prepare_cb;
  end;

  uv_connect_private_fields = record

  end;

  uv_udp_send_private_fields = record

  end;

  uv_async_private_fields = record
    async_req: uv_req_s;
    async_cb: uv_async_cb;
    // char to avoid alignment issues
    [volatile]
    async_sent: AnsiChar;
  end;

  uv_process_exit_s = record
    req: uv_req_t;
  end;

  uv_process_private_fields = record
    exit_req: uv_process_exit_s;
    child_stdio_buffer: PByte;
    exit_signal: Integer;
    wait_handle, process_handle: THandle;
    [volatile]
    exit_cb_pending: AnsiChar;
  end;

  uv_signal_private_fields = record
    tree_entry: record
      rbe_left, rbe_right, rbe_parent: puv_signal_t;
      rbe_color: Integer;
    end;

    signal_req: uv_req_s;
    pending_signum: ULONG;
  end;
{$ENDIF}

  uv_stream_s = record
    handle: uv_handle_t;
    write_queue_size: size_t;
    alloc_cb: uv_alloc_cb;
    read_cb: uv_read_cb;
    &private: uv_stream_private;
  end;

  uv_stream_t = uv_stream_s;

  uv_tcp_s = record
    handle: uv_handle_t;
    stream: uv_stream_t;
    &private: uv_tcp_private_fields;
  end;

  uv_tcp_t = uv_tcp_s;
  puv_tcp_t = ^uv_tcp_t;

  uv_udp_s = record
    handle: uv_handle_t;
    (* read-only *)
    (*
      * Number of bytes queued for sending. This field strictly shows how much
      * information is currently queued.
    *)
    send_queue_size: size_t;
    (*
      * Number of send requests currently in the queue awaiting to be processed.
    *)
    send_queue_count: size_t;
    &private: uv_udp_private_fields;
  end;

  uv_udp_t = uv_udp_s;
  // puv_udp_t = ^uv_udp_t;

  uv_pipe_s = record
    handle: uv_handle_t;
    stream: uv_stream_t;
    ipc: Integer; // non-zero if this pipe is used for passing handles

    &private: uv_pipe_private_fields;
  end;

  uv_pipe_t = uv_pipe_s;
  puv_pipe_t = ^uv_pipe_t;

  uv_tty_s = record
  end;

  uv_tty_t = uv_tty_s;
  puv_tty_t = ^uv_tty_t;

  uv_poll_s = record
    handle: uv_handle_t;
    poll_cb: uv_poll_cb;
    &private: uv_pool_private_fields;
  end;

  uv_poll_t = uv_poll_s;
  // puv_poll_t = ^uv_poll_t;

  uv_timer_s = record
    handle: uv_handle_t;
    &private: uv_timer_private_fields;
  end;

  uv_timer_t = uv_timer_s;
  // puv_timer_t = ^uv_timer_t;

  uv_prepare_s = record
    handle: uv_handle_t;
    &private: uv_prepare_private_fields;
  end;

  uv_prepare_t = uv_prepare_s;
  // puv_prepare_t = ^uv_prepare_t;

  uv_check_private_fields = record
    check_prev, check_next: puv_check_t;
    check_cb: uv_check_cb;
  end;

  uv_check_s = record
    handle: uv_handle_t;
    &private: uv_check_private_fields;
  end;

  uv_check_t = uv_check_s;
  // puv_check_t = ^uv_check_t;

  uv_idle_private_fields = record
    idle_prev, idle_next: puv_idle_t;
    idle_cb: uv_idle_cb;
  end;

  uv_idle_s = record
    handle: uv_handle_t;
    &private: uv_idle_private_fields;
  end;

  uv_idle_t = uv_idle_s;

  uv_async_s = record
    handle: uv_handle_t;
    &private: uv_async_private_fields;
  end;

  uv_async_t = uv_async_s;
  // puv_async_t = ^uv_async_t;

  uv_process_s = record
    handle: uv_handle_t;
    exit_cb: uv_exit_cb;
    pid: Integer;
    &private: uv_process_private_fields;
  end;

  uv_process_t = uv_process_s;
  // puv_process_t = ^uv_process_t;

  uv_fs_event_req_s = record
    req: uv_req_t;
  end;

  uv_fs_event_private_fields = record
    req: uv_fs_event_req_s;
    dir_handle: THandle;
    req_pending: Integer;
    cb: uv_fs_event_cb;
    filew, short_filew, dirw: PWideChar;
    buffer: PAnsiChar;
  end;

  uv_fs_event_s = record
    handle: uv_handle_t;
    path: PAnsiChar;
    &private: uv_fs_event_private_fields;
  end;

  uv_fs_event_t = uv_fs_event_s;

  uv_fs_poll_s = record
    handle: uv_handle_t;
    // Private, don't touch.
    poll_ctx: Pointer;
  end;

  uv_fs_poll_t = uv_fs_poll_s;
  puv_fs_poll_t = ^uv_fs_poll_t;

  uv_signal_s = record
    handle: uv_handle_t;
    signal_cb: uv_signal_cb;
    signum: Integer;
    &private: uv_signal_private_fields end;

    uv_signal_t = uv_signal_s;

    uv_getaddrinfo_s = record
  end;

  uv_getaddrinfo_t = uv_getaddrinfo_s;
  puv_getaddrinfo_t = ^uv_getaddrinfo_t;

  uv_getnameinfo_s = record
  end;

  uv_getnameinfo_t = uv_getnameinfo_s;
  puv_getnameinfo_t = ^uv_getnameinfo_t;

  // puv_shutdown_t = ^uv_shutdown_s;

  uv_shutdown_cb = procedure(req: puv_shutdown_t; status: Integer); cdecl;

  uv_shutdown_s = record
    req: uv_req_t;
    handle: puv_stream_t;
    cb: uv_shutdown_cb;
    &private: uv_shutdown_private_fields;
  end;

  uv_connect_s = record
    req: uv_req_t;
    cb: uv_connect_cb;
    handle: puv_stream_t;
    &private: uv_connect_private_fields;
  end;

  uv_connect_t = uv_connect_s;
  // puv_connect_t = ^uv_connect_t;

  // uv_udp_send_t is a subclass of uv_req_t.
  uv_udp_send_s = record
    req: uv_req_t;
    handle: puv_udp_t;
    cb: uv_udp_send_cb;
    &private: uv_udp_send_private_fields;
  end;

  uv_udp_send_t = uv_udp_send_s;

  uv_fs_private_fields = record
    work_req: uv__work;
    flags: Integer;
    sys_errno_: DWORD;

    &file: record
      // TODO: remove me in 0.9.
      case Integer of
        0:
          (pathw: PWideChar;);
        1:
          (fd: Integer;);
    end;

    fs: record
      case Integer of
        0:
          (info: record mode: Integer;
            new_pathw: PWideChar;
            file_flags, fd_out: Integer;
            nbufs: UInt;
            bufs: puv_buf_t;
            offset: Int64;
            bufsml: array [0 .. 3] of uv_buf_t;
          end;);
        1:
          (time: record atime, mtime: double;
          end;);
    end;
  end;

  uv_fs_type = (UV_FS_UNKNOWN = -1, UV_FS_CUSTOM, UV_FS_OPEN_, UV_FS_CLOSE_, UV_FS_READ_, UV_FS_WRITE_, UV_FS_SENDFILE_, UV_FS_STAT_, UV_FS_LSTAT_, UV_FS_FSTAT_, UV_FS_FTRUNCATE_, UV_FS_UTIME_,
    UV_FS_FUTIME_, UV_FS_ACCESS_, UV_FS_CHMOD_, UV_FS_FCHMOD_, UV_FS_FSYNC_, UV_FS_FDATASYNC_, UV_FS_UNLINK_, UV_FS_RMDIR_, UV_FS_MKDIR_, UV_FS_MKDTEMP_, UV_FS_RENAME_, UV_FS_SCANDIR_, UV_FS_LINK_,
    UV_FS_SYMLINK_, UV_FS_READLINK_, UV_FS_CHOWN_, UV_FS_FCHOWN_, UV_FS_REALPATH_);

  uv_timespec_t = record
    tv_sec: Integer;
    tv_nsec: Integer;
  end;

  uv_stat_t = record
    st_dev: UInt64;
    st_mode: UInt64;
    st_nlink: UInt64;
    st_uid: UInt64;
    st_gid: UInt64;
    st_rdev: UInt64;
    st_ino: UInt64;
    st_size: UInt64;
    st_blksize: UInt64;
    st_blocks: UInt64;
    st_flags: UInt64;
    st_gen: UInt64;
    st_atim: uv_timespec_t;
    st_mtim: uv_timespec_t;
    st_ctim: uv_timespec_t;
    st_birthtim: uv_timespec_t;
  end;

  puv_stat_t = ^uv_stat_t;

  // uv_fs_t is a subclass of uv_req_t.
  uv_fs_s = record
    req: uv_req_t;
    fs_type: uv_fs_type;
    loop: puv_loop_t;
    cb: uv_fs_cb;
    result: ssize_t;
    ptr: Pointer;
    path: PAnsiChar;
    statbuf: uv_stat_t; // Stores the result of uv_fs_stat() and uv_fs_fstat().
    &private: uv_fs_private_fields;
  end;

  uv_fs_t = uv_fs_s;

  (*
    * uv_work_t is a subclass of uv_req_t.
  *)
  uv_work_private_fields = record
    work_req: uv__work;
  end;

  uv_work_s = record
    req: uv_req_t;
    loop: puv_loop_t;
    work_cb: uv_work_cb;
    after_work_cb: uv_after_work_cb;
    &private: uv_work_private_fields;
  end;

  uv_work_t = uv_work_s;

  uv_cpu_times_s = record
    user, nice, sys, idle, irq: UInt64;
  end;

  uv_cpu_info_s = record
    model: PAnsiChar;
    speed: Integer;
    cpu_times: uv_cpu_times_s;
  end;

  uv_cpu_info_t = uv_cpu_info_s;
  puv_cpu_info_t = ^uv_cpu_info_t;

  uv_interface_address_s = record
    name: PAnsiChar;
    phys_addr: array [0 .. 5] of Byte;
    is_internal: Integer;

    address: record
      case Integer of
        0:
          (address4: sockaddr_in;);
        1:
          (address6: sockaddr_in6;);
    end;

    netmask: record
      case Integer of
        0:
          (netmask4: sockaddr_in;);
        1:
          (netmask6: sockaddr_in6;);
    end;
  end;

  uv_interface_address_t = uv_interface_address_s;
  puv_interface_address_t = ^uv_interface_address_t;

  uv_dirent_s = record
    name: PAnsiChar;
    &type: uv_dirent_type_t;
  end;

  uv_dirent_t = uv_dirent_s;
  puv_dirent_t = ^uv_dirent_t;

  uv_passwd_s = record
  username:pAnsiChar;
  uid, gid:Long;
  shell,homedir:PAnsiChar;
  end;

  uv_passwd_t = uv_passwd_s;
  puv_passwd_t = ^uv_passwd_t;
  uv_loop_option = (UV_LOOP_BLOCK_SIGNAL);

  uv_run_mode = (UV_RUN_DEFAULT = 0, UV_RUN_ONCE, UV_RUN_NOWAIT);

function uv_version: UInt; cdecl;

function uv_version_string: pchar; cdecl;

type
  uv_malloc_func = procedure(size: size_t); cdecl;
  uv_realloc_func = procedure(ptr: Pointer; size: size_t); cdecl;
  uv_calloc_func = procedure(count: size_t; size: size_t); cdecl;
  uv_free_func = procedure(ptr: Pointer); cdecl;

function uv_replace_allocator(malloc_func: uv_malloc_func; realloc_func: uv_realloc_func; calloc_func: uv_calloc_func; free_func: uv_free_func): Integer; cdecl;

function uv_default_loop: puv_loop_t; cdecl;

function uv_loop_init(loop: puv_loop_t): Integer; cdecl;

function uv_loop_close(loop: puv_loop_t): Integer; cdecl;
(*
  * NOTE:
  *  This function is DEPRECATED (to be removed after 0.12), users should
  *  allocate the loop manually and use uv_loop_init instead.
*)

function uv_loop_new: puv_loop_t; cdecl;
(*
  * NOTE:
  *  This function is DEPRECATED (to be removed after 0.12). Users should use
  *  uv_loop_close and free the memory manually instead.
*)

procedure uv_loop_delete(loop: puv_loop_t); cdecl;

function uv_loop_size: size_t; cdecl;

function uv_loop_alive(loop: puv_loop_t): Integer; cdecl;

function uv_loop_configure(loop: puv_loop_t; option: uv_loop_option): Integer; varargs; cdecl;

function uv_run(loop: puv_loop_t; mode: uv_run_mode): Integer; cdecl;

procedure uv_stop(loop: puv_loop_t); cdecl;

procedure uv_ref(loop: puv_loop_t); cdecl;

procedure uv_unref(handle: puv_handle_t); cdecl;

function uv_has_ref(const handle: puv_handle_t): Integer; cdecl;

procedure uv_update_time(loop: puv_loop_t); cdecl;

function uv_no(loop: puv_loop_t): UInt64; cdecl;

function uv_backend_fd(const loop: puv_loop_t): Integer; cdecl;

function uv_backend_timeout(const loop: puv_loop_t): Integer; cdecl;

type
  // uv_alloc_cb = procedure(handle: puv_handle_t; suggested_size: size_t; buf: puv_buf_t); cdecl;
  // uv_read_cb = procedure(stream: puv_stream_t; nread: ssize_t; buf: puv_buf_t); cdecl;
  // uv_write_cb = procedure(req: puv_write_t; status: Integer); cdecl;
  // uv_connect_cb = procedure(req: puv_connect_t; status: Integer); cdecl;
  // uv_shutdown_cb = procedure(req: puv_shutdown_t; status: Integer); cdecl;
  // uv_connection_cb = procedure(server: puv_stream_t; status: Integer); cdecl;
  // uv_close_cb = procedure(handle: puv_handle_t); cdecl;
  // uv_poll_cb = procedure(handle: puv_poll_t; status: Integer; events: Integer); cdecl;
  // uv_timer_cb = procedure(handle: puv_timer_t); cdecl;
  // uv_async_cb = procedure(handle: puv_async_t); cdecl;
  // uv_prepare_cb = procedure(handle: puv_prepare_t); cdecl;
  // uv_check_cb = procedure(handle: puv_check_t); cdecl;
  // uv_idle_cb = procedure(handle: puv_idle_t); cdecl;
  // uv_exit_cb = procedure(process: uv_process_t; exit_status: Int64; term_signal: Integer); cdecl;
  uv_walk_cb = procedure(handle: puv_handle_t; arg: pinteger); cdecl;
  // uv_fs_cb = procedure(req: puv_fs_t); cdecl;
  // uv_work_cb = procedure(req: puv_work_t); cdecl;
  // uv_after_work_cb = procedure(req: puv_work_t; status: Integer); cdecl;
  uv_getaddrinfo_cb = procedure(req: puv_getaddrinfo_t; status: Integer; res: paddrinfo); cdecl;
  uv_getnameinfo_cb = procedure(req: puv_getnameinfo_t; status: Integer; hostname: pchar; service: pchar); cdecl;

  uv_fs_poll_cb = procedure(handle: puv_fs_poll_t; status: Integer; prev: puv_stat_t; curr: puv_stat_t); cdecl;
  // uv_signal_cb = procedure(handle: puv_signal_t; signum: Integer); cdecl;

  uv_membership = (UV_LEAVE_GROUP = 0, UV_JOIN_GROUP);

function uv_strerror(err: Integer): pchar; cdecl;

function uv_err_name(err: Integer): pchar; cdecl;

function uv_shutdown(req: puv_shutdown_t; handle: puv_stream_t; cb: uv_shutdown_cb): Integer; cdecl;

function uv_handle_size(&type: uv_handle_type): size_t; cdecl;

function uv_req_size(&type: uv_req_type): size_t; cdecl;

function uv_is_active(handle: puv_handle_t): Integer; cdecl;

procedure uv_walk(loop: puv_loop_t; walk_cb: uv_walk_cb; arg: pinteger); cdecl;
(* Helpers for ad hoc debugging, no API/ABI stability guaranteed. *)

procedure uv_print_all_handles(loop: puv_loop_t; stream: Pointer); cdecl;

procedure uv_print_active_handles(loop: puv_loop_t; stream: Pointer); cdecl;

procedure uv_close(handle: puv_handle_t; close_cb: uv_close_cb); cdecl;

function uv_send_buffer_size(handle: puv_handle_t; value: pinteger): Integer; cdecl;

function uv_recv_buffer_size(handle: puv_handle_t; value: pinteger): Integer; cdecl;

function uv_fileno(handle: puv_handle_t; fd: puv_os_fd_t): Integer; cdecl;

function uv_buf_init(base: pchar; len: UInt): uv_buf_t; cdecl;

function uv_listen(stream: puv_stream_t; backlog: Integer; cb: uv_connection_cb): Integer; cdecl;

function uv_accept(server: puv_stream_t; client: puv_stream_t): Integer; cdecl;

function uv_read_start(req: puv_write_t; alloc_cb: uv_alloc_cb; read_cb: uv_read_cb): Integer; cdecl;

function uv_read_stop(req: puv_stream_t): Integer; cdecl;

function uv_write(req: puv_write_t; handle: puv_stream_t; const bufs: puv_buf_array; nbufs: UInt; cb: uv_write_cb): Integer; cdecl;

function uv_write2(req: puv_write_t; handle: puv_stream_t; const bufs: puv_buf_array; nbufs: UInt; send_handle: puv_stream_t; cb: uv_write_cb): Integer; cdecl;

function uv_try_write(handle: puv_stream_t; const bufs: puv_buf_array; nbufs: UInt): Integer;

(* uv_write_t is a subclass of uv_req_t. *)

function uv_is_readable(handle: puv_stream_t): Integer; cdecl;

function uv_is_writable(handle: puv_stream_t): Integer; cdecl;

function uv_stream_set_blocking(handle: puv_stream_t; blocking: Integer): Integer; cdecl;

function uv_is_closing(handle: puv_handle_t): Integer; cdecl;
(*
  * uv_tcp_t is a subclass of uv_stream_t.
  *
  * Represents a TCP stream or TCP server.
*)

function uv_tcp_init(loop: puv_loop_t; handle: puv_tcp_t): Integer; cdecl;

function uv_tcp_init_ex(loop: puv_loop_t; handle: puv_tcp_t; flags: UInt): Integer; cdecl;

function uv_tcp_open(handle: puv_tcp_t; sock: uv_os_sock_t): Integer; cdecl;

function uv_tcp_nodelay(handle: puv_tcp_t; enable: Integer): Integer; cdecl;

function uv_tcp_keepalive(handle: puv_tcp_t; enable: Integer; delay: UInt): Integer; cdecl;

function uv_tcp_simultaneous_accepts(handle: puv_tcp_t; enable: Integer): Integer; cdecl;

type
  uv_tcp_flags = (
    (* Used with uv_tcp_bind, when an IPv6 address is used. *)
    UV_TCP_IPV6ONLY = 1);

function uv_tcp_bind(handle: puv_tcp_t; addr: psockaddr; flags: UInt): Integer; cdecl;

function uv_tcp_getsockname(handle: puv_tcp_t; name: psockaddr; namelen: pinteger): Integer; cdecl;

function uv_tcp_getpeername(handle: puv_tcp_t; name: psockaddr; namelen: pinteger): Integer; cdecl;

function uv_tcp_connect(req: puv_connect_t; handle: puv_tcp_t; addr: psockaddr; cb: uv_connect_cb): Integer; cdecl;
(* uv_connect_t is a subclass of uv_req_t. *)

(*
  * UDP support.
*)
type
  uv_udp_flags = (
    (* Disables dual stack mode. *)
    UV_UDP_IPV6ONLY = 1, UV_UDP_PARTIAL = 2,
    (*
      * Indicates message was truncated because read buffer was too small. The
      * remainder was discarded by the OS. Used in uv_udp_recv_cb.
    *)
    UV_UDP_REUSEADDR = 4
    (*
      * Indicates if SO_REUSEADDR will be set when binding the handle.
      * This sets the SO_REUSEPORT socket flag on the BSDs and OS X. On other
      * Unix platforms, it sets the SO_REUSEADDR flag.  What that means is that
      * multiple threads or processes can bind to the same address without error
      * (provided they all set the flag) but only the last one to bind will receive
      * any traffic, in effect "stealing" the port from the previous listener.
    *)
    );

  (* uv_udp_t is a subclass of uv_handle_t. *)
  (* uv_udp_send_t is a subclass of uv_req_t. *)

function uv_udp_init(loop: puv_loop_t; handle: puv_udp_t): Integer; cdecl;

function uv_udp_init_ex(loop: puv_loop_t; handle: puv_udp_t; flags: UInt): Integer; cdecl;

function uv_udp_open(handle: puv_udp_t; sock: uv_os_sock_t): Integer; cdecl;

function uv_udp_bind(handle: puv_udp_t; addr: psockaddr; flags: UInt): Integer; cdecl;

function uv_udp_getsockname(handle: puv_udp_t; name: psockaddr; namelen: pinteger): Integer; cdecl;

function uv_udp_set_membership(handle: puv_udp_t; multicast_addr: pchar; interface_addr: pchar; membership: uv_membership): Integer; cdecl;

function uv_udp_set_multicast_loop(handle: puv_udp_t; &on: Integer): Integer; cdecl;

function uv_udp_set_multicast_ttl(handle: puv_udp_t; ttl: Integer): Integer; cdecl;

function uv_udp_set_multicast_interface(handle: puv_udp_t; interface_addr: pchar): Integer; cdecl;

function uv_udp_set_broadcast(handle: puv_udp_t; &on: Integer): Integer; cdecl;

function uv_udp_set_ttl(handle: puv_udp_t; ttl: Integer): Integer; cdecl;

function uv_udp_send(req: puv_udp_send_t; handle: puv_udp_t; const bufs: puv_buf_array; nbufs: UInt; addr: psockaddr; send_cb: uv_udp_send_cb): Integer; cdecl;

function uv_udp_try_send(handle: puv_udp_t; const bufs: puv_buf_array; nbufs: UInt; addr: psockaddr): Integer; cdecl;

function uv_udp_recv_start(handle: puv_udp_t; alloc_cb: uv_alloc_cb; recv_cb: uv_udp_recv_cb): Integer; cdecl;

function uv_udp_recv_stop(handle: puv_udp_t): Integer; cdecl;

type
  (*
    * uv_tty_t is a subclass of uv_stream_t.
    *
    * Representing a stream for the console.
  *)
  uv_tty_mode_t = ( (* Initial/normal terminal mode *)
    UV_TTY_MODE_NORMAL,
    (* Raw input mode (On Windows, ENABLE_WINDOW_INPUT is also enabled) *)
    UV_TTY_MODE_RAW,
    (* Binary-safe I/O mode for IPC (Unix-only) *)
    UV_TTY_MODE_IO);

function uv_tty_init(loop: puv_loop_t; tty: puv_tty_t; fd: uv_file; readable: Integer): Integer; cdecl;

function uv_tty_set_mode(tty: puv_tty_t; mode: uv_tty_mode_t): Integer; cdecl;

function uv_tty_reset_mode: Integer; cdecl;

function uv_tty_get_winsize(tty: puv_tty_t; var width, height: Integer): Integer; cdecl;
function uv_guess_handle(&file: uv_file): uv_handle_type; cdecl;
(*
  * uv_pipe_t is a subclass of uv_stream_t.
  *
  * Representing a pipe stream or pipe server. On Windows this is a Named
  * Pipe. On Unix this is a Unix domain socket.
*)

function uv_pipe_init(loop: uv_loop_t; handle: puv_pipe_t; ipc: Integer): Integer; cdecl;

function uv_pipe_open(pipe: puv_pipe_t; &file: uv_file): Integer; cdecl;

function uv_pipe_bind(handle: puv_pipe_t; name: pchar): Integer; cdecl;

procedure uv_pipe_connect(req: puv_connect_t; handle: puv_pipe_t; name: pchar; cb: uv_connect_cb); cdecl;

function uv_pipe_getsockname(handle: puv_pipe_t; buffer: pchar; size: psize_t): Integer; cdecl;

function uv_pipe_getpeername(handle: puv_pipe_t; buffer: pchar; size: psize_t): Integer; cdecl;

procedure uv_pipe_pending_instances(handle: puv_pipe_t; count: Integer); cdecl;

function uv_pipe_pending_count(handle: puv_pipe_t): Integer; cdecl;

function uv_pipe_pending_type(handle: puv_pipe_t): uv_handle_type; cdecl;

type

  uv_poll_event = (UV_READABLE = 1, UV_WRITABLE = 2, UV_DISCONNECT = 4);

function uv_poll_init(loop: puv_loop_t; handle: puv_poll_t; fd: Integer): Integer; cdecl;

function uv_poll_init_socket(loop: puv_loop_t; handle: puv_poll_t; socket: uv_os_sock_t): Integer; cdecl;

function uv_poll_start(handle: puv_poll_t; events: Integer; cb: uv_poll_cb): Integer; cdecl;

function uv_poll_stop(handle: puv_poll_t): Integer; cdecl;

function uv_prepare_init(loop: puv_loop_t; prepare: puv_prepare_t): Integer; cdecl;

function uv_prepare_start(prepare: puv_prepare_t; cb: uv_prepare_cb): Integer; cdecl;

function uv_prepare_stop(prepare: puv_prepare_t): Integer; cdecl;

function uv_check_init(loop: puv_loop_t; check: puv_check_t): Integer; cdecl;

function uv_check_start(check: puv_check_t; cb: uv_check_cb): Integer; cdecl;

function uv_check_stop(check: puv_check_t): Integer; cdecl;

function uv_idle_init(loop: puv_loop_t; idle: puv_idle_t): Integer; cdecl;

function uv_idle_start(idle: puv_idle_t; cb: uv_idle_cb): Integer; cdecl;

function uv_idle_stop(idle: puv_idle_t): Integer; cdecl;

function uv_async_init(loop: puv_loop_t; async: puv_async_t; async_cb: uv_async_cb): Integer; cdecl;

function uv_async_send(async: puv_async_t): Integer; cdecl;
(*
  * uv_timer_t is a subclass of uv_handle_t.
  *
  * Used to get woken up at a specified time in the future.
*)

function uv_timer_init(loop: puv_loop_t; handle: puv_timer_t): Integer; cdecl;

function uv_timer_start(handle: puv_timer_t; cb: uv_timer_cb; timeout: UInt64; &repeat: UInt64): Integer; cdecl;

function uv_timer_stop(handle: puv_timer_t): Integer; cdecl;

function uv_timer_again(handle: puv_timer_t): Integer; cdecl;

procedure uv_timer_set_repeat(handle: puv_timer_t; &repeat: UInt64); cdecl;

function uv_timer_get_repeat(handle: puv_timer_t): UInt64; cdecl;
(*
  * uv_getaddrinfo_t is a subclass of uv_req_t.
  *
  * Request object for uv_getaddrinfo.
*)

function uv_getaddrinfo(loop: puv_loop_t; req: puv_getaddrinfo_t; getaddrinfo_cb: uv_getaddrinfo_cb; node: pchar; service: pchar; hints: paddrinfo): Integer; cdecl;

procedure uv_freeaddrinfo(ai: paddrinfo); cdecl;
(*
  * uv_getnameinfo_t is a subclass of uv_req_t.
  *
  * Request object for uv_getnameinfo.
*)
function uv_getnameinfo(loop: puv_loop_t; req: puv_getnameinfo_t; getnameinfo_cb: uv_getnameinfo_cb; addr: psockaddr; flags: Integer): Integer; cdecl;
(* uv_spawn() options. *)
{ !!!3 unknown typedef }

(*
  * These are the flags that can be used for the uv_process_options.flags field.
*)
type
  uv_process_flags = (
    (*
      * Set the child process' user id. The user id is supplied in the `uid` field
      * of the options struct. This does not work on windows; setting this flag
      * will cause uv_spawn() to fail.
    *)
    UV_PROCESS_SETUID = (1 shl 0), UV_PROCESS_SETGID = (1 shl 1),
    (*
      * Set the child process' group id. The user id is supplied in the `gid`
      * field of the options struct. This does not work on windows setting this
      * flag will cause uv_spawn() to fail.
    *)
    UV_PROCESS_WINDOWS_VERBATIM_ARGUMENTS = (1 shl 2),
    (*
      * Do not wrap any arguments in quotes, or perform any other escaping, when
      * converting the argument list into a command line string. This option is
      * only meaningful on Windows systems. On Unix it is silently ignored.
    *)
    UV_PROCESS_DETACHED = (1 shl 3),
    (*
      * Spawn the child process in a detached state - this will make it a process
      * group leader, and will effectively enable the child to keep running after
      * the parent exits.  Note that the child process will still keep the
      * parent's event loop alive unless the parent process calls uv_unref() on
      * the child's process handle.
    *)
    UV_PROCESS_WINDOWS_HIDE = (1 shl 4)
    (*
      * Hide the subprocess console window that would normally be created. This
      * option is only meaningful on Windows systems. On Unix it is silently
      * ignored.
    *)
    );
  (*
    * uv_process_t is a subclass of uv_handle_t.
  *)

  uv_process_options_s = record
  end;

  uv_process_options_t = uv_process_options_s;
  puv_process_options_t = ^uv_process_options_t;

function uv_spawn(loop: puv_loop_t; handle: puv_process_t; const options: puv_process_options_t): Integer; cdecl;

function uv_process_kill(process: puv_process_t; signum: Integer): Integer; cdecl;

function uv_kill(pid: Integer; signum: Integer): Integer; cdecl;
(*
  * uv_work_t is a subclass of uv_req_t.
*)

function uv_queue_work(loop: puv_loop_t; req: puv_work_t; work_cb: uv_work_cb; after_work_cb: uv_after_work_cb): Integer; cdecl;

function uv_cancel(req: puv_req_t): Integer; cdecl;

function uv_setup_args(argc: Integer; argv: PAnsiCharArray): PAnsiCharArray; cdecl;

function uv_get_process_title(buffer: pchar; size: size_t): Integer; cdecl;

function uv_set_process_title(title: pchar): Integer; cdecl;

function uv_resident_set_memory(rss: psize_t): Integer; cdecl;

function uv_uptime(uptime: pdouble): Integer; cdecl;

type
  uv_timeval_t = record
    tv_sec: Integer;
    tv_usec: Integer;
  end;

  puv_timeval_t = ^uv_timeval_t;

  uv_rusage_t = record
    ru_utime: uv_timeval_t; (* user CPU time used *)
    ru_stime: uv_timeval_t; (* system CPU time used *)
    ru_maxrss: UInt64; (* maximum resident set size *)
    ru_ixrss: UInt64; (* integral shared memory size *)
    ru_idrss: UInt64; (* integral unshared data size *)
    ru_isrss: UInt64; (* integral unshared stack size *)
    ru_minflt: UInt64; (* page reclaims (soft page faults) *)
    ru_majflt: UInt64; (* page faults (hard page faults) *)
    ru_nswap: UInt64; (* swaps *)
    ru_inblock: UInt64; (* block input operations *)
    ru_oublock: UInt64; (* block output operations *)
    ru_msgsnd: UInt64; (* IPC messages sent *)
    ru_msgrcv: UInt64; (* IPC messages received *)
    ru_nsignals: UInt64; (* signals received *)
    ru_nvcsw: UInt64; (* voluntary context switches *)
    ru_nivcsw: UInt64; (* involuntary context switches *)
  end;

  puv_rusage_t = ^uv_rusage_t;

function uv_getrusage(rusage: puv_rusage_t): Integer; cdecl;

function uv_os_homedir(buffer: pchar; size: psize_t): Integer; cdecl;

function uv_os_tmpdir(buffer: pchar; size: psize_t): Integer; cdecl;

function uv_os_get_passwd(pwd: puv_passwd_t): Integer; cdecl;

procedure uv_os_free_passwd(pwd: puv_passwd_t); cdecl;

function uv_cpu_info(var cpu_infos: puv_cpu_info_t; var count: Integer): Integer; cdecl;

procedure uv_free_cpu_info(cpu_infos: puv_cpu_info_t; count: Integer); cdecl;

function uv_interface_addresses(var addresses: puv_interface_address_t; var count: Integer): Integer; cdecl;

procedure uv_free_interface_addresses(addresses: puv_interface_address_t; count: Integer); cdecl;

procedure uv_fs_req_cleanup(req: puv_fs_t); cdecl;

function uv_fs_close(loop: puv_loop_t; req: puv_fs_t; &file: uv_file; cb: uv_fs_cb): Integer; cdecl;

function uv_fs_open(loop: puv_loop_t; req: puv_fs_t; path: pchar; flags: Integer; mode: Integer; cb: uv_fs_cb): Integer; cdecl;

function uv_fs_read(loop: puv_loop_t; req: puv_fs_t; &file: uv_file; bufs: puv_buf_array; nbufs: UInt; offset: Int64; cb: uv_fs_cb): Integer; cdecl;

function uv_fs_unlink(loop: puv_loop_t; req: puv_fs_t; path: pchar; cb: uv_fs_cb): Integer; cdecl;

function uv_fs_write(loop: puv_loop_t; req: puv_fs_t; &file: uv_file; bufs: puv_buf_array; nbufs: UInt; offset: Int64; cb: uv_fs_cb): Integer; cdecl;

function uv_fs_mkdir(loop: puv_loop_t; req: puv_fs_t; path: pchar; mode: Integer; cb: uv_fs_cb): Integer; cdecl;

function uv_fs_mkdtemp(loop: puv_loop_t; req: puv_fs_t; tpl: pchar; cb: uv_fs_cb): Integer; cdecl;

function uv_fs_rmdir(loop: puv_loop_t; req: puv_fs_t; path: pchar; cb: uv_fs_cb): Integer; cdecl;

function uv_fs_scandir(loop: puv_loop_t; req: puv_fs_t; path: pchar; flags: Integer; cb: uv_fs_cb): Integer; cdecl;

function uv_fs_scandir_next(req: puv_fs_t; ent: puv_dirent_t): Integer; cdecl;

function uv_fs_stat(loop: puv_loop_t; req: puv_fs_t; path: pchar; cb: uv_fs_cb): Integer; cdecl;

function uv_fs_fstat(loop: puv_loop_t; req: puv_fs_t; &file: uv_file; cb: uv_fs_cb): Integer; cdecl;

function uv_fs_rename(loop: puv_loop_t; req: puv_fs_t; path: pchar; new_path: pchar; cb: uv_fs_cb): Integer; cdecl;

function uv_fs_fsync(loop: puv_loop_t; req: puv_fs_t; &file: uv_file; cb: uv_fs_cb): Integer; cdecl;

function uv_fs_fdatasync(loop: puv_loop_t; req: puv_fs_t; &file: uv_file; cb: uv_fs_cb): Integer; cdecl;

function uv_fs_ftruncate(loop: puv_loop_t; req: puv_fs_t; &file: uv_file; offset: Int64; cb: uv_fs_cb): Integer; cdecl;

function uv_fs_sendfile(loop: puv_loop_t; req: puv_fs_t; out_fd: uv_file; in_fd: uv_file; in_offset: Int64; length: size_t; cb: uv_fs_cb): Integer; cdecl;

function uv_fs_access(loop: puv_loop_t; req: puv_fs_t; path: pchar; mode: Integer; cb: uv_fs_cb): Integer; cdecl;

function uv_fs_chmod(loop: puv_loop_t; req: puv_fs_t; path: pchar; mode: Integer; cb: uv_fs_cb): Integer; cdecl;

function uv_fs_utime(loop: puv_loop_t; req: puv_fs_t; path: pchar; atime: double; mtime: double; cb: uv_fs_cb): Integer; cdecl;

function uv_fs_futime(loop: puv_loop_t; req: puv_fs_t; &file: uv_file; atime: double; mtime: double; cb: uv_fs_cb): Integer; cdecl;

function uv_fs_lstat(loop: puv_loop_t; req: puv_fs_t; path: pchar; cb: uv_fs_cb): Integer; cdecl;

function uv_fs_link(loop: puv_loop_t; req: puv_fs_t; path: pchar; new_path: pchar; cb: uv_fs_cb): Integer; cdecl;

(*
  * This flag can be used with uv_fs_symlink() on Windows to specify whether
  * path argument points to a directory.
*)
const
  UV_FS_SYMLINK_DIR = $0001;
  (*
    * This flag can be used with uv_fs_symlink() on Windows to specify whether
    * the symlink is to be created using junction points.
  *)
  UV_FS_SYMLINK_JUNCTION = $0002;

function uv_fs_symlink(loop: puv_loop_t; req: puv_fs_t; path: pchar; new_path: pchar; flags: Integer; cb: uv_fs_cb): Integer; cdecl;

function uv_fs_readlink(loop: puv_loop_t; req: puv_fs_t; path: pchar; cb: uv_fs_cb): Integer; cdecl;

function uv_fs_realpath(loop: puv_loop_t; req: puv_fs_t; path: pchar; cb: uv_fs_cb): Integer; cdecl;

function uv_fs_fchmod(loop: puv_loop_t; req: puv_fs_t; &file: uv_file; mode: Integer; cb: uv_fs_cb): Integer; cdecl;

function uv_fs_chown(loop: puv_loop_t; req: puv_fs_t; path: pchar; uid: uv_uid_t; gid: uv_gid_t; cb: uv_fs_cb): Integer; cdecl;

function uv_fs_fchown(loop: puv_loop_t; req: puv_fs_t; &file: uv_file; uid: uv_uid_t; gid: uv_gid_t; cb: uv_fs_cb): Integer; cdecl;

type
  uv_fs_event = (UV_RENAME = 1, UV_CHANGE = 2);

  (*
    * uv_fs_stat() based polling file watcher.
  *)

function uv_fs_poll_init(loop: puv_loop_t; handle: puv_fs_poll_t): Integer; cdecl;

function uv_fs_poll_start(handle: puv_fs_poll_t; poll_cb: uv_fs_poll_cb; path: pchar; interval: UInt): Integer; cdecl;

function uv_fs_poll_stop(handle: puv_fs_poll_t): Integer; cdecl;

function uv_fs_poll_getpath(handle: puv_fs_poll_t; buffer: pchar; size: psize_t): Integer; cdecl;

function uv_signal_init(loop: puv_loop_t; handle: puv_signal_t): Integer; cdecl;

function uv_signal_start(handle: puv_signal_t; signal_cb: uv_signal_cb; signum: Integer): Integer; cdecl;

function uv_signal_stop(handle: puv_signal_t): Integer; cdecl;

type
  uv_loadavg_param = array [0 .. 2] of double;
procedure uv_loadavg(avg: uv_loadavg_param); cdecl;

type
  (*
    * Flags to be passed to uv_fs_event_start().
  *)
  uv_fs_event_flags = ( (*
      * By default, if the fs event watcher is given a directory name, we will
      * watch for all events in that directory. This flags overrides this behavior
      * and makes fs_event report only changes to the directory entry itself. This
      * flag does not affect individual files watched.
      * This flag is currently not implemented yet on any backend.
    *)
    UV_FS_EVENT_WATCH_ENTRY = 1, UV_FS_EVENT_STAT = 2,
    (*
      * By default uv_fs_event will try to use a kernel interface such as inotify
      * or kqueue to detect events. This may not work on remote filesystems such
      * as NFS mounts. This flag makes fs_event fall back to calling stat() on a
      * regular interval.
      * This flag is currently not implemented yet on any backend.
    *)
    UV_FS_EVENT_RECURSIVE = 4
    (*
      * By default, event watcher, when watching directory, is not registering
      * (is ignoring) changes in it's subdirectories.
      * This flag will override this behaviour on platforms that support it.
    *)
    );

function uv_fs_event_init(loop: puv_loop_t; handle: puv_fs_event_t): Integer; cdecl;

function uv_fs_event_start(handle: puv_fs_event_t; cb: uv_fs_event_cb; path: pchar; flags: UInt): Integer; cdecl;

function uv_fs_event_stop(handle: puv_fs_event_t): Integer; cdecl;

function uv_fs_event_getpath(handle: puv_fs_event_t; buffer: pchar; size: psize_t): Integer; cdecl;

function uv_ip4_addr(ip: pchar; port: Integer; addr: PSockAddrIn): Integer; cdecl;

function uv_ip6_addr(ip: pchar; port: Integer; addr: psockaddr_in6): Integer; cdecl;

function uv_ip4_name(src: PSockAddrIn; dst: pchar; size: size_t): Integer; cdecl;

function uv_ip6_name(src: psockaddr_in6; dst: pchar; size: size_t): Integer; cdecl;

function uv_inet_ntop(af: Integer; src: pinteger; dst: pchar; size: size_t): Integer; cdecl;

function uv_inet_pton(af: Integer; src: pchar; dst: pinteger): Integer; cdecl;

function uv_exepath(buffer: pchar; size: psize_t): Integer; cdecl;

function uv_cwd(buffer: pchar; size: psize_t): Integer; cdecl;

function uv_chdir(dir: pchar): Integer; cdecl;

function uv_get_free_memory: UInt64; cdecl;

function uv_get_total_memory: UInt64; cdecl;

function uv_hrtime: UInt64; cdecl;

procedure uv_disable_stdio_inheritance; cdecl;

function uv_dlopen(filename: pchar; lib: puv_lib_t): Integer; cdecl;

procedure uv_dlclose(lib: puv_lib_t); cdecl;

function uv_dlsym(lib: puv_lib_t; name: pchar; var ptr: Pointer): Integer; cdecl;

function uv_dlerror(lib: puv_lib_t): pchar; cdecl;

function uv_mutex_init(handle: puv_mutex_t): Integer; cdecl;

procedure uv_mutex_destroy(handle: puv_mutex_t); cdecl;

procedure uv_mutex_lock(handle: puv_mutex_t); cdecl;

function uv_mutex_trylock(handle: puv_mutex_t): Integer; cdecl;

procedure uv_mutex_unlock(handle: puv_mutex_t); cdecl;

function uv_rwlock_init(rwlock: puv_rwlock_t): Integer; cdecl;

procedure uv_rwlock_destroy(rwlock: puv_rwlock_t); cdecl;

procedure uv_rwlock_rdlock(rwlock: puv_rwlock_t); cdecl;

function uv_rwlock_tryrdlock(rwlock: puv_rwlock_t): Integer; cdecl;

procedure uv_rwlock_rdunlock(rwlock: puv_rwlock_t); cdecl;

procedure uv_rwlock_wrlock(rwlock: puv_rwlock_t); cdecl;

function uv_rwlock_trywrlock(rwlock: puv_rwlock_t): Integer; cdecl;

procedure uv_rwlock_wrunlock(rwlock: puv_rwlock_t); cdecl;

function uv_sem_init(sem: puv_sem_t; value: UInt): Integer; cdecl;

procedure uv_sem_destroy(sem: puv_sem_t); cdecl;

procedure uv_sem_post(sem: puv_sem_t); cdecl;

procedure uv_sem_wait(sem: puv_sem_t); cdecl;

function uv_sem_trywait(sem: puv_sem_t): Integer; cdecl;

function uv_cond_init(cond: puv_cond_t): Integer; cdecl;

procedure uv_cond_destroy(cond: puv_cond_t); cdecl;

procedure uv_cond_signal(cond: puv_cond_t); cdecl;

procedure uv_cond_broadcast(cond: puv_cond_t); cdecl;

function uv_barrier_init(barrier: puv_barrier_t; count: UInt): Integer; cdecl;

procedure uv_barrier_destroy(barrier: puv_barrier_t); cdecl;

function uv_barrier_wait(barrier: puv_barrier_t): Integer; cdecl;

procedure uv_cond_wait(cond: puv_cond_t; mutex: puv_mutex_t); cdecl;

function uv_cond_timedwait(cond: puv_cond_t; mutex: puv_mutex_t; timeout: UInt64): Integer; cdecl;

type
  TOnceProcedure = procedure; cdecl;

procedure uv_once(guard: puv_once_t; callback: TOnceProcedure)cdecl;

function uv_key_create(key: puv_key_t): Integer; cdecl;

procedure uv_key_delete(key: puv_key_t); cdecl;

procedure uv_key_get(key: puv_key_t); cdecl;

procedure uv_key_set(key: puv_key_t; value: pinteger); cdecl;

type
  uv_thread_cb = procedure(arg: pinteger); cdecl;

function uv_thread_create(tid: puv_thread_t; entry: uv_thread_cb; arg: pinteger): Integer; cdecl;

function uv_thread_self: uv_thread_t; cdecl;

function uv_thread_join(tid: puv_thread_t): Integer; cdecl;

function uv_thread_equal(t1: puv_thread_t; t2: puv_thread_t): Integer; cdecl;
(* The presence of these unions force similar struct layout. *)

implementation

function uv_version; external DLLFILE;

function uv_version_string; external DLLFILE;

function uv_replace_allocator; external DLLFILE;

function uv_default_loop; external DLLFILE;

function uv_loop_init; external DLLFILE;

function uv_loop_close; external DLLFILE;

function uv_loop_new; external DLLFILE;

procedure uv_loop_delete; external DLLFILE;

function uv_loop_size; external DLLFILE;

function uv_loop_alive; external DLLFILE;

function uv_loop_configure; external DLLFILE;

function uv_run; external DLLFILE;

procedure uv_stop; external DLLFILE;

procedure uv_ref; external DLLFILE;

procedure uv_unref; external DLLFILE;

function uv_has_ref; external DLLFILE;

procedure uv_update_time; external DLLFILE;

function uv_no; external DLLFILE;

function uv_backend_fd; external DLLFILE;

function uv_backend_timeout; external DLLFILE;

function uv_strerror; external DLLFILE;

function uv_err_name; external DLLFILE;

function uv_shutdown; external DLLFILE;

function uv_handle_size; external DLLFILE;

function uv_req_size; external DLLFILE;

function uv_is_active; external DLLFILE;

procedure uv_walk; external DLLFILE;

procedure uv_print_all_handles; external DLLFILE;

procedure uv_print_active_handles; external DLLFILE;

procedure uv_close; external DLLFILE;

function uv_send_buffer_size; external DLLFILE;

function uv_recv_buffer_size; external DLLFILE;

function uv_fileno; external DLLFILE;

function uv_buf_init; external DLLFILE;

function uv_listen; external DLLFILE;

function uv_accept; external DLLFILE;

function uv_read_start; external DLLFILE;

function uv_read_stop; external DLLFILE;

function uv_write; external DLLFILE;

function uv_write2; external DLLFILE;

function uv_try_write; external DLLFILE;

function uv_is_readable; external DLLFILE;

function uv_is_writable; external DLLFILE;

function uv_stream_set_blocking; external DLLFILE;

function uv_is_closing; external DLLFILE;

function uv_tcp_init; external DLLFILE;

function uv_tcp_init_ex; external DLLFILE;

function uv_tcp_open; external DLLFILE;

function uv_tcp_nodelay; external DLLFILE;

function uv_tcp_keepalive; external DLLFILE;

function uv_tcp_simultaneous_accepts; external DLLFILE;

function uv_tcp_bind; external DLLFILE;

function uv_tcp_getsockname; external DLLFILE;

function uv_tcp_getpeername; external DLLFILE;

function uv_tcp_connect; external DLLFILE;
function uv_udp_init; external DLLFILE;

function uv_udp_init_ex; external DLLFILE;

function uv_udp_open; external DLLFILE;

function uv_udp_bind; external DLLFILE;

function uv_udp_getsockname; external DLLFILE;

function uv_udp_set_membership; external DLLFILE;

function uv_udp_set_multicast_loop; external DLLFILE;

function uv_udp_set_multicast_ttl; external DLLFILE;

function uv_udp_set_multicast_interface; external DLLFILE;

function uv_udp_set_broadcast; external DLLFILE;

function uv_udp_set_ttl; external DLLFILE;

function uv_udp_send; external DLLFILE;

function uv_udp_try_send; external DLLFILE;

function uv_udp_recv_start; external DLLFILE;

function uv_udp_recv_stop; external DLLFILE;

function uv_tty_init; external DLLFILE;

function uv_tty_set_mode; external DLLFILE;

function uv_tty_reset_mode; external DLLFILE;

function uv_tty_get_winsize; external DLLFILE;
function uv_guess_handle; external DLLFILE;

function uv_pipe_init; external DLLFILE;

function uv_pipe_open; external DLLFILE;

function uv_pipe_bind; external DLLFILE;

procedure uv_pipe_connect; external DLLFILE;

function uv_pipe_getsockname; external DLLFILE;

function uv_pipe_getpeername; external DLLFILE;

procedure uv_pipe_pending_instances; external DLLFILE;

function uv_pipe_pending_count; external DLLFILE;

function uv_pipe_pending_type; external DLLFILE;

function uv_poll_init; external DLLFILE;

function uv_poll_init_socket; external DLLFILE;

function uv_poll_start; external DLLFILE;

function uv_poll_stop; external DLLFILE;

function uv_prepare_init; external DLLFILE;

function uv_prepare_start; external DLLFILE;

function uv_prepare_stop; external DLLFILE;

function uv_check_init; external DLLFILE;

function uv_check_start; external DLLFILE;

function uv_check_stop; external DLLFILE;

function uv_idle_init; external DLLFILE;

function uv_idle_start; external DLLFILE;

function uv_idle_stop; external DLLFILE;

function uv_async_init; external DLLFILE;

function uv_async_send; external DLLFILE;

function uv_timer_init; external DLLFILE;

function uv_timer_start; external DLLFILE;

function uv_timer_stop; external DLLFILE;

function uv_timer_again; external DLLFILE;

procedure uv_timer_set_repeat; external DLLFILE;

function uv_timer_get_repeat; external DLLFILE;

function uv_getaddrinfo; external DLLFILE;

procedure uv_freeaddrinfo; external DLLFILE;

function uv_getnameinfo; external DLLFILE;

function uv_spawn; external DLLFILE;

function uv_process_kill; external DLLFILE;

function uv_kill; external DLLFILE;

function uv_queue_work; external DLLFILE;

function uv_cancel; external DLLFILE;

function uv_setup_args; external DLLFILE;

function uv_get_process_title; external DLLFILE;

function uv_set_process_title; external DLLFILE;

function uv_resident_set_memory; external DLLFILE;

function uv_uptime; external DLLFILE;

function uv_getrusage; external DLLFILE;

function uv_os_homedir; external DLLFILE;

function uv_os_tmpdir; external DLLFILE;

function uv_os_get_passwd; external DLLFILE;

procedure uv_os_free_passwd; external DLLFILE;

function uv_cpu_info; external DLLFILE;

procedure uv_free_cpu_info; external DLLFILE;

function uv_interface_addresses; external DLLFILE;

procedure uv_free_interface_addresses; external DLLFILE;

procedure uv_fs_req_cleanup; external DLLFILE;

function uv_fs_close; external DLLFILE;

function uv_fs_open; external DLLFILE;

function uv_fs_read; external DLLFILE;

function uv_fs_unlink; external DLLFILE;

function uv_fs_write; external DLLFILE;

function uv_fs_mkdir; external DLLFILE;

function uv_fs_mkdtemp; external DLLFILE;

function uv_fs_rmdir; external DLLFILE;

function uv_fs_scandir; external DLLFILE;

function uv_fs_scandir_next; external DLLFILE;

function uv_fs_stat; external DLLFILE;

function uv_fs_fstat; external DLLFILE;

function uv_fs_rename; external DLLFILE;

function uv_fs_fsync; external DLLFILE;

function uv_fs_fdatasync; external DLLFILE;

function uv_fs_ftruncate; external DLLFILE;

function uv_fs_sendfile; external DLLFILE;

function uv_fs_access; external DLLFILE;

function uv_fs_chmod; external DLLFILE;

function uv_fs_utime; external DLLFILE;

function uv_fs_futime; external DLLFILE;

function uv_fs_lstat; external DLLFILE;

function uv_fs_link; external DLLFILE;

function uv_fs_symlink; external DLLFILE;

function uv_fs_readlink; external DLLFILE;

function uv_fs_realpath; external DLLFILE;

function uv_fs_fchmod; external DLLFILE;

function uv_fs_chown; external DLLFILE;

function uv_fs_fchown; external DLLFILE;

function uv_fs_poll_init; external DLLFILE;

function uv_fs_poll_start; external DLLFILE;

function uv_fs_poll_stop; external DLLFILE;

function uv_fs_poll_getpath; external DLLFILE;

function uv_signal_init; external DLLFILE;

function uv_signal_start; external DLLFILE;

function uv_signal_stop; external DLLFILE;

procedure uv_loadavg; external DLLFILE;

function uv_fs_event_init; external DLLFILE;

function uv_fs_event_start; external DLLFILE;

function uv_fs_event_stop; external DLLFILE;

function uv_fs_event_getpath; external DLLFILE;

function uv_ip4_addr; external DLLFILE;

function uv_ip6_addr; external DLLFILE;

function uv_ip4_name; external DLLFILE;

function uv_ip6_name; external DLLFILE;

function uv_inet_ntop; external DLLFILE;

function uv_inet_pton; external DLLFILE;

function uv_exepath; external DLLFILE;

function uv_cwd; external DLLFILE;

function uv_chdir; external DLLFILE;

function uv_get_free_memory; external DLLFILE;

function uv_get_total_memory; external DLLFILE;

function uv_hrtime; external DLLFILE;

procedure uv_disable_stdio_inheritance; external DLLFILE;

function uv_dlopen; external DLLFILE;

procedure uv_dlclose; external DLLFILE;

function uv_dlsym; external DLLFILE;

function uv_dlerror; external DLLFILE;

function uv_mutex_init; external DLLFILE;

procedure uv_mutex_destroy; external DLLFILE;

procedure uv_mutex_lock; external DLLFILE;

function uv_mutex_trylock; external DLLFILE;

procedure uv_mutex_unlock; external DLLFILE;

function uv_rwlock_init; external DLLFILE;

procedure uv_rwlock_destroy; external DLLFILE;

procedure uv_rwlock_rdlock; external DLLFILE;

function uv_rwlock_tryrdlock; external DLLFILE;

procedure uv_rwlock_rdunlock; external DLLFILE;

procedure uv_rwlock_wrlock; external DLLFILE;

function uv_rwlock_trywrlock; external DLLFILE;

procedure uv_rwlock_wrunlock; external DLLFILE;

function uv_sem_init; external DLLFILE;

procedure uv_sem_destroy; external DLLFILE;

procedure uv_sem_post; external DLLFILE;

procedure uv_sem_wait; external DLLFILE;

function uv_sem_trywait; external DLLFILE;

function uv_cond_init; external DLLFILE;

procedure uv_cond_destroy; external DLLFILE;

procedure uv_cond_signal; external DLLFILE;

procedure uv_cond_broadcast; external DLLFILE;

function uv_barrier_init; external DLLFILE;

procedure uv_barrier_destroy; external DLLFILE;

function uv_barrier_wait; external DLLFILE;

procedure uv_cond_wait; external DLLFILE;

function uv_cond_timedwait; external DLLFILE;

procedure uv_once; external DLLFILE;

function uv_key_create; external DLLFILE;

procedure uv_key_delete; external DLLFILE;

procedure uv_key_get; external DLLFILE;

procedure uv_key_set; external DLLFILE;

function uv_thread_create; external DLLFILE;

function uv_thread_self; external DLLFILE;

function uv_thread_join; external DLLFILE;

function uv_thread_equal; external DLLFILE;

end.
