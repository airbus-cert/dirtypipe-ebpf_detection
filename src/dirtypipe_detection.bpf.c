#include "vmlinux.h"
#include "dirtypipe_detection_event.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

#define S_IFMT	00170000
#define S_IFREG	0100000
#define S_IFIFO	0010000
#define S_ISFIFO(m)	(((m) & S_IFMT) == S_IFIFO)
#define S_ISREG(m)	(((m) & S_IFMT) == S_IFREG)
#define FMODE_READ	((fmode_t)0x1)
#define FMODE_WRITE	((fmode_t)0x2)
#define PIPE_BUF_FLAG_CAN_MERGE	0x10

char LICENSE[] SEC("license") = "Dual BSD/GPL";

/****************************************************/
/*!
 *  \brief  Structure use for local context
 */
struct fd_struct{
  int                      i_mode;
  unsigned int 	           i_uid;
  unsigned int 	           i_gid;
  unsigned int 	           f_mode;
  unsigned int 	           flags;
  struct qstr              d_name;
};

/****************************************************/
/*!
 *  \brief  Ring buffer map use to send event 
 *          to the userland program
 */
struct {
  __uint(type, BPF_MAP_TYPE_RINGBUF);
  __uint(max_entries, 256 * 1024);
} rb SEC(".maps");

/****************************************************/
/*!
 *  \brief  tracepoint on the splice() syscall entry
 *          The signature of the syscall is :
 *          ssize_t splice(int fd_in, loff_t *off_in, int fd_out, loff_t *off_out, size_t len, unsigned int flags);
 */
SEC("tp/syscalls/sys_enter_splice")
int trace_syscall_splice_dirtypipe(struct trace_event_raw_sys_enter *ctx){
  int fd_in  = ctx->args[0]; // fd_in parameter from splice syscall
  int fd_out = ctx->args[2]; // fd_out parameter from splice syscall
  struct task_struct *task = (struct task_struct *)bpf_get_current_task();

  // task_struct substructures and variables declaration
  struct files_struct     *files;
  struct fdtable          *fdt;
  struct file             **fd;
  struct file             *f;
  struct dentry           *dentry;
  struct qstr              d_name;
  struct inode            *d_inode;
  struct pipe_inode_info  *i_pipe;
  struct pipe_buffer      *bufs;
  struct pipe_buffer       buf;

  unsigned int 	           f_mode;
  unsigned int 	           i_uid;
  unsigned int 	           i_gid;
  int                      i_mode;
  unsigned int 	           flags;
  unsigned int 	           ring_size;

  bpf_probe_read(&files    , sizeof(files)    , &task->files);
  bpf_probe_read(&fdt      , sizeof(fdt)      , &files->fdt);
  bpf_probe_read(&fd       , sizeof(fd)       , &fdt->fd);
  bpf_probe_read(&f        , sizeof(f)        , &fd[fd_in]);
  bpf_probe_read(&dentry   , sizeof(dentry)   , &f->f_path.dentry);
  bpf_probe_read(&f_mode   , sizeof(f_mode)   , &f->f_mode);
  bpf_probe_read(&d_name   , sizeof(d_name)   , &dentry->d_name);
  bpf_probe_read(&d_inode  , sizeof(d_inode)  , &dentry->d_inode);
  bpf_probe_read(&i_uid    , sizeof(i_uid)    , &d_inode->i_uid.val);
  bpf_probe_read(&i_gid    , sizeof(i_gid)    , &d_inode->i_gid.val);
  bpf_probe_read(&i_mode   , sizeof(i_mode)   , &d_inode->i_mode);

  // Save it as input file descriptor information
  struct fd_struct in = {
    .i_mode  = i_mode,
    .i_uid   = i_uid,
    .i_gid   = i_gid,
    .f_mode  = f_mode,
    .d_name  = d_name
  };

  bpf_probe_read(&f        , sizeof(f)        , &fd[fd_out]);
  bpf_probe_read(&dentry   , sizeof(dentry)   , &f->f_path.dentry);
  bpf_probe_read(&d_inode  , sizeof(d_inode)  , &dentry->d_inode);
  bpf_probe_read(&i_mode   , sizeof(i_mode)   , &d_inode->i_mode);
  bpf_probe_read(&i_pipe   , sizeof(i_pipe)   , &d_inode->i_pipe);
  bpf_probe_read(&ring_size, sizeof(ring_size), &i_pipe->ring_size);
  bpf_probe_read(&bufs     , sizeof(bufs)     , &i_pipe->bufs);
  bpf_probe_read(&buf      , sizeof(buf)      , &bufs[ring_size-1]);
  bpf_probe_read(&flags    , sizeof(flags)    , &buf.flags);

  // Save it as output file descriptor information
  struct fd_struct out = {
    .i_mode  = i_mode,
    .flags   = flags,
  };

  // Exit if the input file descriptor is not a file, and if the output one is not a pipe
  if(!(S_ISREG(in.i_mode) && S_ISFIFO(out.i_mode))) return 0;

  // Exit if the input file descriptor is not read only
  if((in.f_mode & (FMODE_READ | FMODE_WRITE)) != FMODE_READ) return 0;

  // If the flag PIPE_BUF_FLAG_CAN_MERGE is set in the last page ring buf, send the event
  if(out.flags & PIPE_BUF_FLAG_CAN_MERGE){
    event_t* event;
    event = bpf_ringbuf_reserve(&rb, sizeof(event_t), 0);
    if(!event) return 0;

    event->pid  = bpf_get_current_pid_tgid() >> 32;
    event->time = bpf_ktime_get_ns();
    event->uid  = bpf_get_current_uid_gid();

    bpf_probe_read(event->target, sizeof(event->target), in.d_name.name);
    bpf_get_current_comm(event->process, sizeof(event->process));
    bpf_ringbuf_submit(event, 0);
  }
  return 0;
};
