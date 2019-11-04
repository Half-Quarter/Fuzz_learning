#### run_target()
---

```c
 /* Execute target application, monitoring for timeouts. Return status
   information. The called program will update trace_bits[]. */
//执行目标应用，监视超时并返回状态信息
static u8 run_target(char** argv, u32 timeout) {
  //初始化变量
  static struct itimerval it;
  static u32 prev_timed_out = 0;
  int status = 0;
  u32 tb4;
  child_timed_out = 0;

 //初始化trace_bits数组
  memset(trace_bits, 0, MAP_SIZE);
  MEM_BARRIER();

  //如果我们在dumb模式下或者没有配置forkserver，我们就手动fork一个子进程
  if (dumb_mode == 1 || no_forkserver) {
    child_pid = fork();
    if (child_pid < 0) PFATAL("fork() failed");
    if (!child_pid) {
    //rlimit是描述资源软硬限制的结构体，里面包含rlim_cur和rlim_max两个参数
      struct rlimit r;
      if (mem_limit) {
        r.rlim_max = r.rlim_cur = ((rlim_t)mem_limit) << 20;
#ifdef RLIMIT_AS
    //RLIMIT_AS 设置进程的最大虚内存空间，字节为单位
        setrlimit(RLIMIT_AS, &r); /* Ignore errors */
#else
   //设置进程数据段的最大值
        setrlimit(RLIMIT_DATA, &r); /* Ignore errors */
#endif /* ^RLIMIT_AS */
      }
      r.rlim_max = r.rlim_cur = 0;
      //设置内存转存文件的最大长度
      setrlimit(RLIMIT_CORE, &r); /* Ignore errors */

      //新建进程组
      setsid();
      //重定向fd为1，2
      dup2(dev_null_fd, 1);
      dup2(dev_null_fd, 2);
       //如果fuzz文件被指定，重定向fd为标准输入
      if (out_file) {
        dup2(dev_null_fd, 0);
      } 
      //否则关闭out_fd
      else {
        dup2(out_fd, 0);
        close(out_fd);

      }

      /* On Linux, would be faster to use O_CLOEXEC. Maybe TODO. */
      close(dev_null_fd);
      close(out_dir_fd);
      close(dev_urandom_fd);
      close(fileno(plot_file));
      //设置ASAN的环境变量
      setenv("ASAN_OPTIONS", "abort_on_error=1:"
                             "detect_leaks=0:"
                             "symbolize=0:"
                             "allocator_may_return_null=1", 0);
      setenv("MSAN_OPTIONS", "exit_code=" STRINGIFY(MSAN_ERROR) ":"
                             "symbolize=0:"
                             "msan_track_origins=0", 0);
     //停止执行当前进程，用target_path应用程序替换被停止的进程，进程ID不变
      execv(target_path, argv);
     //使用一个独特的bitmap来通知父进程是否失败
      *(u32*)trace_bits = EXEC_FAIL_SIG;
      exit(0);
    }
  } else {
    s32 res;
    //如果在非dumb模式，我们让forkserver启动运行，只需要简单的打开pid
    //fsrv_ctl_fd管道用来写，prev_timed_out是跟踪超时时间
    if ((res = write(fsrv_ctl_fd, &prev_timed_out, 4)) != 4) {
      if (stop_soon) return 0;
      RPFATAL(res, "Unable to request new process from fork server (OOM?)");
    }
     //fsrv_st_fd管道用来读，读取子进程pid
    if ((res = read(fsrv_st_fd, &child_pid, 4)) != 4) {
      if (stop_soon) return 0;
      RPFATAL(res, "Unable to request new process from fork server (OOM?)");
    }
    if (child_pid <= 0) FATAL("Fork server is misbehaving (OOM?)");
  }

 //配置超时时间，等到子进程终止
  it.it_value.tv_sec = (timeout / 1000);
  it.it_value.tv_usec = (timeout % 1000) * 1000;
  setitimer(ITIMER_REAL, &it, NULL);

 //sigalrm处理程序结束子进程设置子进程超时
 //如果是dumb模式开启或者没有配置forkserver
  if (dumb_mode == 1 || no_forkserver) {
    /*wait()用于使父进程阻塞，直到一个子进程结束或者该进程接收到了一个指定的信号为止
status是一个整形指针，是该进程退出时的状态，若status不为空，则通过它可以获得子进程的结束状态。
child_pid>0只等待进程id等于pid的子进程，只要指定子进程没结束，就会一直等待；
child_pid=-1 等待任何一个子进程退出;
child_pid=0等待该组id等于调用进程的组id的任一子进程;
child_pid<-1 等待该组id等于pid的绝对值的任一子程序
     waitpid返回0 -1是异常
  */
    if (waitpid(child_pid, &status, 0) <= 0) PFATAL("waitpid() failed");
  }
  /*** 启动forkserver 获取PID ***/
  else {
    s32 res;
    //读取子进程状态
    if ((res = read(fsrv_st_fd, &status, 4)) != 4) {
      if (stop_soon) return 0;
      RPFATAL(res, "Unable to communicate with fork server (OOM?)");
    }
  }

  if (!WIFSTOPPED(status)) child_pid = 0;
  it.it_value.tv_sec = 0;
  it.it_value.tv_usec = 0;
  /*Linux C函数，实现延时和定时
    第一个参数which是类型：ITIMER_REAL是以系统真实时间来计算
  */
  setitimer(ITIMER_REAL, &it, NULL);
  //execs运行总数+1
  total_execs++;

  /* Any subsequent operations on trace_bits must not be moved by the
     compiler below this point. Past this location, trace_bits[] behave
     very normally and do not have to be treated as volatile. */

  MEM_BARRIER();
  //将trace_bits存到tb4临时变量里
  tb4 = *(u32*)trace_bits;
  //分别执行32和64位下面的函数classify_counts()设置tracebit所在的内存
#ifdef __x86_64__
  classify_counts((u64*)trace_bits);
#else
  classify_counts((u32*)trace_bits);
#endif /* ^__x86_64__ */

  prev_timed_out = child_timed_out;

  //结果报告
  if (WIFSIGNALED(status) && !stop_soon) {
    //WTERMSIG(status) 取得子进程因信号而中止的信号
    kill_signal = WTERMSIG(status);
    //返回超时错误
    if (child_timed_out && kill_signal == SIGKILL) return FAULT_TMOUT;
    //返回崩溃错误
    return FAULT_CRASH;
  }
  //asan
  if (uses_asan && WEXITSTATUS(status) == MSAN_ERROR) {
    kill_signal = 0;
    return FAULT_CRASH;
  }
  //tb4临时变量里存的是失败 且 dumb模式开或没有配置forkserver 返回error
  if ((dumb_mode == 1 || no_forkserver) && tb4 == EXEC_FAIL_SIG)
    return FAULT_ERROR;

  return FAULT_NONE;

}
```

问题：forkserver是为了绕过execve 节省了载入目标文件和库、解析符号地址等重复性工作 那他是怎么执行的呢

​           分桶 save_if_interest