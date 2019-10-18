### AFL-Fuzz 源码解析
---

```c
/* Main entry point */

int main(int argc, char** argv) {

  s32 opt;
  u64 prev_queued = 0;
  u32 sync_interval_cnt = 0, seek_to;
  u8  *extras_dir = 0;
  u8  mem_limit_given = 0;
  u8  exit_1 = !!getenv("AFL_BENCH_JUST_ONE");
   // !!非0值 = 1，而!!0 = 0
   //仅进行基准测试：AFL_BENCH_JUST_ONE环境变量使模糊器在处理了第一个队列条目后退出；
    char** use_argv;

  //设定时间
  struct timeval tv; 
  struct timezone tz;
 
  SAYF(cCYA "afl-fuzz " cBRI VERSION cRST " by <lcamtuf@google.com>\n");
  
  /* 文件路径 Path to documentation dir        
     access（需要检测的文件路径，需要测试的操作模式）
     F_OK 测试文件是否存在
     所以若存在就将文件路径存到doc_path中
     不存在就保存一个字符串docs到doc_path中
  */
  doc_path = access(DOC_PATH, F_OK) ? "docs" : DOC_PATH;
  
  //获取时间
  gettimeofday(&tv, &tz);
  
  //srandom是给random设定种子 说明random的随机数和 时间 id的异或有关
  srandom(tv.tv_sec ^ tv.tv_usec ^ getpid());

 //获取配置
  while ((opt = getopt(argc, argv, "+i:o:f:m:t:T:dnCB:S:M:x:Q")) > 0)

    switch (opt) {
      //设置输入文件夹
      case 'i': /* input dir */

        if (in_dir) FATAL("Multiple -i options not supported");
        in_dir = optarg;

        if (!strcmp(in_dir, "-")) in_place_resume = 1;

        break;
     //设置输出文件夹
      case 'o': /* output dir */

        if (out_dir) FATAL("Multiple -o options not supported");
        out_dir = optarg;
        break;
     
     //多核处理器 分布式处理时的设置的主节点
      case 'M': { /* master sync ID */

          u8* c;

          if (sync_id) FATAL("Multiple -S or -M options not supported");
          sync_id = ck_strdup(optarg);

          if ((c = strchr(sync_id, ':'))) {

            *c = 0;

            if (sscanf(c + 1, "%u/%u", &master_id, &master_max) != 2 ||
             !master_id || !master_max || master_id > master_max ||
             master_max > 1000000) FATAL("Bogus master ID passed to -M");
          }
          force_deterministic = 1;
        }
        break;
      //多核处理器时设置的子节点
      case 'S': 
        if (sync_id) FATAL("Multiple -S or -M options not supported");
        sync_id = ck_strdup(optarg);
        break;
      //模糊测试程序读取位置stdin
      case 'f': /* target file */
        if (out_file) FATAL("Multiple -f options not supported");
        out_file = optarg;
        break;
      //测试字典
      case 'x': /* dictionary */

        if (extras_dir) FATAL("Multiple -x options not supported");
        extras_dir = optarg;
        break;
      
      //每次运行的超时时间设置
      case 't': { /* timeout */

          u8 suffix = 0;

          if (timeout_given) FATAL("Multiple -t options not supported");

          if (sscanf(optarg, "%u%c", &exec_tmout, &suffix) < 1 ||
              optarg[0] == '-') FATAL("Bad syntax used for -t");

          if (exec_tmout < 5) FATAL("Dangerously low value of -t");

          if (suffix == '+') timeout_given = 2; else timeout_given = 1;

          break;

      }
      //子进程的内存限制
      case 'm': { /* mem limit */

          u8 suffix = 'M';

          if (mem_limit_given) FATAL("Multiple -m options not supported");
          mem_limit_given = 1;

          if (!strcmp(optarg, "none")) {

            mem_limit = 0;
            break;

          }

          if (sscanf(optarg, "%llu%c", &mem_limit, &suffix) < 1 ||
              optarg[0] == '-') FATAL("Bad syntax used for -m");

          switch (suffix) {

            case 'T': mem_limit *= 1024 * 1024; break;
            case 'G': mem_limit *= 1024; break;
            case 'k': mem_limit /= 1024; break;
            case 'M': break;

            default:  FATAL("Unsupported suffix or bad syntax for -m");

          }

          if (mem_limit < 5) FATAL("Dangerously low value of -m");

          if (sizeof(rlim_t) == 4 && mem_limit > 2000)
            FATAL("Value of -m out of range on 32-bit systems");

        }

        break;
     // 快速模式 跳过确定性步骤
      case 'd': /* skip deterministic */

        if (skip_deterministic) FATAL("Multiple -d options not supported");
        skip_deterministic = 1;
        use_splicing = 1;
        break;
      
      //之前运行会产生bitmap 可以再指向并加载
      case 'B': /* load bitmap */
        if (in_bitmap) FATAL("Multiple -B options not supported");

        in_bitmap = optarg;
        read_bitmap(in_bitmap);
        break;
      
      //崩溃探查模式
      case 'C': /* crash mode */

        if (crash_mode) FATAL("Multiple -C options not supported");
        crash_mode = FAULT_CRASH;
        break;
      
      //无插桩模糊测试
      case 'n': /* dumb mode */

        if (dumb_mode) FATAL("Multiple -n options not supported");
        if (getenv("AFL_DUMB_FORKSRV")) dumb_mode = 2; else dumb_mode = 1;

        break;
      
      //要在屏幕上显示的文本
      case 'T': /* banner */

        if (use_banner) FATAL("Multiple -T options not supported");
        use_banner = optarg;
        break;
      
      //qemu模式打开
      case 'Q': /* QEMU mode */

        if (qemu_mode) FATAL("Multiple -Q options not supported");
        qemu_mode = 1;

        if (!mem_limit_given) mem_limit = MEM_LIMIT_QEMU;

        break;

      default:

        usage(argv[0]);

    }
   
  if (optind == argc || !in_dir || !out_dir) usage(argv[0]);
  
  //信号处理 
  setup_signal_handlers();
  /*检查ASAN/MSAN的配置
  ASAN和MSAN都是检查内存，能够发现内存中的问题
  ASAN_OPTIONS=symbolize=1  用于显示栈的符号信息
  如果没有设置symbolize或者error 会报错
  */
  check_asan_opts();

  /* 当选择-S参数时验证并修复输出目录和sync目录
     sync是同步 -S选择时是选择主节点 所以存在一个主从同步的问题
     先查看是不是 -S/-M 和 -n同时存在 不能同时存在 因为会互斥
     再检查一下sync id（就是测试id）的格式
     alloc_printf（）就是打印路径 分配地址
     这里x=alloc_printf 根据fuzzid分配一个路径/地址给out_dir
     在输出目录下在新建了一个根据id来的目录
  */
  if (sync_id) fix_up_sync();
   
  //如果输入输出目录一样 则提示输入输出文件夹不同
  if (!strcmp(in_dir, out_dir))
    FATAL("Input and output directories can't be the same");

  //参数冲突
  if (dumb_mode) {
    if (crash_mode) FATAL("-C and -n are mutually exclusive");
    if (qemu_mode)  FATAL("-Q and -n are mutually exclusive");

  }
  
  //根据环境变量设定变量
  //设置AFL_NO_FORKSRV将禁用forkserver优化，用于处理不灵活的库
  if (getenv("AFL_NO_FORKSRV"))    no_forkserver    = 1;
  //显示UI底部的CPU小部件，在内核数较少的系统上不会过早的报高负载
  if (getenv("AFL_NO_CPU_RED"))    no_cpu_meter_red = 1;
  //跳过大多数确定性算法，加快基于文本格式的模糊测试
  if (getenv("AFL_NO_ARITH"))      no_arith         = 1;
  //在启动时随机重新排序输入队列
  if (getenv("AFL_SHUFFLE_QUEUE")) shuffle_queue    = 1;
  //加快校验2.5倍速度，降低精度，当启动会话慢时有用
  if (getenv("AFL_FAST_CAL"))      fast_cal         = 1;
  //指定超时时间，来确定测试用例是否挂起
  if (getenv("AFL_HANG_TMOUT")) {
    hang_tmout = atoi(getenv("AFL_HANG_TMOUT"));
    if (!hang_tmout) FATAL("Invalid value of AFL_HANG_TMOUT");
  }
  
  //参数冲突
  if (dumb_mode == 2 && no_forkserver)
    FATAL("AFL_DUMB_FORKSRV and AFL_NO_FORKSRV are mutually exclusive");

 //设置preload会让afl给二进制文件设置LD-preload 不会中断测试
 //对于引导libdislocator.so非常有用
 //LD_PRELOAD影响程序运行时的链接，允许定义在程序运行前优先加载动态链接库
  if (getenv("AFL_PRELOAD")) {
    setenv("LD_PRELOAD", getenv("AFL_PRELOAD"), 1);
    setenv("DYLD_INSERT_LIBRARIES", getenv("AFL_PRELOAD"), 1);
  }
  if (getenv("AFL_LD_PRELOAD"))
    FATAL("Use AFL_PRELOAD instead of AFL_LD_PRELOAD");

  //存档你当前输入的命令行
  save_cmdline(argc, argv);
  
  //修改输出到屏幕的内容
  fix_up_banner(argv[optind]);
  
  /*检查我们使用终端，如果我们设置AFL_NO_UI会禁止使用界面输出，只定期输出一些基本统计信息，ioctl函数返回终端窗口大小,如果出错，ioctl函数返回一个负数，它作为errno值反馈
  */
  check_if_tty();
  //获得逻辑CPU内核的数量
  get_core_count();

#ifdef HAVE_AFFINITY
  bind_to_free_cpu();
#endif /* HAVE_AFFINITY */
  
  //根据不同的内核（MACOSX比较糟糕）确保程序不会出现内核转储
  check_crash_handling();
  
  //检查CPU调速器
  check_cpu_governor();   
  
  //为变异文件配置后处理器，可以用于处理校验和
  setup_post();
  
  //配置共享内存和原始位
  /*
   AFL使用共享内存完成执行过程中的分支信息在fuzzer和target之间传递
   分配成功后，共享内存的标志会被设置到环境变量中，之后fork的子进程都可以通过这个环境变量获得共享内存的标志符，fuzzer也通过trace_bits保存共享内存的地址，在每次target执行之前都会清零共享内容（见run_target（））
  */
  setup_shm();
  //简单归类，处理一些因为循环次数的微小区别而误判为不同执行结果的情况
  init_count_class16(); 
  //创建文件夹
  setup_dirs_fds();
  //从输入目录中读取所有测试用例，然后将他们排队进行测试
  //scandir函数扫描dir目录下满足nl条件的文件，返回的结果经过排序，失败返回-1
  //这里使用scandir函数控制测试用例的顺序
  //检查输入目录中有没有有效的测试用例，测试其需要一个或多个用例开始
  read_testcases();
  //加载自动生成的额外项
  load_auto();
  //使用函数markasdetdone为已经经过确定性变异的测试用例放到一个文件夹中
  pivot_inputs();
  //如果存在额外文件目录 则读取并按照文件大小排序
  if (extras_dir) load_extras(extras_dir);
  //在没有给定-t的情况下，不能一直自动调整超时值，防止它由于意外增长
  if (!timeout_given) find_timeout();
  /*检测参数中的@@
   如果没有选择文件名，用一个安全的默认值
   确定始终使用完全限定的路径
   构造替换argv值
  */
  detect_file_args(argv + optind + 1);
  //如果没有设定-f参数 创建输出文件保存测试数据
  if (!out_file) setup_stdio_file();
  //根据路径搜索找到目标二进制文件，查看是否存在
  //检查有效的ELF头和是否被插桩
  check_binary(argv[optind]);
  //设定开始时间
  start_time = get_cur_time();
  //qemu_mode
  if (qemu_mode)
    use_argv = get_qemu_argv(argv[0], argv + optind, argc - optind);
  else
    use_argv = argv + optind;
    
  /*执行所有测试用例的试运行，确认程序的工作方式，只针对初始输入，只执行一次
    其中调用的calibrate_case()函数 在fuzz_one()中也有调用
    作用：执行input下预先准备的所有testcase，生成初始化的queue和bitmap
     调用calibrate_case进行校准，再根据返回值判断是否有错误和错误类型
  */
  perform_dry_run(use_argv);
```

```c
 //根据top_rated设置队列中的favored标志
  cull_queue();
  /*遍历top_rated[]条目，然后依次获取先前未见过的字节（temp_v）的获胜者，并将其标记为受青睐，至少直到下一次运行为止，在所有模糊测试步骤中，首选条目将获得更多广播时间。*/

  show_init_stats();
    /*在处理输入目录的末尾显示快速统计信息，以及一堆警告。一些校准的东西，以及几个硬编码的常数。*/
  seek_to = find_start_position();
    /*恢复时，请尝试查找要从其开始的队列位置。 这仅在恢复时以及当我们可以找到原始的fuzzer_stats时才有意义。*/
  
  //更新统计文件，保存一些参数
  write_stats_file(0, 0, 0);
  //保存自动生成的附加文件
  save_auto();
  
  //接受到ctrl+C指令 直接停止
  if (stop_soon) goto stop_fuzzing;

  /* Woop woop woop */
   //不在终端里运行的情况
  if (!not_on_tty) {
    sleep(4);
    start_time += 4000;
    if (stop_soon) goto stop_fuzzing;
  }
```

---
###  涉及到的关键函数
 #### calibrate_case():
 ---
```c
 static u8 calibrate_case(char** argv, struct queue_entry* q, u8* use_mem,u32 handicap, u8 from_queue) {
 static u8 first_trace[MAP_SIZE];
  u8  fault = 0, new_bits = 0, var_detected = 0,
  first_run = (q->exec_cksum == 0);

  u64 start_us, stop_us;
  //设置阶段参数设置,超时时间
  s32 old_sc = stage_cur, old_sm = stage_max;
  u32 use_tmout = exec_tmout;
  u8* old_sn = stage_name;
 //如果不是队列中的或者是恢复的测试，设置较长的timeout
  if (!from_queue || resuming_fuzz)
    use_tmout = MAX(exec_tmout + CAL_TMOUT_ADD,
                    exec_tmout * CAL_TMOUT_PERC / 100);

  q->cal_failed++;

  stage_name = "calibration";
  //环境变量有一个AFL_FAST_CAL设置是否calibrate快速，如果快速设置3，否则设置8
  //config.h CAL_CYCLES全局变量为8 每个新测试用例的校准周期数
  stage_max  = fast_cal ? 3 : CAL_CYCLES;

 //确保启动forkserver
  if (dumb_mode != 1 && !no_forkserver && !forksrv_pid)
    /*
    fork就是linux复制一个子进程的，fork()的返回值如果是0则是创建了子进程，负数则为创建进程时出错，正数则为父进程中新创建子进程的进程ID
    */
    init_forkserver(argv);
  
  if (q->exec_cksum) memcpy(first_trace, trace_bits, MAP_SIZE);

  start_us = get_cur_time_us();
 //开始循环 以周期数为最大值
  for (stage_cur = 0; stage_cur < stage_max; stage_cur++) {

    u32 cksum;
    //first_run是检验是不是第一次运行 第一次运行校验和为0
    //且当前循环数和统计更新频率取余不为0则调用展示一个统计页面
    if (!first_run && !(stage_cur % stats_update_freq)) show_stats();
    //将修改后的数据写入文件进行测试
    write_to_testcase(use_mem, q->len);
    //可以让forkserver运行并进行fuzz
    fault = run_target(argv, use_tmout);
     
    /* stop_soon is set by the handler for Ctrl+C. When it's pressed,
       we want to bail out quickly. */
    if (stop_soon || fault != crash_mode) goto abort_calibration;
    if (!dumb_mode && !stage_cur && !count_bytes(trace_bits)) {
      fault = FAULT_NOINST; //报错
      goto abort_calibration;
    }
    //以trace_bits为key，map_size为长度，HASH_CONST为种子生成哈希值
    //trace_bits前文讲过是共享内存 如果该变量出现了变化，则cksum就会发生变化
    cksum = hash32(trace_bits, MAP_SIZE, HASH_CONST);
    //如果检验和不相等（产生了新分支执行路径？）
    if (q->exec_cksum != cksum) {
      //检查当前执行路径是否为表格带来新内容
      u8 hnb = has_new_bits(virgin_bits);
      
      if (hnb > new_bits) new_bits = hnb;
    
      if (q->exec_cksum) {
    
        u32 i;
    
        for (i = 0; i < MAP_SIZE; i++) {
    
          if (!var_bytes[i] && first_trace[i] != trace_bits[i]) {
            //增加最大校准次数为40
            var_bytes[i] = 1;
            stage_max    = CAL_CYCLES_LONG;
          }
        }
        var_detected = 1;
      }
      //如果校准和为0则将新的校准和赋给他
      else {
        q->exec_cksum = cksum;
        memcpy(first_trace, trace_bits, MAP_SIZE);
      }
    }
  }

  stop_us = get_cur_time_us();
 //统计用时和循环次数
  total_cal_us     += stop_us - start_us;
  total_cal_cycles += stage_max;

 //更新信息
  q->exec_us     = (stop_us - start_us) / stage_max;
  q->bitmap_size = count_bytes(trace_bits);
  q->handicap    = handicap;
  q->cal_failed  = 0;

  total_bitmap_size += q->bitmap_size;
  total_bitmap_entries++;

  update_bitmap_score(q);

 //如果这个用例没有导致从插桩中获得新输出，提醒用户注意
  if (!dumb_mode && first_run && !fault && !new_bits) fault = FAULT_NOBITS;

abort_calibration:

  if (new_bits == 2 && !q->has_new_cov) {
    q->has_new_cov = 1;
    queued_with_cov++;
  }

  /* 标记变量路径 */
  //在符合q的检验和不为空时设置var_detected=1,标记具有可变行为的测试用例
  if (var_detected) {
    var_byte_count = count_bytes(var_bytes);
    if (!q->var_behavior) {
      mark_as_variable(q);
      queued_variable++;
    }
  }
  stage_name = old_sn;
  stage_cur  = old_sc;
  stage_max  = old_sm;
  if (!first_run) show_stats();
  return fault;
}

```

#### while(1)

```c
//每fuzz一个队列，就会重新进入while循环，再用cull_queue精简队列 
while (1) {

    u8 skipped_fuzz;
    //精简队列
    cull_queue();
    
    if (!queue_cur) {

      queue_cycle++;
      current_entry     = 0;
      cur_skipped_paths = 0;
      queue_cur         = queue;

      while (seek_to) {
        current_entry++;
        seek_to--;
        queue_cur = queue_cur->next;
      }

      show_stats();

      if (not_on_tty) {
        ACTF("Entering queue cycle %llu.", queue_cycle);
        fflush(stdout);
      }

      /* If we had a full queue cycle with no new finds, try
         recombination strategies next. */

      if (queued_paths == prev_queued) {

        if (use_splicing) cycles_wo_finds++; else use_splicing = 1;

      } else cycles_wo_finds = 0;

      prev_queued = queued_paths;

      if (sync_id && queue_cycle == 1 && getenv("AFL_IMPORT_FIRST"))
        sync_fuzzers(use_argv);

    }

    skipped_fuzz = fuzz_one(use_argv);

    if (!stop_soon && sync_id && !skipped_fuzz) {
      
      if (!(sync_interval_cnt++ % SYNC_INTERVAL))
        sync_fuzzers(use_argv);

    }

    if (!stop_soon && exit_1) stop_soon = 2;

    if (stop_soon) break;

    queue_cur = queue_cur->next;
    current_entry++;

  }

  if (queue_cur) show_stats();

  write_bitmap();
  write_stats_file(0, 0, 0);
  save_auto();

stop_fuzzing:

  SAYF(CURSOR_SHOW cLRD "\n\n+++ Testing aborted %s +++\n" cRST,
       stop_soon == 2 ? "programmatically" : "by user");

  /* Running for more than 30 minutes but still doing first cycle? */

  if (queue_cycle == 1 && get_cur_time() - start_time > 30 * 60 * 1000) {

    SAYF("\n" cYEL "[!] " cRST
           "Stopped during the first cycle, results may be incomplete.\n"
           "    (For info on resuming, see %s/README.)\n", doc_path);

  }

  fclose(plot_file);
  destroy_queue();
  destroy_extras();
  ck_free(target_path);
  ck_free(sync_id);

  alloc_report();

  OKF("We're done here. Have a nice day!\n");

  exit(0);

}
```


#### run_target()
---

```c
 /* Execute target application, monitoring for timeouts. Return status
   information. The called program will update trace_bits[]. */

static u8 run_target(char** argv, u32 timeout) {
  //初始化变量
  static struct itimerval it;
  static u32 prev_timed_out = 0;
  int status = 0;
  u32 tb4;
  child_timed_out = 0;

 //初始化trace_bits
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
     status是一个整形指针，是该进程退出时的状态，若status不为空，则通过它可以获得子进程的结束状态，child_pid>0只等待进程id等于pid的子进程，只要指定子进程没结束，就会一直等待；child_pid=-1 等待任何一个子进程退出;child_pid=0等待该组id等于调用进程的组id的任一子进程;child_pid<-1 等待该组id等于pid的绝对值的任一子程序
     waitpid返回0 -1是异常
  */
    if (waitpid(child_pid, &status, 0) <= 0) PFATAL("waitpid() failed");
  } else {
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
    kill_signal = WTERMSIG(status);
    if (child_timed_out && kill_signal == SIGKILL) return FAULT_TMOUT;
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

#### fuzz_one()
---

```c
 static u8 fuzz_one(char** argv) {
  //定义临时变量等
  s32 len, fd, temp_len, i, j;
  u8  *in_buf, *out_buf, *orig_in, *ex_tmp, *eff_map = 0;
  u64 havoc_queued,  orig_hit_cnt, new_hit_cnt;
  u32 splice_cycle = 0, perf_score = 100, orig_perf, prev_cksum, eff_cnt = 1;
  u8  ret_val = 1, doing_det = 0;
  u8  a_collect[MAX_AUTO_EXTRA];
  u32 a_len = 0;

#ifdef IGNORE_FINDS

  /* In IGNORE_FINDS mode, skip any entries that weren't in the
     initial data set. */
   //如果ignore_finds模式开启 直接跳出分析
  if (queue_cur->depth > 1) return 1;

#else

  if (pending_favored) {

    /* If we have any favored, non-fuzzed new arrivals in the queue,
 possibly skip to them at the expense of already-fuzzed or non-favored
 cases. */
    //如果已经被fuzz或者favored为0 则有很大的概率跳过分析
    if ((queue_cur->was_fuzzed || !queue_cur->favored) &&
        UR(100) < SKIP_TO_NEW_PROB) return 1;

  } else if (!dumb_mode && !queue_cur->favored && queued_paths > 10) {

    /* Otherwise, still possibly skip non-favored cases, albeit less often. The odds of skipping stuff are higher for already-fuzzed inputs and lower for never-fuzzed entries. */

    if (queue_cycle > 1 && !queue_cur->was_fuzzed) {

      if (UR(100) < SKIP_NFAV_NEW_PROB) return 1;

    } else {

      if (UR(100) < SKIP_NFAV_OLD_PROB) return 1;

    }

  }

#endif /* ^IGNORE_FINDS */
  //无窗口模式的提示行
  if (not_on_tty) {
    ACTF("Fuzzing test case #%u (%u total, %llu uniq crashes found)...",
         current_entry, queued_paths, unique_crashes);
    fflush(stdout);
  }

  /* Map the test case into memory. */
  //将测试用例映射到内存中
  fd = open(queue_cur->fname, O_RDONLY);
  if (fd < 0) PFATAL("Unable to open '%s'", queue_cur->fname);
  len = queue_cur->len;
  orig_in = in_buf = mmap(0, len, PROT_READ | PROT_WRITE, MAP_PRIVATE, fd, 0);
  if (orig_in == MAP_FAILED) PFATAL("Unable to mmap '%s'", queue_cur->fname);
  close(fd);

  /* We could mmap() out_buf as MAP_PRIVATE, but we end up clobbering every  single byte anyway, so it wouldn't give us any performance or memory usage  benefits. */

  out_buf = ck_alloc_nozero(len);
  subseq_tmouts = 0;
  cur_depth = queue_cur->depth;

  /*******************************************
   * CALIBRATION (only if failed earlier on) *
   *******************************************/

  if (queue_cur->cal_failed) {

    u8 res = FAULT_TMOUT;

    if (queue_cur->cal_failed < CAL_CHANCES) {
      //校验测试用例
      res = calibrate_case(argv, queue_cur, in_buf, queue_cycle - 1, 0);

      if (res == FAULT_ERROR)
        FATAL("Unable to execute target application");

    }

    if (stop_soon || res != crash_mode) {
      cur_skipped_paths++;
      goto abandon_entry;
    }

  }

  /************
   * TRIMMING *
   ************/
  //输入文件修剪
  if (!dumb_mode && !queue_cur->trim_done) {

    u8 res = trim_case(argv, queue_cur, in_buf);

    if (res == FAULT_ERROR)
      FATAL("Unable to execute target application");

    if (stop_soon) {
      cur_skipped_paths++;
      goto abandon_entry;
    }

    /* Don't retry trimming, even if it failed. */
    //不要重复修剪，即使失败了
    queue_cur->trim_done = 1;
 
    if (len != queue_cur->len) len = queue_cur->len;

  }

  memcpy(out_buf, in_buf, len);

  /*********************
   * PERFORMANCE SCORE *
   *********************/
  /*评估分数
  根据路径的执行速度，位图大小，路径深度等因素给testcase进行打分，来调整在havoc阶段的用时
  执行速度快，位图小，代码覆盖高，新发现的，路径深的testcase获得更多havoc变异机会
  */ 
  orig_perf = perf_score = calculate_score(queue_cur);

  /* Skip right away if -d is given, if we have done deterministic fuzzing on this entry ourselves (was_fuzzed), or if it has gone through deterministic testing in earlier, resumed runs (passed_det). */
 //如果跳过确定性阶段，当前用例已经被测试过，则直接进入破坏阶段
  if (skip_deterministic || queue_cur->was_fuzzed || queue_cur->passed_det)
    goto havoc_stage;

  /* Skip deterministic fuzzing if exec path checksum puts this out of scope
     for this master instance. */
 
  if (master_max && (queue_cur->exec_cksum % master_max) != master_id - 1)
    goto havoc_stage;

  doing_det = 1;

  /*********************************************
   * SIMPLE BITFLIP (+dictionary construction) *
   *********************************************/

#define FLIP_BIT(_ar, _b) do { \
    u8* _arf = (u8*)(_ar); \
    u32 _bf = (_b); \
    _arf[(_bf) >> 3] ^= (128 >> ((_bf) & 7)); \
  } while (0)

  /* Single walking bit. */

  stage_short = "flip1";
  stage_max   = len << 3;
  stage_name  = "bitflip 1/1";

  stage_val_type = STAGE_VAL_NONE;

  orig_hit_cnt = queued_paths + unique_crashes;

  prev_cksum = queue_cur->exec_cksum;

  for (stage_cur = 0; stage_cur < stage_max; stage_cur++) {

    stage_cur_byte = stage_cur >> 3;

    FLIP_BIT(out_buf, stage_cur);

    if (common_fuzz_stuff(argv, out_buf, len)) goto abandon_entry;

    FLIP_BIT(out_buf, stage_cur);

    /* While flipping the least significant bit in every byte, pull of an extra
       trick to detect possible syntax tokens. In essence, the idea is that if
       you have a binary blob like this:

       xxxxxxxxIHDRxxxxxxxx

       ...and changing the leading and trailing bytes causes variable or no
       changes in program flow, but touching any character in the "IHDR" string
       always produces the same, distinctive path, it's highly likely that
       "IHDR" is an atomically-checked magic value of special significance to
       the fuzzed format.

       We do this here, rather than as a separate stage, because it's a nice
       way to keep the operation approximately "free" (i.e., no extra execs).
       
       Empirically, performing the check when flipping the least significant bit
       is advantageous, compared to doing it at the time of more disruptive
       changes, where the program flow may be affected in more violent ways.

       The caveat is that we won't generate dictionaries in the -d mode or -S
       mode - but that's probably a fair trade-off.

       This won't work particularly well with paths that exhibit variable
       behavior, but fails gracefully, so we'll carry out the checks anyway.

      */

    if (!dumb_mode && (stage_cur & 7) == 7) {

      u32 cksum = hash32(trace_bits, MAP_SIZE, HASH_CONST);

      if (stage_cur == stage_max - 1 && cksum == prev_cksum) {

        /* If at end of file and we are still collecting a string, grab the
           final character and force output. */

        if (a_len < MAX_AUTO_EXTRA) a_collect[a_len] = out_buf[stage_cur >> 3];
        a_len++;

        if (a_len >= MIN_AUTO_EXTRA && a_len <= MAX_AUTO_EXTRA)
          maybe_add_auto(a_collect, a_len);

      } else if (cksum != prev_cksum) {

        /* Otherwise, if the checksum has changed, see if we have something
           worthwhile queued up, and collect that if the answer is yes. */

        if (a_len >= MIN_AUTO_EXTRA && a_len <= MAX_AUTO_EXTRA)
          maybe_add_auto(a_collect, a_len);

        a_len = 0;
        prev_cksum = cksum;

      }

      /* Continue collecting string, but only if the bit flip actually made
         any difference - we don't want no-op tokens. */

      if (cksum != queue_cur->exec_cksum) {

        if (a_len < MAX_AUTO_EXTRA) a_collect[a_len] = out_buf[stage_cur >> 3];        
        a_len++;

      }

    }

  }

  new_hit_cnt = queued_paths + unique_crashes;

  stage_finds[STAGE_FLIP1]  += new_hit_cnt - orig_hit_cnt;
  stage_cycles[STAGE_FLIP1] += stage_max;

  /* Two walking bits. */

  stage_name  = "bitflip 2/1";
  stage_short = "flip2";
  stage_max   = (len << 3) - 1;

  orig_hit_cnt = new_hit_cnt;

  for (stage_cur = 0; stage_cur < stage_max; stage_cur++) {

    stage_cur_byte = stage_cur >> 3;

    FLIP_BIT(out_buf, stage_cur);
    FLIP_BIT(out_buf, stage_cur + 1);

    if (common_fuzz_stuff(argv, out_buf, len)) goto abandon_entry;

    FLIP_BIT(out_buf, stage_cur);
    FLIP_BIT(out_buf, stage_cur + 1);

  }

  new_hit_cnt = queued_paths + unique_crashes;

  stage_finds[STAGE_FLIP2]  += new_hit_cnt - orig_hit_cnt;
  stage_cycles[STAGE_FLIP2] += stage_max;

  /* Four walking bits. */

  stage_name  = "bitflip 4/1";
  stage_short = "flip4";
  stage_max   = (len << 3) - 3;

  orig_hit_cnt = new_hit_cnt;

  for (stage_cur = 0; stage_cur < stage_max; stage_cur++) {

    stage_cur_byte = stage_cur >> 3;

    FLIP_BIT(out_buf, stage_cur);
    FLIP_BIT(out_buf, stage_cur + 1);
    FLIP_BIT(out_buf, stage_cur + 2);
    FLIP_BIT(out_buf, stage_cur + 3);

    if (common_fuzz_stuff(argv, out_buf, len)) goto abandon_entry;

    FLIP_BIT(out_buf, stage_cur);
    FLIP_BIT(out_buf, stage_cur + 1);
    FLIP_BIT(out_buf, stage_cur + 2);
    FLIP_BIT(out_buf, stage_cur + 3);

  }

  new_hit_cnt = queued_paths + unique_crashes;

  stage_finds[STAGE_FLIP4]  += new_hit_cnt - orig_hit_cnt;
  stage_cycles[STAGE_FLIP4] += stage_max;

  /* Effector map setup. These macros calculate:

     EFF_APOS      - position of a particular file offset in the map.
     EFF_ALEN      - length of a map with a particular number of bytes.
     EFF_SPAN_ALEN - map span for a sequence of bytes.

   */

#define EFF_APOS(_p)          ((_p) >> EFF_MAP_SCALE2)
#define EFF_REM(_x)           ((_x) & ((1 << EFF_MAP_SCALE2) - 1))
#define EFF_ALEN(_l)          (EFF_APOS(_l) + !!EFF_REM(_l))
#define EFF_SPAN_ALEN(_p, _l) (EFF_APOS((_p) + (_l) - 1) - EFF_APOS(_p) + 1)

  /* Initialize effector map for the next step (see comments below). Always
     flag first and last byte as doing something. */

  eff_map    = ck_alloc(EFF_ALEN(len));
  eff_map[0] = 1;

  if (EFF_APOS(len - 1) != 0) {
    eff_map[EFF_APOS(len - 1)] = 1;
    eff_cnt++;
  }

  /* Walking byte. */

  stage_name  = "bitflip 8/8";
  stage_short = "flip8";
  stage_max   = len;

  orig_hit_cnt = new_hit_cnt;

  for (stage_cur = 0; stage_cur < stage_max; stage_cur++) {

    stage_cur_byte = stage_cur;

    out_buf[stage_cur] ^= 0xFF;

    if (common_fuzz_stuff(argv, out_buf, len)) goto abandon_entry;

    /* We also use this stage to pull off a simple trick: we identify
       bytes that seem to have no effect on the current execution path
       even when fully flipped - and we skip them during more expensive
       deterministic stages, such as arithmetics or known ints. */

    if (!eff_map[EFF_APOS(stage_cur)]) {

      u32 cksum;

      /* If in dumb mode or if the file is very short, just flag everything
         without wasting time on checksums. */

      if (!dumb_mode && len >= EFF_MIN_LEN)
        cksum = hash32(trace_bits, MAP_SIZE, HASH_CONST);
      else
        cksum = ~queue_cur->exec_cksum;

      if (cksum != queue_cur->exec_cksum) {
        eff_map[EFF_APOS(stage_cur)] = 1;
        eff_cnt++;
      }

    }

    out_buf[stage_cur] ^= 0xFF;

  }

  /* If the effector map is more than EFF_MAX_PERC dense, just flag the
     whole thing as worth fuzzing, since we wouldn't be saving much time
     anyway. */

  if (eff_cnt != EFF_ALEN(len) &&
      eff_cnt * 100 / EFF_ALEN(len) > EFF_MAX_PERC) {

    memset(eff_map, 1, EFF_ALEN(len));

    blocks_eff_select += EFF_ALEN(len);

  } else {

    blocks_eff_select += eff_cnt;

  }

  blocks_eff_total += EFF_ALEN(len);

  new_hit_cnt = queued_paths + unique_crashes;

  stage_finds[STAGE_FLIP8]  += new_hit_cnt - orig_hit_cnt;
  stage_cycles[STAGE_FLIP8] += stage_max;

  /* Two walking bytes. */

  if (len < 2) goto skip_bitflip;

  stage_name  = "bitflip 16/8";
  stage_short = "flip16";
  stage_cur   = 0;
  stage_max   = len - 1;

  orig_hit_cnt = new_hit_cnt;

  for (i = 0; i < len - 1; i++) {

    /* Let's consult the effector map... */

    if (!eff_map[EFF_APOS(i)] && !eff_map[EFF_APOS(i + 1)]) {
      stage_max--;
      continue;
    }

    stage_cur_byte = i;

    *(u16*)(out_buf + i) ^= 0xFFFF;

    if (common_fuzz_stuff(argv, out_buf, len)) goto abandon_entry;
    stage_cur++;

    *(u16*)(out_buf + i) ^= 0xFFFF;


  }

  new_hit_cnt = queued_paths + unique_crashes;

  stage_finds[STAGE_FLIP16]  += new_hit_cnt - orig_hit_cnt;
  stage_cycles[STAGE_FLIP16] += stage_max;

  if (len < 4) goto skip_bitflip;

  /* Four walking bytes. */

  stage_name  = "bitflip 32/8";
  stage_short = "flip32";
  stage_cur   = 0;
  stage_max   = len - 3;

  orig_hit_cnt = new_hit_cnt;

  for (i = 0; i < len - 3; i++) {

    /* Let's consult the effector map... */
    if (!eff_map[EFF_APOS(i)] && !eff_map[EFF_APOS(i + 1)] &&
        !eff_map[EFF_APOS(i + 2)] && !eff_map[EFF_APOS(i + 3)]) {
      stage_max--;
      continue;
    }

    stage_cur_byte = i;

    *(u32*)(out_buf + i) ^= 0xFFFFFFFF;

    if (common_fuzz_stuff(argv, out_buf, len)) goto abandon_entry;
    stage_cur++;

    *(u32*)(out_buf + i) ^= 0xFFFFFFFF;

  }

  new_hit_cnt = queued_paths + unique_crashes;

  stage_finds[STAGE_FLIP32]  += new_hit_cnt - orig_hit_cnt;
  stage_cycles[STAGE_FLIP32] += stage_max;

skip_bitflip:

  if (no_arith) goto skip_arith;

  /**********************
   * ARITHMETIC INC/DEC *
   **********************/

  /* 8-bit arithmetics. */

  stage_name  = "arith 8/8";
  stage_short = "arith8";
  stage_cur   = 0;
  stage_max   = 2 * len * ARITH_MAX;

  stage_val_type = STAGE_VAL_LE;

  orig_hit_cnt = new_hit_cnt;

  for (i = 0; i < len; i++) {

    u8 orig = out_buf[i];

    /* Let's consult the effector map... */

    if (!eff_map[EFF_APOS(i)]) {
      stage_max -= 2 * ARITH_MAX;
      continue;
    }

    stage_cur_byte = i;

    for (j = 1; j <= ARITH_MAX; j++) {

      u8 r = orig ^ (orig + j);

      /* Do arithmetic operations only if the result couldn't be a product
         of a bitflip. */

      if (!could_be_bitflip(r)) {

        stage_cur_val = j;
        out_buf[i] = orig + j;

        if (common_fuzz_stuff(argv, out_buf, len)) goto abandon_entry;
        stage_cur++;

      } else stage_max--;

      r =  orig ^ (orig - j);

      if (!could_be_bitflip(r)) {

        stage_cur_val = -j;
        out_buf[i] = orig - j;

        if (common_fuzz_stuff(argv, out_buf, len)) goto abandon_entry;
        stage_cur++;

      } else stage_max--;

      out_buf[i] = orig;

    }

  }

  new_hit_cnt = queued_paths + unique_crashes;

  stage_finds[STAGE_ARITH8]  += new_hit_cnt - orig_hit_cnt;
  stage_cycles[STAGE_ARITH8] += stage_max;

  /* 16-bit arithmetics, both endians. */

  if (len < 2) goto skip_arith;

  stage_name  = "arith 16/8";
  stage_short = "arith16";
  stage_cur   = 0;
  stage_max   = 4 * (len - 1) * ARITH_MAX;

  orig_hit_cnt = new_hit_cnt;

  for (i = 0; i < len - 1; i++) {

    u16 orig = *(u16*)(out_buf + i);

    /* Let's consult the effector map... */

    if (!eff_map[EFF_APOS(i)] && !eff_map[EFF_APOS(i + 1)]) {
      stage_max -= 4 * ARITH_MAX;
      continue;
    }

    stage_cur_byte = i;

    for (j = 1; j <= ARITH_MAX; j++) {

      u16 r1 = orig ^ (orig + j),
          r2 = orig ^ (orig - j),
          r3 = orig ^ SWAP16(SWAP16(orig) + j),
          r4 = orig ^ SWAP16(SWAP16(orig) - j);

      /* Try little endian addition and subtraction first. Do it only
         if the operation would affect more than one byte (hence the 
         & 0xff overflow checks) and if it couldn't be a product of
         a bitflip. */

      stage_val_type = STAGE_VAL_LE; 

      if ((orig & 0xff) + j > 0xff && !could_be_bitflip(r1)) {

        stage_cur_val = j;
        *(u16*)(out_buf + i) = orig + j;

        if (common_fuzz_stuff(argv, out_buf, len)) goto abandon_entry;
        stage_cur++;
 
      } else stage_max--;

      if ((orig & 0xff) < j && !could_be_bitflip(r2)) {

        stage_cur_val = -j;
        *(u16*)(out_buf + i) = orig - j;

        if (common_fuzz_stuff(argv, out_buf, len)) goto abandon_entry;
        stage_cur++;

      } else stage_max--;

      /* Big endian comes next. Same deal. */

      stage_val_type = STAGE_VAL_BE;


      if ((orig >> 8) + j > 0xff && !could_be_bitflip(r3)) {

        stage_cur_val = j;
        *(u16*)(out_buf + i) = SWAP16(SWAP16(orig) + j);

        if (common_fuzz_stuff(argv, out_buf, len)) goto abandon_entry;
        stage_cur++;

      } else stage_max--;

      if ((orig >> 8) < j && !could_be_bitflip(r4)) {

        stage_cur_val = -j;
        *(u16*)(out_buf + i) = SWAP16(SWAP16(orig) - j);

        if (common_fuzz_stuff(argv, out_buf, len)) goto abandon_entry;
        stage_cur++;

      } else stage_max--;

      *(u16*)(out_buf + i) = orig;

    }

  }

  new_hit_cnt = queued_paths + unique_crashes;

  stage_finds[STAGE_ARITH16]  += new_hit_cnt - orig_hit_cnt;
  stage_cycles[STAGE_ARITH16] += stage_max;

  /* 32-bit arithmetics, both endians. */

  if (len < 4) goto skip_arith;

  stage_name  = "arith 32/8";
  stage_short = "arith32";
  stage_cur   = 0;
  stage_max   = 4 * (len - 3) * ARITH_MAX;

  orig_hit_cnt = new_hit_cnt;

  for (i = 0; i < len - 3; i++) {

    u32 orig = *(u32*)(out_buf + i);

    /* Let's consult the effector map... */

    if (!eff_map[EFF_APOS(i)] && !eff_map[EFF_APOS(i + 1)] &&
        !eff_map[EFF_APOS(i + 2)] && !eff_map[EFF_APOS(i + 3)]) {
      stage_max -= 4 * ARITH_MAX;
      continue;
    }

    stage_cur_byte = i;

    for (j = 1; j <= ARITH_MAX; j++) {

      u32 r1 = orig ^ (orig + j),
          r2 = orig ^ (orig - j),
          r3 = orig ^ SWAP32(SWAP32(orig) + j),
          r4 = orig ^ SWAP32(SWAP32(orig) - j);

      /* Little endian first. Same deal as with 16-bit: we only want to
         try if the operation would have effect on more than two bytes. */

      stage_val_type = STAGE_VAL_LE;

      if ((orig & 0xffff) + j > 0xffff && !could_be_bitflip(r1)) {

        stage_cur_val = j;
        *(u32*)(out_buf + i) = orig + j;

        if (common_fuzz_stuff(argv, out_buf, len)) goto abandon_entry;
        stage_cur++;

      } else stage_max--;

      if ((orig & 0xffff) < j && !could_be_bitflip(r2)) {

        stage_cur_val = -j;
        *(u32*)(out_buf + i) = orig - j;

        if (common_fuzz_stuff(argv, out_buf, len)) goto abandon_entry;
        stage_cur++;

      } else stage_max--;

      /* Big endian next. */

      stage_val_type = STAGE_VAL_BE;

      if ((SWAP32(orig) & 0xffff) + j > 0xffff && !could_be_bitflip(r3)) {

        stage_cur_val = j;
        *(u32*)(out_buf + i) = SWAP32(SWAP32(orig) + j);

        if (common_fuzz_stuff(argv, out_buf, len)) goto abandon_entry;
        stage_cur++;

      } else stage_max--;

      if ((SWAP32(orig) & 0xffff) < j && !could_be_bitflip(r4)) {

        stage_cur_val = -j;
        *(u32*)(out_buf + i) = SWAP32(SWAP32(orig) - j);

        if (common_fuzz_stuff(argv, out_buf, len)) goto abandon_entry;
        stage_cur++;

      } else stage_max--;

      *(u32*)(out_buf + i) = orig;

    }

  }

  new_hit_cnt = queued_paths + unique_crashes;

  stage_finds[STAGE_ARITH32]  += new_hit_cnt - orig_hit_cnt;
  stage_cycles[STAGE_ARITH32] += stage_max;

skip_arith:

  /**********************
   * INTERESTING VALUES *
   **********************/

  stage_name  = "interest 8/8";
  stage_short = "int8";
  stage_cur   = 0;
  stage_max   = len * sizeof(interesting_8);

  stage_val_type = STAGE_VAL_LE;

  orig_hit_cnt = new_hit_cnt;

  /* Setting 8-bit integers. */

  for (i = 0; i < len; i++) {

    u8 orig = out_buf[i];

    /* Let's consult the effector map... */

    if (!eff_map[EFF_APOS(i)]) {
      stage_max -= sizeof(interesting_8);
      continue;
    }

    stage_cur_byte = i;

    for (j = 0; j < sizeof(interesting_8); j++) {

      /* Skip if the value could be a product of bitflips or arithmetics. */

      if (could_be_bitflip(orig ^ (u8)interesting_8[j]) ||
          could_be_arith(orig, (u8)interesting_8[j], 1)) {
        stage_max--;
        continue;
      }

      stage_cur_val = interesting_8[j];
      out_buf[i] = interesting_8[j];

      if (common_fuzz_stuff(argv, out_buf, len)) goto abandon_entry;

      out_buf[i] = orig;
      stage_cur++;

    }

  }

  new_hit_cnt = queued_paths + unique_crashes;

  stage_finds[STAGE_INTEREST8]  += new_hit_cnt - orig_hit_cnt;
  stage_cycles[STAGE_INTEREST8] += stage_max;

  /* Setting 16-bit integers, both endians. */

  if (no_arith || len < 2) goto skip_interest;

  stage_name  = "interest 16/8";
  stage_short = "int16";
  stage_cur   = 0;
  stage_max   = 2 * (len - 1) * (sizeof(interesting_16) >> 1);

  orig_hit_cnt = new_hit_cnt;

  for (i = 0; i < len - 1; i++) {

    u16 orig = *(u16*)(out_buf + i);

    /* Let's consult the effector map... */

    if (!eff_map[EFF_APOS(i)] && !eff_map[EFF_APOS(i + 1)]) {
      stage_max -= sizeof(interesting_16);
      continue;
    }

    stage_cur_byte = i;

    for (j = 0; j < sizeof(interesting_16) / 2; j++) {

      stage_cur_val = interesting_16[j];

      /* Skip if this could be a product of a bitflip, arithmetics,
         or single-byte interesting value insertion. */

      if (!could_be_bitflip(orig ^ (u16)interesting_16[j]) &&
          !could_be_arith(orig, (u16)interesting_16[j], 2) &&
          !could_be_interest(orig, (u16)interesting_16[j], 2, 0)) {

        stage_val_type = STAGE_VAL_LE;

        *(u16*)(out_buf + i) = interesting_16[j];

        if (common_fuzz_stuff(argv, out_buf, len)) goto abandon_entry;
        stage_cur++;

      } else stage_max--;

      if ((u16)interesting_16[j] != SWAP16(interesting_16[j]) &&
          !could_be_bitflip(orig ^ SWAP16(interesting_16[j])) &&
          !could_be_arith(orig, SWAP16(interesting_16[j]), 2) &&
          !could_be_interest(orig, SWAP16(interesting_16[j]), 2, 1)) {

        stage_val_type = STAGE_VAL_BE;

        *(u16*)(out_buf + i) = SWAP16(interesting_16[j]);
        if (common_fuzz_stuff(argv, out_buf, len)) goto abandon_entry;
        stage_cur++;

      } else stage_max--;

    }

    *(u16*)(out_buf + i) = orig;

  }

  new_hit_cnt = queued_paths + unique_crashes;

  stage_finds[STAGE_INTEREST16]  += new_hit_cnt - orig_hit_cnt;
  stage_cycles[STAGE_INTEREST16] += stage_max;

  if (len < 4) goto skip_interest;

  /* Setting 32-bit integers, both endians. */

  stage_name  = "interest 32/8";
  stage_short = "int32";
  stage_cur   = 0;
  stage_max   = 2 * (len - 3) * (sizeof(interesting_32) >> 2);

  orig_hit_cnt = new_hit_cnt;

  for (i = 0; i < len - 3; i++) {

    u32 orig = *(u32*)(out_buf + i);

    /* Let's consult the effector map... */

    if (!eff_map[EFF_APOS(i)] && !eff_map[EFF_APOS(i + 1)] &&
        !eff_map[EFF_APOS(i + 2)] && !eff_map[EFF_APOS(i + 3)]) {
      stage_max -= sizeof(interesting_32) >> 1;
      continue;
    }

    stage_cur_byte = i;

    for (j = 0; j < sizeof(interesting_32) / 4; j++) {

      stage_cur_val = interesting_32[j];

      /* Skip if this could be a product of a bitflip, arithmetics,
         or word interesting value insertion. */

      if (!could_be_bitflip(orig ^ (u32)interesting_32[j]) &&
          !could_be_arith(orig, interesting_32[j], 4) &&
          !could_be_interest(orig, interesting_32[j], 4, 0)) {

        stage_val_type = STAGE_VAL_LE;

        *(u32*)(out_buf + i) = interesting_32[j];

        if (common_fuzz_stuff(argv, out_buf, len)) goto abandon_entry;
        stage_cur++;

      } else stage_max--;

      if ((u32)interesting_32[j] != SWAP32(interesting_32[j]) &&
          !could_be_bitflip(orig ^ SWAP32(interesting_32[j])) &&
          !could_be_arith(orig, SWAP32(interesting_32[j]), 4) &&
          !could_be_interest(orig, SWAP32(interesting_32[j]), 4, 1)) {

        stage_val_type = STAGE_VAL_BE;

        *(u32*)(out_buf + i) = SWAP32(interesting_32[j]);
        if (common_fuzz_stuff(argv, out_buf, len)) goto abandon_entry;
        stage_cur++;

      } else stage_max--;

    }

    *(u32*)(out_buf + i) = orig;

  }

  new_hit_cnt = queued_paths + unique_crashes;

  stage_finds[STAGE_INTEREST32]  += new_hit_cnt - orig_hit_cnt;
  stage_cycles[STAGE_INTEREST32] += stage_max;

skip_interest:

  /********************
   * DICTIONARY STUFF *
   ********************/

  if (!extras_cnt) goto skip_user_extras;

  /* Overwrite with user-supplied extras. */

  stage_name  = "user extras (over)";
  stage_short = "ext_UO";
  stage_cur   = 0;
  stage_max   = extras_cnt * len;

  stage_val_type = STAGE_VAL_NONE;

  orig_hit_cnt = new_hit_cnt;

  for (i = 0; i < len; i++) {

    u32 last_len = 0;

    stage_cur_byte = i;

    /* Extras are sorted by size, from smallest to largest. This means
       that we don't have to worry about restoring the buffer in
       between writes at a particular offset determined by the outer
       loop. */

    for (j = 0; j < extras_cnt; j++) {

      /* Skip extras probabilistically if extras_cnt > MAX_DET_EXTRAS. Also
         skip them if there's no room to insert the payload, if the token
         is redundant, or if its entire span has no bytes set in the effector
         map. */

      if ((extras_cnt > MAX_DET_EXTRAS && UR(extras_cnt) >= MAX_DET_EXTRAS) ||
          extras[j].len > len - i ||
          !memcmp(extras[j].data, out_buf + i, extras[j].len) ||
          !memchr(eff_map + EFF_APOS(i), 1, EFF_SPAN_ALEN(i, extras[j].len))) {

        stage_max--;
        continue;

      }

      last_len = extras[j].len;
      memcpy(out_buf + i, extras[j].data, last_len);

      if (common_fuzz_stuff(argv, out_buf, len)) goto abandon_entry;

      stage_cur++;

    }

    /* Restore all the clobbered memory. */
    memcpy(out_buf + i, in_buf + i, last_len);

  }

  new_hit_cnt = queued_paths + unique_crashes;

  stage_finds[STAGE_EXTRAS_UO]  += new_hit_cnt - orig_hit_cnt;
  stage_cycles[STAGE_EXTRAS_UO] += stage_max;

  /* Insertion of user-supplied extras. */

  stage_name  = "user extras (insert)";
  stage_short = "ext_UI";
  stage_cur   = 0;
  stage_max   = extras_cnt * len;

  orig_hit_cnt = new_hit_cnt;

  ex_tmp = ck_alloc(len + MAX_DICT_FILE);

  for (i = 0; i <= len; i++) {

    stage_cur_byte = i;

    for (j = 0; j < extras_cnt; j++) {

      if (len + extras[j].len > MAX_FILE) {
        stage_max--; 
        continue;
      }

      /* Insert token */
      memcpy(ex_tmp + i, extras[j].data, extras[j].len);

      /* Copy tail */
      memcpy(ex_tmp + i + extras[j].len, out_buf + i, len - i);

      if (common_fuzz_stuff(argv, ex_tmp, len + extras[j].len)) {
        ck_free(ex_tmp);
        goto abandon_entry;
      }

      stage_cur++;

    }

    /* Copy head */
    ex_tmp[i] = out_buf[i];

  }

  ck_free(ex_tmp);

  new_hit_cnt = queued_paths + unique_crashes;

  stage_finds[STAGE_EXTRAS_UI]  += new_hit_cnt - orig_hit_cnt;
  stage_cycles[STAGE_EXTRAS_UI] += stage_max;

skip_user_extras:

  if (!a_extras_cnt) goto skip_extras;

  stage_name  = "auto extras (over)";
  stage_short = "ext_AO";
  stage_cur   = 0;
  stage_max   = MIN(a_extras_cnt, USE_AUTO_EXTRAS) * len;

  stage_val_type = STAGE_VAL_NONE;

  orig_hit_cnt = new_hit_cnt;

  for (i = 0; i < len; i++) {

    u32 last_len = 0;

    stage_cur_byte = i;

    for (j = 0; j < MIN(a_extras_cnt, USE_AUTO_EXTRAS); j++) {

      /* See the comment in the earlier code; extras are sorted by size. */

      if (a_extras[j].len > len - i ||
          !memcmp(a_extras[j].data, out_buf + i, a_extras[j].len) ||
          !memchr(eff_map + EFF_APOS(i), 1, EFF_SPAN_ALEN(i, a_extras[j].len))) {

        stage_max--;
        continue;

      }

      last_len = a_extras[j].len;
      memcpy(out_buf + i, a_extras[j].data, last_len);

      if (common_fuzz_stuff(argv, out_buf, len)) goto abandon_entry;

      stage_cur++;

    }

    /* Restore all the clobbered memory. */
    memcpy(out_buf + i, in_buf + i, last_len);

  }

  new_hit_cnt = queued_paths + unique_crashes;

  stage_finds[STAGE_EXTRAS_AO]  += new_hit_cnt - orig_hit_cnt;
  stage_cycles[STAGE_EXTRAS_AO] += stage_max;

skip_extras:

  /* If we made this to here without jumping to havoc_stage or abandon_entry,
     we're properly done with deterministic steps and can mark it as such
     in the .state/ directory. */

  if (!queue_cur->passed_det) mark_as_det_done(queue_cur);

  /****************
   * RANDOM HAVOC *
   ****************/

havoc_stage:

  stage_cur_byte = -1;

  /* The havoc stage mutation code is also invoked when splicing files; if the
     splice_cycle variable is set, generate different descriptions and such. */

  if (!splice_cycle) {

    stage_name  = "havoc";
    stage_short = "havoc";
    stage_max   = (doing_det ? HAVOC_CYCLES_INIT : HAVOC_CYCLES) *
                  perf_score / havoc_div / 100;

  } else {

    static u8 tmp[32];

    perf_score = orig_perf;

    sprintf(tmp, "splice %u", splice_cycle);
    stage_name  = tmp;
    stage_short = "splice";
    stage_max   = SPLICE_HAVOC * perf_score / havoc_div / 100;

  }

  if (stage_max < HAVOC_MIN) stage_max = HAVOC_MIN;

  temp_len = len;

  orig_hit_cnt = queued_paths + unique_crashes;

  havoc_queued = queued_paths;

  /* We essentially just do several thousand runs (depending on perf_score)
     where we take the input file and make random stacked tweaks. */

  for (stage_cur = 0; stage_cur < stage_max; stage_cur++) {

    u32 use_stacking = 1 << (1 + UR(HAVOC_STACK_POW2));

    stage_cur_val = use_stacking;
 
    for (i = 0; i < use_stacking; i++) {

      switch (UR(15 + ((extras_cnt + a_extras_cnt) ? 2 : 0))) {

        case 0:

          /* Flip a single bit somewhere. Spooky! */

          FLIP_BIT(out_buf, UR(temp_len << 3));
          break;

        case 1: 

          /* Set byte to interesting value. */

          out_buf[UR(temp_len)] = interesting_8[UR(sizeof(interesting_8))];
          break;

        case 2:

          /* Set word to interesting value, randomly choosing endian. */

          if (temp_len < 2) break;

          if (UR(2)) {

            *(u16*)(out_buf + UR(temp_len - 1)) =
              interesting_16[UR(sizeof(interesting_16) >> 1)];

          } else {

            *(u16*)(out_buf + UR(temp_len - 1)) = SWAP16(
              interesting_16[UR(sizeof(interesting_16) >> 1)]);

          }

          break;

        case 3:

          /* Set dword to interesting value, randomly choosing endian. */

          if (temp_len < 4) break;

          if (UR(2)) {
  
            *(u32*)(out_buf + UR(temp_len - 3)) =
              interesting_32[UR(sizeof(interesting_32) >> 2)];

          } else {

            *(u32*)(out_buf + UR(temp_len - 3)) = SWAP32(
              interesting_32[UR(sizeof(interesting_32) >> 2)]);

          }

          break;

        case 4:

          /* Randomly subtract from byte. */

          out_buf[UR(temp_len)] -= 1 + UR(ARITH_MAX);
          break;

        case 5:

          /* Randomly add to byte. */

          out_buf[UR(temp_len)] += 1 + UR(ARITH_MAX);
          break;

        case 6:

          /* Randomly subtract from word, random endian. */

          if (temp_len < 2) break;

          if (UR(2)) {

            u32 pos = UR(temp_len - 1);

            *(u16*)(out_buf + pos) -= 1 + UR(ARITH_MAX);

          } else {

            u32 pos = UR(temp_len - 1);
            u16 num = 1 + UR(ARITH_MAX);

            *(u16*)(out_buf + pos) =
              SWAP16(SWAP16(*(u16*)(out_buf + pos)) - num);

          }

          break;

        case 7:

          /* Randomly add to word, random endian. */

          if (temp_len < 2) break;

          if (UR(2)) {

            u32 pos = UR(temp_len - 1);

            *(u16*)(out_buf + pos) += 1 + UR(ARITH_MAX);

          } else {

            u32 pos = UR(temp_len - 1);
            u16 num = 1 + UR(ARITH_MAX);

            *(u16*)(out_buf + pos) =
              SWAP16(SWAP16(*(u16*)(out_buf + pos)) + num);

          }

          break;

        case 8:

          /* Randomly subtract from dword, random endian. */

          if (temp_len < 4) break;

          if (UR(2)) {

            u32 pos = UR(temp_len - 3);

            *(u32*)(out_buf + pos) -= 1 + UR(ARITH_MAX);

          } else {

            u32 pos = UR(temp_len - 3);
            u32 num = 1 + UR(ARITH_MAX);

            *(u32*)(out_buf + pos) =
              SWAP32(SWAP32(*(u32*)(out_buf + pos)) - num);

          }

          break;

        case 9:

          /* Randomly add to dword, random endian. */

          if (temp_len < 4) break;

          if (UR(2)) {

            u32 pos = UR(temp_len - 3);

            *(u32*)(out_buf + pos) += 1 + UR(ARITH_MAX);

          } else {

            u32 pos = UR(temp_len - 3);
            u32 num = 1 + UR(ARITH_MAX);

            *(u32*)(out_buf + pos) =
              SWAP32(SWAP32(*(u32*)(out_buf + pos)) + num);

          }

          break;

        case 10:

          /* Just set a random byte to a random value. Because,
             why not. We use XOR with 1-255 to eliminate the
             possibility of a no-op. */

          out_buf[UR(temp_len)] ^= 1 + UR(255);
          break;

        case 11 ... 12: {

            /* Delete bytes. We're making this a bit more likely
               than insertion (the next option) in hopes of keeping
               files reasonably small. */

            u32 del_from, del_len;

            if (temp_len < 2) break;

            /* Don't delete too much. */

            del_len = choose_block_len(temp_len - 1);

            del_from = UR(temp_len - del_len + 1);

            memmove(out_buf + del_from, out_buf + del_from + del_len,
                    temp_len - del_from - del_len);

            temp_len -= del_len;

            break;

          }

        case 13:

          if (temp_len + HAVOC_BLK_XL < MAX_FILE) {

            /* Clone bytes (75%) or insert a block of constant bytes (25%). */

            u8  actually_clone = UR(4);
            u32 clone_from, clone_to, clone_len;
            u8* new_buf;

            if (actually_clone) {

              clone_len  = choose_block_len(temp_len);
              clone_from = UR(temp_len - clone_len + 1);

            } else {

              clone_len = choose_block_len(HAVOC_BLK_XL);
              clone_from = 0;

            }

            clone_to   = UR(temp_len);

            new_buf = ck_alloc_nozero(temp_len + clone_len);

            /* Head */

            memcpy(new_buf, out_buf, clone_to);

            /* Inserted part */

            if (actually_clone)
              memcpy(new_buf + clone_to, out_buf + clone_from, clone_len);
            else
              memset(new_buf + clone_to,
                     UR(2) ? UR(256) : out_buf[UR(temp_len)], clone_len);

            /* Tail */
            memcpy(new_buf + clone_to + clone_len, out_buf + clone_to,
                   temp_len - clone_to);

            ck_free(out_buf);
            out_buf = new_buf;
            temp_len += clone_len;

          }

          break;

        case 14: {

            /* Overwrite bytes with a randomly selected chunk (75%) or fixed
               bytes (25%). */

            u32 copy_from, copy_to, copy_len;

            if (temp_len < 2) break;

            copy_len  = choose_block_len(temp_len - 1);

            copy_from = UR(temp_len - copy_len + 1);
            copy_to   = UR(temp_len - copy_len + 1);

            if (UR(4)) {

              if (copy_from != copy_to)
                memmove(out_buf + copy_to, out_buf + copy_from, copy_len);

            } else memset(out_buf + copy_to,
                          UR(2) ? UR(256) : out_buf[UR(temp_len)], copy_len);

            break;

          }

        /* Values 15 and 16 can be selected only if there are any extras
           present in the dictionaries. */

        case 15: {

            /* Overwrite bytes with an extra. */

            if (!extras_cnt || (a_extras_cnt && UR(2))) {

              /* No user-specified extras or odds in our favor. Let's use an
                 auto-detected one. */

              u32 use_extra = UR(a_extras_cnt);
              u32 extra_len = a_extras[use_extra].len;
              u32 insert_at;

              if (extra_len > temp_len) break;

              insert_at = UR(temp_len - extra_len + 1);
              memcpy(out_buf + insert_at, a_extras[use_extra].data, extra_len);

            } else {

              /* No auto extras or odds in our favor. Use the dictionary. */

              u32 use_extra = UR(extras_cnt);
              u32 extra_len = extras[use_extra].len;
              u32 insert_at;

              if (extra_len > temp_len) break;

              insert_at = UR(temp_len - extra_len + 1);
              memcpy(out_buf + insert_at, extras[use_extra].data, extra_len);

            }

            break;

          }

        case 16: {

            u32 use_extra, extra_len, insert_at = UR(temp_len + 1);
            u8* new_buf;

            /* Insert an extra. Do the same dice-rolling stuff as for the
               previous case. */

            if (!extras_cnt || (a_extras_cnt && UR(2))) {

              use_extra = UR(a_extras_cnt);
              extra_len = a_extras[use_extra].len;

              if (temp_len + extra_len >= MAX_FILE) break;

              new_buf = ck_alloc_nozero(temp_len + extra_len);

              /* Head */
              memcpy(new_buf, out_buf, insert_at);

              /* Inserted part */
              memcpy(new_buf + insert_at, a_extras[use_extra].data, extra_len);

            } else {

              use_extra = UR(extras_cnt);
              extra_len = extras[use_extra].len;

              if (temp_len + extra_len >= MAX_FILE) break;

              new_buf = ck_alloc_nozero(temp_len + extra_len);

              /* Head */
              memcpy(new_buf, out_buf, insert_at);

              /* Inserted part */
              memcpy(new_buf + insert_at, extras[use_extra].data, extra_len);

            }

            /* Tail */
            memcpy(new_buf + insert_at + extra_len, out_buf + insert_at,
                   temp_len - insert_at);

            ck_free(out_buf);
            out_buf   = new_buf;
            temp_len += extra_len;

            break;

          }

      }

    }

    if (common_fuzz_stuff(argv, out_buf, temp_len))
      goto abandon_entry;

    /* out_buf might have been mangled a bit, so let's restore it to its
       original size and shape. */

    if (temp_len < len) out_buf = ck_realloc(out_buf, len);
    temp_len = len;
    memcpy(out_buf, in_buf, len);

    /* If we're finding new stuff, let's run for a bit longer, limits
       permitting. */

    if (queued_paths != havoc_queued) {

      if (perf_score <= HAVOC_MAX_MULT * 100) {
        stage_max  *= 2;
        perf_score *= 2;
      }

      havoc_queued = queued_paths;

    }

  }

  new_hit_cnt = queued_paths + unique_crashes;

  if (!splice_cycle) {
    stage_finds[STAGE_HAVOC]  += new_hit_cnt - orig_hit_cnt;
    stage_cycles[STAGE_HAVOC] += stage_max;
  } else {
    stage_finds[STAGE_SPLICE]  += new_hit_cnt - orig_hit_cnt;
    stage_cycles[STAGE_SPLICE] += stage_max;
  }

#ifndef IGNORE_FINDS

  /************
   * SPLICING *
   ************/

  /* This is a last-resort strategy triggered by a full round with no findings.
     It takes the current input file, randomly selects another input, and
     splices them together at some offset, then relies on the havoc
     code to mutate that blob. */

retry_splicing:

  if (use_splicing && splice_cycle++ < SPLICE_CYCLES &&
      queued_paths > 1 && queue_cur->len > 1) {

    struct queue_entry* target;
    u32 tid, split_at;
    u8* new_buf;
    s32 f_diff, l_diff;

    /* First of all, if we've modified in_buf for havoc, let's clean that
       up... */

    if (in_buf != orig_in) {
      ck_free(in_buf);
      in_buf = orig_in;
      len = queue_cur->len;
    }

    /* Pick a random queue entry and seek to it. Don't splice with yourself. */

    do { tid = UR(queued_paths); } while (tid == current_entry);

    splicing_with = tid;
    target = queue;

    while (tid >= 100) { target = target->next_100; tid -= 100; }
    while (tid--) target = target->next;

    /* Make sure that the target has a reasonable length. */

    while (target && (target->len < 2 || target == queue_cur)) {
      target = target->next;
      splicing_with++;
    }

    if (!target) goto retry_splicing;

    /* Read the testcase into a new buffer. */

    fd = open(target->fname, O_RDONLY);

    if (fd < 0) PFATAL("Unable to open '%s'", target->fname);

    new_buf = ck_alloc_nozero(target->len);

    ck_read(fd, new_buf, target->len, target->fname);

    close(fd);

    /* Find a suitable splicing location, somewhere between the first and
       the last differing byte. Bail out if the difference is just a single
       byte or so. */

    locate_diffs(in_buf, new_buf, MIN(len, target->len), &f_diff, &l_diff);

    if (f_diff < 0 || l_diff < 2 || f_diff == l_diff) {
      ck_free(new_buf);
      goto retry_splicing;
    }

    /* Split somewhere between the first and last differing byte. */

    split_at = f_diff + UR(l_diff - f_diff);

    /* Do the thing. */

    len = target->len;
    memcpy(new_buf, in_buf, split_at);
    in_buf = new_buf;

    ck_free(out_buf);
    out_buf = ck_alloc_nozero(len);
    memcpy(out_buf, in_buf, len);

    goto havoc_stage;

  }

#endif /* !IGNORE_FINDS */

  ret_val = 0;

abandon_entry:

  splicing_with = -1;

  /* Update pending_not_fuzzed count if we made it through the calibration
     cycle and have not seen this entry before. */

  if (!stop_soon && !queue_cur->cal_failed && !queue_cur->was_fuzzed) {
    queue_cur->was_fuzzed = 1;
    pending_not_fuzzed--;
    if (queue_cur->favored) pending_favored--;
  }

  munmap(orig_in, queue_cur->len);

  if (in_buf != orig_in) ck_free(in_buf);
  ck_free(out_buf);
  ck_free(eff_map);

  return ret_val;

#undef FLIP_BIT

}
```

### 参考的文章

- AFL内部实现细节：http://rk700.github.io/2017/12/28/afl-internals/
- linux中的fork函数：https://www.cnblogs.com/dongguolei/p/8086346.html
- AFL afl_fuzz.c 详细分析：https://bbs.pediy.com/thread-254705.htm