### while（1）之前的源码解析
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
      //输入文件夹
      case 'i': /* input dir */

        if (in_dir) FATAL("Multiple -i options not supported");
        in_dir = optarg;

        if (!strcmp(in_dir, "-")) in_place_resume = 1;

        break;
     //输出文件夹
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
  setup_shm();
  //？
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
  //？
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
  //检查有效的ELF头 （为AFL插桩的证据？？二进制怎么插桩）
  check_binary(argv[optind]);
  //设定开始时间
  start_time = get_cur_time();
  //qemu_mode
  if (qemu_mode)
    use_argv = get_qemu_argv(argv[0], argv + optind, argc - optind);
  else
    use_argv = argv + optind;
  //执行所有测试用例的试运行，确认程序的工作方式
  //只针对初始输入，只执行一次
  perform_dry_run(use_argv);

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