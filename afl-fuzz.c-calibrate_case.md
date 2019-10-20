# afl-fuzz.c源码阅读

## perform_dry_run（）和calibrate_case（）

### 函数perform_dry_run（）

`perform_dry_run（）`运行所有的测试用例涉及函数主要有calibrate_case（） 

```C
/* Perform dry run of all test cases to confirm that the app is working as
   expected. This is done only for the initial inputs, and only once. 
   inputs的所有的测试用例运行一次确认应用程序按照期望的工作，他只是对初始的出入执行一遍且只有一遍*/

static void perform_dry_run(char** argv) {

  struct queue_entry* q = queue;
  u32 cal_failures = 0;
  u8* skip_crashes = getenv("AFL_SKIP_CRASHES");

  while (q) {//对输入文件的每个测试用例进行分析

    u8* use_mem;
    u8  res;
    s32 fd;

    u8* fn = strrchr(q->fname, '/') + 1;//获取输入的文件名，返回最后一次出现/位置+1

    ACTF("Attempting dry run with '%s'...", fn);

    fd = open(q->fname, O_RDONLY);//打开输入文件，获取文件描述符
    if (fd < 0) PFATAL("Unable to open '%s'", q->fname);//打开文件失败

    use_mem = ck_alloc_nozero(q->len);//分配测试用例的长度的空间

    if (read(fd, use_mem, q->len) != q->len)//将当前测试用例读入use_mem中，判断读取成功否
      FATAL("Short read from '%s'", q->fname);

    close(fd);

    res = calibrate_case(argv, q, use_mem, 0, 1);//测试用例矫正，返回运行的状态
    ck_free(use_mem);//安全释放use_mem

    if (stop_soon) return;

    if (res == crash_mode || res == FAULT_NOBITS)
      SAYF(cGRA "    len = %u, map size = %u, exec speed = %llu us\n" cRST, 
           q->len, q->bitmap_size, q->exec_us);

    switch (res) {//根据返回的状态输出相关的提示和警告

      case FAULT_NONE:

        if (q == queue) check_map_coverage();

        if (crash_mode) FATAL("Test case '%s' does *NOT* crash", fn);

        break;

      case FAULT_TMOUT:

        if (timeout_given) {

          /* The -t nn+ syntax in the command line sets timeout_given to '2' and
             instructs afl-fuzz to tolerate but skip queue entries that time
             out. */

          if (timeout_given > 1) {
            WARNF("Test case results in a timeout (skipping)");
            q->cal_failed = CAL_CHANCES;
            cal_failures++;
            break;
          }

          SAYF("\n" cLRD "[-] " cRST
               "The program took more than %u ms to process one of the initial test cases.\n"
               "    Usually, the right thing to do is to relax the -t option - or to delete it\n"
               "    altogether and allow the fuzzer to auto-calibrate. That said, if you know\n"
               "    what you are doing and want to simply skip the unruly test cases, append\n"
               "    '+' at the end of the value passed to -t ('-t %u+').\n", exec_tmout,
               exec_tmout);

          FATAL("Test case '%s' results in a timeout", fn);

        } else {

          SAYF("\n" cLRD "[-] " cRST
               "The program took more than %u ms to process one of the initial test cases.\n"
               "    This is bad news; raising the limit with the -t option is possible, but\n"
               "    will probably make the fuzzing process extremely slow.\n\n"

               "    If this test case is just a fluke, the other option is to just avoid it\n"
               "    altogether, and find one that is less of a CPU hog.\n", exec_tmout);

          FATAL("Test case '%s' results in a timeout", fn);

        }

      case FAULT_CRASH:  

        if (crash_mode) break;

        if (skip_crashes) {
          WARNF("Test case results in a crash (skipping)");
          q->cal_failed = CAL_CHANCES;
          cal_failures++;
          break;
        }

        if (mem_limit) {

          SAYF("\n" cLRD "[-] " cRST
               "Oops, the program crashed with one of the test cases provided. There are\n"
               "    several possible explanations:\n\n"

               "    - The test case causes known crashes under normal working conditions. If\n"
               "      so, please remove it. The fuzzer should be seeded with interesting\n"
               "      inputs - but not ones that cause an outright crash.\n\n"

               "    - The current memory limit (%s) is too low for this program, causing\n"
               "      it to die due to OOM when parsing valid files. To fix this, try\n"
               "      bumping it up with the -m setting in the command line. If in doubt,\n"
               "      try something along the lines of:\n\n"

#ifdef RLIMIT_AS
               "      ( ulimit -Sv $[%llu << 10]; /path/to/binary [...] <testcase )\n\n"
#else
               "      ( ulimit -Sd $[%llu << 10]; /path/to/binary [...] <testcase )\n\n"
#endif /* ^RLIMIT_AS */

               "      Tip: you can use http://jwilk.net/software/recidivm to quickly\n"
               "      estimate the required amount of virtual memory for the binary. Also,\n"
               "      if you are using ASAN, see %s/notes_for_asan.txt.\n\n"

#ifdef __APPLE__
  
               "    - On MacOS X, the semantics of fork() syscalls are non-standard and may\n"
               "      break afl-fuzz performance optimizations when running platform-specific\n"
               "      binaries. To fix this, set AFL_NO_FORKSRV=1 in the environment.\n\n"

#endif /* __APPLE__ */

               "    - Least likely, there is a horrible bug in the fuzzer. If other options\n"
               "      fail, poke <lcamtuf@coredump.cx> for troubleshooting tips.\n",
               DMS(mem_limit << 20), mem_limit - 1, doc_path);

        } else {

          SAYF("\n" cLRD "[-] " cRST
               "Oops, the program crashed with one of the test cases provided. There are\n"
               "    several possible explanations:\n\n"

               "    - The test case causes known crashes under normal working conditions. If\n"
               "      so, please remove it. The fuzzer should be seeded with interesting\n"
               "      inputs - but not ones that cause an outright crash.\n\n"

#ifdef __APPLE__
  
               "    - On MacOS X, the semantics of fork() syscalls are non-standard and may\n"
               "      break afl-fuzz performance optimizations when running platform-specific\n"
               "      binaries. To fix this, set AFL_NO_FORKSRV=1 in the environment.\n\n"

#endif /* __APPLE__ */

               "    - Least likely, there is a horrible bug in the fuzzer. If other options\n"
               "      fail, poke <lcamtuf@coredump.cx> for troubleshooting tips.\n");

        }

        FATAL("Test case '%s' results in a crash", fn);

      case FAULT_ERROR:

        FATAL("Unable to execute target application ('%s')", argv[0]);

      case FAULT_NOINST:

        FATAL("No instrumentation detected");

      case FAULT_NOBITS: 

        useless_at_start++;

        if (!in_bitmap && !shuffle_queue)
          WARNF("No new instrumentation output, test case may be useless.");

        break;

    }

    if (q->var_behavior) WARNF("Instrumentation output varies across runs.");

    q = q->next;//指向下一个测试用例

  }

  if (cal_failures) {

    if (cal_failures == queued_paths)
      FATAL("All test cases time out%s, giving up!",
            skip_crashes ? " or crash" : "");

    WARNF("Skipped %u test cases (%0.02f%%) due to timeouts%s.", cal_failures,
          ((double)cal_failures) * 100 / queued_paths,
          skip_crashes ? " or crashes" : "");

    if (cal_failures * 5 > queued_paths)
      WARNF(cLRD "High percentage of rejected test cases, check settings!");

  }

  OKF("All test cases processed.");

}
```

### calibrate_case（）函数

calibrate_case（）函数涉及的函数init_forkserver()，run_target（），has_new_bits（）

```c
/* Calibrate a new test case. This is done when processing the input directory
   to warn about flaky or otherwise problematic test cases early on; and when
   new paths are discovered to detect variable behavior and so on.矫正一个新的测试用例，在运行输入目录的测试用例的时候，早早警告那些有问题的测试用例 而且当新的路径发现的时候去检测变量的行为等等*/

static u8 calibrate_case(char** argv, struct queue_entry* q, u8* use_mem,
                         u32 handicap, u8 from_queue) {

  static u8 first_trace[MAP_SIZE];

  u8  fault = 0, new_bits = 0, var_detected = 0,
      first_run = (q->exec_cksum == 0);//q也就是测试用例第一次运行的exec_cksum是0

  u64 start_us, stop_us;//时间变量

  s32 old_sc = stage_cur, old_sm = stage_max;
  u32 use_tmout = exec_tmout;
  u8* old_sn = stage_name;

  /* Be a bit more generous about timeouts when resuming sessions, or when
     trying to calibrate already-added finds. This helps avoid trouble due
     to intermittent latency. */

  if (!from_queue || resuming_fuzz)
    use_tmout = MAX(exec_tmout + CAL_TMOUT_ADD,
                    exec_tmout * CAL_TMOUT_PERC / 100);

  q->cal_failed++;//开始设置矫正失败

  stage_name = "calibration";//阶段名称：矫正阶段
  stage_max  = fast_cal ? 3 : CAL_CYCLES;//通过fast_cal设置阶段的最大值

  /* Make sure the forkserver is up before we do anything, and let's not
     count its spin-up time toward binary calibration. */

  if (dumb_mode != 1 && !no_forkserver && !forksrv_pid)
    init_forkserver(argv);//初始化forksever

  if (q->exec_cksum) memcpy(first_trace, trace_bits, MAP_SIZE);//通过当前测试用例的exec_cksum判断是否复制trace_bits数组中的值

  start_us = get_cur_time_us();//获取程序开始的时间

  for (stage_cur = 0; stage_cur < stage_max; stage_cur++) {//循环最大值的次数次

    u32 cksum;//当前运行的cksum

    if (!first_run && !(stage_cur % stats_update_freq)) show_stats();//显示相关

    write_to_testcase(use_mem, q->len);//

    fault = run_target(argv, use_tmout);//运行目标程序返回状态值

    /* stop_soon is set by the handler for Ctrl+C. When it's pressed,
       we want to bail out quickly. stop_soon是按下Ctrl+C的处理，快速地退出*/

    if (stop_soon || fault != crash_mode) goto abort_calibration;//abort_calibration终止矫正

    if (!dumb_mode && !stage_cur && !count_bytes(trace_bits)) {
      fault = FAULT_NOINST;
      goto abort_calibration;
    }

    cksum = hash32(trace_bits, MAP_SIZE, HASH_CONST);//trace_bits进行hash

    if (q->exec_cksum != cksum) {//测试用例exec_cksum的和本次运行的cksum比较

      u8 hnb = has_new_bits(virgin_bits);//通过空闲区域变量来判断是否产生了新的覆盖（返回2）和新的撞击次数（返回1），没有的话返回0
      if (hnb > new_bits) new_bits = hnb;

      if (q->exec_cksum) {//如果测试用例的exec_cksum不为0，也就是不是第一次运行

        u32 i;

        for (i = 0; i < MAP_SIZE; i++) {//遍历tarce_bits数组的所有内容

          if (!var_bytes[i] && first_trace[i] != trace_bits[i]) {//找出产生新的覆盖的分支

            var_bytes[i] = 1;//var_byte数组初始为0，标志着trace_bits[]从为更新
            stage_max    = CAL_CYCLES_LONG;//加大阶段的最大值为40

          }

        }

        var_detected = 1;//检测过变量的行为

      } else {//q->exec_cksum==0的时候

        q->exec_cksum = cksum;
        memcpy(first_trace, trace_bits, MAP_SIZE);

      }

    }

  }

  stop_us = get_cur_time_us();//获取当前时间

  total_cal_us     += stop_us - start_us;//矫正阶段总用时
  total_cal_cycles += stage_max;//矫正阶段总的运行此时

  /* OK, let's collect some stats about the performance of this test case.
     This is used for fuzzing air time calculations in calculate_score(). 搜集关于测试用例表现的数据
     这是有用的对于在calculate_score()函数中计算fuzz开始的时间*/

  q->exec_us     = (stop_us - start_us) / stage_max;//测试用例执行一次的时间
  q->bitmap_size = count_bytes(trace_bits);//测试用例的bitmap的大小（trace_bits数组不为0的个数）
  q->handicap    = handicap;//先前测试用例的周期是0
  q->cal_failed  = 0;//矫正成功

  total_bitmap_size += q->bitmap_size;//总的bitmap的大小
  total_bitmap_entries++;//bitmaps的数量

  update_bitmap_score(q);//

  /* If this case didn't result in new output from the instrumentation, tell
     parent. This is a non-critical problem, but something to warn the user
     about. */

  if (!dumb_mode && first_run && !fault && !new_bits) fault = FAULT_NOBITS;

abort_calibration:

  if (new_bits == 2 && !q->has_new_cov) {//产生了新的覆盖但是测试用力的has_new_cov为0
    q->has_new_cov = 1;//更新
    queued_with_cov++;//产生新的覆盖的次数
  }

  /* Mark variable paths. */

  if (var_detected) {//

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





