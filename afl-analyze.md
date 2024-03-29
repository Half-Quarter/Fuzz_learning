# afl-analyze.c源码阅读

  AFL的介绍文件中这样介绍analyze工具：它需要一个输入文件，尝试顺序翻转字节，并观察被测试程序的行为。 然后，根据哪些部分看起来很关键，哪些不是关键部分，对输入进行颜色编码。 尽管不安全，它通常可以快速洞察复杂的文件格式。
  这个程序的功能主要是获取输入文件，并尝试解释其结构，通过观察对它的更改，看其是如何影响执行路径的。最主要的函数是analyze();
```C
/* Classify tuple counts. This is a slow & naive version, but good enough here. */

static u8 count_class_lookup[256] = {

  [0]           = 0,
  [1]           = 1,
  [2]           = 2,
  [3]           = 4,
  [4 ... 7]     = 8,
  [8 ... 15]    = 16,
  [16 ... 31]   = 32,
  [32 ... 127]  = 64,
  [128 ... 255] = 128

};

static void classify_counts(u8* mem) {

  u32 i = MAP_SIZE;
  if (edges_only) {
    while (i--) {
      if (*mem) *mem = 1;
      mem++;
    }
  } else {
    while (i--) {
      *mem = count_class_lookup[*mem];
      mem++;
    }
  }
}


/* See if any bytes are set in the bitmap. */
static inline u8 anything_set(void) {
  u32* ptr = (u32*)trace_bits;
  u32  i   = (MAP_SIZE >> 2);
  while (i--) if (*(ptr++)) return 1;
  return 0;
}


/* Get rid of shared memory and temp files (atexit handler). */
static void remove_shm(void) {
  unlink(prog_in); /* Ignore errors */  //主要意思是从文件系统中删除一个指定名字的文件，并清空这个文件使用的可用的系统资源，如空间、进程等
  shmctl(shm_id, IPC_RMID, NULL); //删除共享内存
}

/* Configure shared memory. */
static void setup_shm(void) {  //共享内存进程

  u8* shm_str;
 //该函数用来创建共享内存，可以根据此函数的返回值来访问同一共享内存 
  //具体参数见：https://www.cnblogs.com/52php/p/5861372.html
  shm_id = shmget(IPC_PRIVATE, MAP_SIZE, IPC_CREAT | IPC_EXCL | 0600); 
 
  //如果返回值小于0，说明创建共享内存错误
  if (shm_id < 0) PFATAL("shmget() failed"); 

  atexit(remove_shm);  //atexit函数是一个特殊的函数，它是在正常程序退出时调用的函数，叫为登记函数,如果一个函数被多次登记，也会被多次调用。

  shm_str = alloc_printf("%d", shm_id);  //分配的共享内存地址

  setenv(SHM_ENV_VAR, shm_str, 1);

  ck_free(shm_str);

  trace_bits = shmat(shm_id, NULL, 0);  //shmat()函数的作用就是用来启动对该共享内存的访问,将共享内存连接到当前的进程地址空间
  
  if (!trace_bits) PFATAL("shmat() failed");

}


/* Read initial file. */
static void read_initial_file(void) {

  struct stat st;
  s32 fd = open(in_file, O_RDONLY);
  if (fd < 0) PFATAL("Unable to open '%s'", in_file);
  if (fstat(fd, &st) || !st.st_size)
    FATAL("Zero-sized input file.");
  if (st.st_size >= TMIN_MAX_FILE)
    FATAL("Input file is too large (%u MB max)", TMIN_MAX_FILE / 1024 / 1024);
  in_len  = st.st_size;
  in_data = ck_alloc_nozero(in_len);
  ck_read(fd, in_data, in_len, in_file);
  close(fd);
  OKF("Read %u byte%s from '%s'.", in_len, in_len == 1 ? "" : "s", in_file);
}


/* Write output file. */
static s32 write_to_file(u8* path, u8* mem, u32 len) {
  s32 ret;
  unlink(path); /* Ignore errors */
  ret = open(path, O_RDWR | O_CREAT | O_EXCL, 0600);
  if (ret < 0) PFATAL("Unable to create '%s'", path);
  ck_write(ret, mem, len, path);
  lseek(ret, 0, SEEK_SET);
  return ret;
}


/* Handle timeout signal. */
static void handle_timeout(int sig) {
  child_timed_out = 1;
  if (child_pid > 0) kill(child_pid, SIGKILL);
}


/* Execute target application. Returns exec checksum, or 0 if program
   times out. */
static u32 run_target(char** argv, u8* mem, u32 len, u8 first_run) {
  static struct itimerval it;
  int status = 0;
  s32 prog_in_fd;
  u32 cksum;
  memset(trace_bits, 0, MAP_SIZE);
  MEM_BARRIER();

  prog_in_fd = write_to_file(prog_in, mem, len);
  child_pid = fork();
  if (child_pid < 0) PFATAL("fork() failed");
  if (!child_pid) {
    struct rlimit r;
    if (dup2(use_stdin ? prog_in_fd : dev_null_fd, 0) < 0 ||
        dup2(dev_null_fd, 1) < 0 ||
        dup2(dev_null_fd, 2) < 0) {
      *(u32*)trace_bits = EXEC_FAIL_SIG;
      PFATAL("dup2() failed");
    }
    close(dev_null_fd);
    close(prog_in_fd);
    if (mem_limit) {
      r.rlim_max = r.rlim_cur = ((rlim_t)mem_limit) << 20;
#ifdef RLIMIT_AS
      setrlimit(RLIMIT_AS, &r); /* Ignore errors */
#else
      setrlimit(RLIMIT_DATA, &r); /* Ignore errors */
#endif /* ^RLIMIT_AS */
    }
    r.rlim_max = r.rlim_cur = 0;
    setrlimit(RLIMIT_CORE, &r); /* Ignore errors */
    execv(target_path, argv);
    *(u32*)trace_bits = EXEC_FAIL_SIG;
    exit(0);
  }
  close(prog_in_fd);
  /* Configure timeout, wait for child, cancel timeout. */
  child_timed_out = 0;
  it.it_value.tv_sec = (exec_tmout / 1000);
  it.it_value.tv_usec = (exec_tmout % 1000) * 1000;
  setitimer(ITIMER_REAL, &it, NULL);
  if (waitpid(child_pid, &status, 0) <= 0) FATAL("waitpid() failed");
  child_pid = 0;
  it.it_value.tv_sec = 0;
  it.it_value.tv_usec = 0;
  setitimer(ITIMER_REAL, &it, NULL);
  MEM_BARRIER();
  /* Clean up bitmap, analyze exit condition, etc. */
  if (*(u32*)trace_bits == EXEC_FAIL_SIG)
    FATAL("Unable to execute '%s'", argv[0]);
  classify_counts(trace_bits);
  total_execs++;
  if (stop_soon) {
    SAYF(cRST cLRD "\n+++ Analysis aborted by user +++\n" cRST);
    exit(1);
  }

  /* Always discard inputs that time out. */

  if (child_timed_out) {
    exec_hangs++;
    return 0;
  }

  cksum = hash32(trace_bits, MAP_SIZE, HASH_CONST);
  /* We don't actually care if the target is crashing or not,
     except that when it does, the checksum should be different. */

  if (WIFSIGNALED(status) ||
      (WIFEXITED(status) && WEXITSTATUS(status) == MSAN_ERROR) ||
      (WIFEXITED(status) && WEXITSTATUS(status))) {
    cksum ^= 0xffffffff;
  }

  if (first_run) orig_cksum = cksum;
  return cksum;
}

#ifdef USE_COLOR
/* Helper function to display a human-readable character. */
static void show_char(u8 val) {
  switch (val) {
    case 0 ... 32:
    case 127 ... 255: SAYF("#%02x", val); break;
    default: SAYF(" %c ", val);
  }
}

/* Show the legend */  展示这些说明，解释
static void show_legend(void) {
  SAYF("    " cLGR bgGRA " 01 " cRST " - no-op block              "  //无操作区
              cBLK bgLGN " 01 " cRST " - suspected length field\n"  //可疑的长度区域，字段
       "    " cBRI bgGRA " 01 " cRST " - superficial content      "  //表面内容
              cBLK bgYEL " 01 " cRST " - suspected cksum or magic int\n" //可疑地校验和或魔数
       "    " cBLK bgCYA " 01 " cRST " - critical stream          "  //关键流
              cBLK bgLRD " 01 " cRST " - suspected checksummed block\n" //可疑的校验和块
       "    " cBLK bgMGN " 01 " cRST " - \"magic value\" section\n\n"); //魔数部分
}

#endif /* USE_COLOR */

/* Interpret and report a pattern in the input file. */ //解释并报告输入文件中的模式，对一些字段进行大致分类
static void dump_hex(u8* buf, u32 len, u8* b_data) {  //buf:指向输入数据的指针，len:输入数据的长度，b_data:指向分配空间的指针
  u32 i;
  for (i = 0; i < len; i++) { //对于输入数据的每个数据，进入循环

#ifdef USE_COLOR
    u32 rlen = 1, off;
#else
    u32 rlen = 1;
#endif /* ^USE_COLOR */
    u8  rtype = b_data[i] & 0x0f;  //只保留b_data[i]的最后四位，比如b_data[i]=0x56,则rtype=0x06  
    /* Look ahead to determine the length of run. */  //提前确定运行长度 rlen
    while (i + rlen < len && (b_data[i] >> 7) == (b_data[i + rlen] >> 7)) { //i+rlen<len并且b_data[i]和b_data[i+rlen]的最高位相等，进入循环
      if (rtype < (b_data[i + rlen] & 0x0f)) rtype = b_data[i + rlen] & 0x0f;//取b_data[i]的最后一位的最大值
      rlen++;  //连续最高位相等的字节个数

    }
    //上述示例：初始条件i=0,rlen=1,b_data[i]=1000 0000,b_data[i+rlen]=1001 0001.
    //b_data[i]>>7=0000 0001 ,b_data[i+rlen]=0000 0001 ,长度符合，进入循环。
    //(b_data[i + rlen] & 0x0f)=0000 0001，b_data[i] & 0x0f=0000 0000，那么rtype=0x01
    //rlen++,若满足条件，继续循环。我理解的：这里循环的意思是对每个字节进行比较，更新rlen和rtype

    /* Try to do some further classification based on length & value. */ //尝试根据长度和值做进一步的分类。

    if (rtype == RESP_FIXED) {  //RESP_FIXED:changes produce fixed patterns.  //rtype=0x03，即改变这些字节的任何位都会产生相同的结果，这里就是告诉我们如何得到这些字节

      switch (rlen) {  //运行的长度rlen

        case 2: {

            u16 val = *(u16*)(in_data + i);  //val=指向当前第i个输入数据

         /* Small integers may be length fields. */  //小整数可能是长度字段

            if (val && (val <= in_len || SWAP16(val) <= in_len)) {  //swap16():将val指向的buf转换成16位整数的数组
           rtype = RESP_LEN;  //运行类型为长度字段（RESP_LEN:potential length field）
              break;
            }

         /* Uniform integers may be checksums. */  //一致的整数可能是校验和

            if (val && abs(in_data[i] - in_data[i + 1]) > 32) {  //不知道这里的绝对值为什么大于32？难道是用的CRC32？
              rtype = RESP_CKSUM;
              break;
            }

            break;

          }

        case 4: {

            u32 val = *(u32*)(in_data + i);
          /* Small integers may be length fields. */  //小整数可能是长度字段
            if (val && (val <= in_len || SWAP32(val) <= in_len)) {
              rtype = RESP_LEN;
              break;
            }

            /* Uniform integers may be checksums. */

            if (val && (in_data[i] >> 7 != in_data[i + 1] >> 7 ||
                in_data[i] >> 7 != in_data[i + 2] >> 7 ||
                in_data[i] >> 7 != in_data[i + 3] >> 7)) {
              rtype = RESP_CKSUM;
              break;
            }
            break;
          }
        case 1: case 3: case 5 ... MAX_AUTO_EXTRA - 1: break;
        default: rtype = RESP_SUSPECT;  // blob
      }
    }
    /* Print out the entire run. */  //打印整个运行
#ifdef USE_COLOR //染色编号

    for (off = 0; off < rlen; off++) {
      /* Every 16 digits, display offset. */  //每十六位显示偏移
      if (!((i + off) % 16)) {
        if (off) SAYF(cRST cLCY ">");
        if (use_hex_offsets)
        SAYF(cRST cGRA "%s[%06x] " cRST, (i + off) ? "\n" : "", i + off);
        else
        SAYF(cRST cGRA "%s[%06u] " cRST, (i + off) ? "\n" : "", i + off);
      }

      switch (rtype) {  //对每种字段类型进行输出
        case RESP_NONE:     SAYF(cLGR bgGRA); break;
        case RESP_MINOR:    SAYF(cBRI bgGRA); break;
        case RESP_VARIABLE: SAYF(cBLK bgCYA); break;
        case RESP_FIXED:    SAYF(cBLK bgMGN); break;
        case RESP_LEN:      SAYF(cBLK bgLGN); break;
        case RESP_CKSUM:    SAYF(cBLK bgYEL); break;
        case RESP_SUSPECT:  SAYF(cBLK bgLRD); break;
      }
      show_char(in_data[i + off]);  //对输入字节进行颜色编号

      if (off != rlen - 1 && (i + off + 1) % 16) SAYF(" "); else SAYF(cRST " ");
    }

#else （不明白）
    if (use_hex_offsets)
      SAYF("    Offset %x, length %u: ", i, rlen);
    else
      SAYF("    Offset %u, length %u: ", i, rlen);
    switch (rtype) {
      case RESP_NONE:     SAYF("no-op block\n"); break;
      case RESP_MINOR:    SAYF("superficial content\n"); break;
      case RESP_VARIABLE: SAYF("critical stream\n"); break;
      case RESP_FIXED:    SAYF("\"magic value\" section\n"); break;
      case RESP_LEN:      SAYF("suspected length field\n"); break;
      case RESP_CKSUM:    SAYF("suspected cksum or magic int\n"); break;
      case RESP_SUSPECT:  SAYF("suspected checksummed block\n"); break;
    }
#endif /* ^USE_COLOR */
    i += rlen - 1;
  }
#ifdef USE_COLOR
  SAYF(cRST "\n");
#endif /* USE_COLOR */
}

/* Actually analyze! */   //实际分析
static void analyze(char** argv) {

  u32 i;
  u32 boring_len = 0, prev_xff = 0, prev_x01 = 0, prev_s10 = 0, prev_a10 = 0;
  u8* b_data = ck_alloc(in_len + 1); //in_len是输入数据的长度，alloc函数可返回一个指向n个连续字符存储单元的指针，alloc函数的调用者可以利用该指针存储字符序列。返回指向in_len+1个字符的指针。即这个b_data是指向一段长度为in_len+1的一段空间的指针。
  u8  seq_byte = 0;
  b_data[in_len] = 0xff; /* Intentional terminator. */  //设置b_data数组中最后一个元素in_len的值为0xff，设置结束符。eof（）是C读入文件判断是否读完的函数，0xff是文件结束符，当读到0xff时，就会结束读文件。我理解的这里的意思是读入数据长度为in_len的数据就结束。

  ACTF("Analyzing input file (this may take a while)...\n");  //输出：分析输入文件，这可能需要一段时间。

#ifdef USE_COLOR
  show_legend();  //展示说明，对一些参数的解释说明
#endif /* USE_COLOR */

  for (i = 0; i < in_len; i++) {

    u32 xor_ff, xor_01, sub_10, add_10;
    u8  xff_orig, x01_orig, s10_orig, a10_orig;

   /* Perform walking byte adjustments across the file. We perform four
     operations designed to elicit some response from the underlying
     code. */ //遍历文件，执行步进字节调整，执行四个操作旨在引起底层代码的某些响应。
    in_data[i] ^= 0xff;
    xor_ff = run_target(argv, in_data, in_len, 0);//每位进行翻转

    in_data[i] ^= 0xfe; //前7位翻转，最后一位保持不变。
    xor_01 = run_target(argv, in_data, in_len, 0);

    in_data[i] = (in_data[i] ^ 0x01) - 0x10;//前四位的最后一位如果是1，则结果是前四位和后四位的最后一位翻转，其他不变，如10011100->10001101（只影响第四位和第八位）
    //前四位的最后一位是0，则前四位倒数第一个1翻转和后四位的最后一位翻转。如10001100->00001101,01101100->01001101（影响前四位和第八位）
    sub_10 = run_target(argv, in_data, in_len, 0);

    in_data[i] += 0x20; //0x20=0010 0000 ，影响第二位（有进位）和第三位
    add_10 = run_target(argv, in_data, in_len, 0);
    in_data[i] -= 0x10;//0x10=0001 0000，影响前四位（有借位）

//以上操作是分别对一个字节不同的位进行翻转操作，观察每次翻转之后目标二进制文件的行为
    /* Classify current behavior. *///根据以上操作，可对某些信息进行分类

    xff_orig = (xor_ff == orig_cksum);
    x01_orig = (xor_01 == orig_cksum);
    s10_orig = (sub_10 == orig_cksum);
    a10_orig = (add_10 == orig_cksum);

    if (xff_orig && x01_orig && s10_orig && a10_orig) {

      b_data[i] = RESP_NONE;//无操作块，即改变这些块不会引发任何对控制流的更改（比如像素数据等）
      boring_len++;

    } else if (xff_orig || x01_orig || s10_orig || a10_orig) {

      b_data[i] = RESP_MINOR;//较长的blob显示此属性，即改变是没有影响的。（校验和或加密的数据）blob释义:一小片
      boring_len++;

    } else if (xor_ff == xor_01 && xor_ff == sub_10 && xor_ff == add_10) {

      b_data[i] = RESP_FIXED; //检验和，魔数，其中任何位翻转都会导致程序执行相同的变化。

    } else b_data[i] = RESP_VARIABLE; //纯粹的数据部分，其中分析器注入的变化始终引起控制流程的不同变化。

    /* When all checksums change, flip most significant bit of b_data. */

    if (prev_xff != xor_ff && prev_x01 != xor_01 &&
        prev_s10 != sub_10 && prev_a10 != add_10) seq_byte ^= 0x80; //翻转最高位 0x80=1000 0000 （不明白）

    b_data[i] |= seq_byte; //按位或（不明白）

    prev_xff = xor_ff;
    prev_x01 = xor_01;
    prev_s10 = sub_10;
    prev_a10 = add_10;

  } 

  dump_hex(in_data, in_len, b_data);  //解释和报告输入文件的模式，对输入数据进行大致分类

  SAYF("\n");

  OKF("Analysis complete. Interesting bits: %0.02f%% of the input file.",
      100.0 - ((double)boring_len * 100) / in_len);  

  if (exec_hangs)  //exec_hangs:程序产生挂起的次数
    WARNF(cLRD "Encountered %u timeouts - results may be skewed." cRST,
          exec_hangs);  //遇到exec_hangs个超时，结果可能会有偏斜

  ck_free(b_data); //释放前边申请的存储空间

}



/* Handle Ctrl-C and the like. */

static void handle_stop_sig(int sig) {

  stop_soon = 1;

  if (child_pid > 0) kill(child_pid, SIGKILL);

}


/* Do basic preparations - persistent fds, filenames, etc. */ //做基本的准备，如fds,文件名等

static void set_up_environment(void) {

  u8* x;

  dev_null_fd = open("/dev/null", O_RDWR);  //dev/null的fd,open函数打开和创建文件，返回值：成功则返回文件描述符，否则返回-1。O_RDWR读写模式
  if (dev_null_fd < 0) PFATAL("Unable to open /dev/null");

  if (!prog_in) {  //如果目标程序输入文件等于0，为空

    u8* use_dir = ".";

    if (access(use_dir, R_OK | W_OK | X_OK)) {  //如果use_dir所指文件可读可写可执行

      use_dir = getenv("TMPDIR"); //获得TMPDIR环境变量的指针，这个指针指向环境变量的内容， 执行成功则返回指向该内容的指针，找不到符合的环境变量名称则返回NULL
      if (!use_dir) use_dir = "/tmp";  //如果上一步找不到符合的环境变量名或者没有与之相符的值，令use_dir指向tmp

    }

    prog_in = alloc_printf("%s/.afl-analyze-temp-%u", use_dir, getpid()); //getpid()返回当前进程标志

  }

  /* Set sane defaults... */  //设置默认值

  x = getenv("ASAN_OPTIONS");  //x为指向ASAN_OPTIONS环境变量的指针

  if (x) {

    if (!strstr(x, "abort_on_error=1"))  //strstr(str1,str2) 函数用于判断字符串str2是否是str1的子串。如果是，则该函数返回str2在str1中首次出现的地址；否则，返回NULL。
      FATAL("Custom ASAN_OPTIONS set without abort_on_error=1 - please fix!");

    if (!strstr(x, "symbolize=0"))
      FATAL("Custom ASAN_OPTIONS set without symbolize=0 - please fix!");

  }

  x = getenv("MSAN_OPTIONS");

  if (x) {

    if (!strstr(x, "exit_code=" STRINGIFY(MSAN_ERROR)))
      FATAL("Custom MSAN_OPTIONS set without exit_code="
            STRINGIFY(MSAN_ERROR) " - please fix!");

    if (!strstr(x, "symbolize=0"))
      FATAL("Custom MSAN_OPTIONS set without symbolize=0 - please fix!");

  }

  setenv("ASAN_OPTIONS", "abort_on_error=1:"
                         "detect_leaks=0:"
                         "symbolize=0:"
                         "allocator_may_return_null=1", 0);

  setenv("MSAN_OPTIONS", "exit_code=" STRINGIFY(MSAN_ERROR) ":"
                         "symbolize=0:"
                         "abort_on_error=1:"
                         "allocator_may_return_null=1:"
                         "msan_track_origins=0", 0);

  if (getenv("AFL_PRELOAD")) {
    setenv("LD_PRELOAD", getenv("AFL_PRELOAD"), 1);
    setenv("DYLD_INSERT_LIBRARIES", getenv("AFL_PRELOAD"), 1);
  }

}


/* Setup signal handlers, duh. */

static void setup_signal_handlers(void) {

  struct sigaction sa;  //sigaction（）设置信号处理的接口

  sa.sa_handler   = NULL;   //sa_handler此参数和signal()的参数handler相同，代表新的信号处理函数，默认信号处理函数
  sa.sa_flags     = SA_RESTART;  //sa_flags 用来设置信号处理的其他相关操作，下列的数值可用。SA_RESTART：如果信号中断了进程的某个系统调用，则系统自动启动该系统调用
  sa.sa_sigaction = NULL;   //成员sa_sigaction 则是另一个信号处理函数，它有三个参数，可以获得关于信号的更详细的信息。
  //当 sa_flags 成员的值包含了 SA_SIGINFO 标志时，系统将使用 sa_sigaction 函数作为信号处理函数，否则使用 sa_handler 作为信号处理函数。

  sigemptyset(&sa.sa_mask);  //该函数的作用是将信号集初始化为空。sa_mask 用来设置在处理该信号时暂时将sa_mask 指定的信号集搁置
  //我们可以通过信号来终止进程，也可以通过信号来在进程间进行通信，程序也可以通过指定信号的关联处理函数来改变信号的默认处理方式，也可以屏蔽某些信号，使其不能传递给进程。
  //那么我们应该如何设定我们需要处理的信号，我们不需要处理哪些信号等问题呢？信号集函数就是帮助我们解决这些问题的。

  /* Various ways of saying "stop". */
  sa.sa_handler = handle_stop_sig;
  sigaction(SIGHUP, &sa, NULL);
  sigaction(SIGINT, &sa, NULL);
  sigaction(SIGTERM, &sa, NULL);

  /* Exec timeout notifications. */
  sa.sa_handler = handle_timeout;
  sigaction(SIGALRM, &sa, NULL);

}


/* Detect @@ in args. */

static void detect_file_args(char** argv) {

  u32 i = 0;
  u8* cwd = getcwd(NULL, 0);

  if (!cwd) PFATAL("getcwd() failed");

  while (argv[i]) {

    u8* aa_loc = strstr(argv[i], "@@");

    if (aa_loc) {

      u8 *aa_subst, *n_arg;
      /* Be sure that we're always using fully-qualified paths. */
      if (prog_in[0] == '/') aa_subst = prog_in;
      else aa_subst = alloc_printf("%s/%s", cwd, prog_in);
      /* Construct a replacement argv value. */
      *aa_loc = 0;
      n_arg = alloc_printf("%s%s%s", argv[i], aa_subst, aa_loc + 2);
      argv[i] = n_arg;
      *aa_loc = '@';
      if (prog_in[0] != '/') ck_free(aa_subst);
    }
    i++;
  }
  free(cwd); /* not tracked */
}


/* Display usage hints. */
static void usage(u8* argv0) {
  SAYF("\n%s [ options ] -- /path/to/target_app [ ... ]\n\n"
       "Required parameters:\n\n"

       "  -i file       - input test case to be analyzed by the tool\n"
       "Execution control settings:\n\n"
       "  -f file       - input file read by the tested program (stdin)\n"
       "  -t msec       - timeout for each run (%u ms)\n"
       "  -m megs       - memory limit for child process (%u MB)\n"
       "  -Q            - use binary-only instrumentation (QEMU mode)\n\n"
       "Analysis settings:\n\n"
       "  -e            - look for edge coverage only, ignore hit counts\n\n"
       "For additional tips, please consult %s/README.\n\n",
       argv0, EXEC_TIMEOUT, MEM_LIMIT, doc_path);
  exit(1);

}


/* Find binary. */
static void find_binary(u8* fname) {
  u8* env_path = 0;
  struct stat st;
  if (strchr(fname, '/') || !(env_path = getenv("PATH"))) {
    target_path = ck_strdup(fname);
    if (stat(target_path, &st) || !S_ISREG(st.st_mode) ||
        !(st.st_mode & 0111) || st.st_size < 4)
      FATAL("Program '%s' not found or not executable", fname);
  } else {
    while (env_path) {
      u8 *cur_elem, *delim = strchr(env_path, ':');
      if (delim) {
        cur_elem = ck_alloc(delim - env_path + 1);
        memcpy(cur_elem, env_path, delim - env_path);
        delim++;
      } else cur_elem = ck_strdup(env_path);
      env_path = delim;
      if (cur_elem[0])
        target_path = alloc_printf("%s/%s", cur_elem, fname);
      else
        target_path = ck_strdup(fname);
      ck_free(cur_elem);
      if (!stat(target_path, &st) && S_ISREG(st.st_mode) &&
          (st.st_mode & 0111) && st.st_size >= 4) break;
      ck_free(target_path);
      target_path = 0;
    }
    if (!target_path) FATAL("Program '%s' not found or not executable", fname);
  }
}

/* Fix up argv for QEMU. */
static char** get_qemu_argv(u8* own_loc, char** argv, int argc) {

  char** new_argv = ck_alloc(sizeof(char*) * (argc + 4));
  u8 *tmp, *cp, *rsl, *own_copy;
  /* Workaround for a QEMU stability glitch. */
  setenv("QEMU_LOG", "nochain", 1);
  memcpy(new_argv + 3, argv + 1, sizeof(char*) * argc);
  /* Now we need to actually find qemu for argv[0]. */
  new_argv[2] = target_path;
  new_argv[1] = "--";
  tmp = getenv("AFL_PATH");
  if (tmp) {
    cp = alloc_printf("%s/afl-qemu-trace", tmp);
    if (access(cp, X_OK))
      FATAL("Unable to find '%s'", tmp);
    target_path = new_argv[0] = cp;
    return new_argv;
  }
  own_copy = ck_strdup(own_loc);
  rsl = strrchr(own_copy, '/');
  if (rsl) {
    *rsl = 0;
    cp = alloc_printf("%s/afl-qemu-trace", own_copy);
    ck_free(own_copy);
    if (!access(cp, X_OK)) {
      target_path = new_argv[0] = cp;
      return new_argv;
    }
  } else ck_free(own_copy);
  if (!access(BIN_PATH "/afl-qemu-trace", X_OK)) {
    target_path = new_argv[0] = BIN_PATH "/afl-qemu-trace";
    return new_argv;
  }
  FATAL("Unable to find 'afl-qemu-trace'.");
}


/* Main entry point */    //主要入口
int main(int argc, char** argv) {
  s32 opt;
  u8  mem_limit_given = 0, timeout_given = 0, qemu_mode = 0;
  char** use_argv;
  doc_path = access(DOC_PATH, F_OK) ? "docs" : DOC_PATH;  // #define  F_OK      0     /* Check for file existence */检查文件是否存在，存在则返回0，不存在则返回-1，这里的条件表达式是文件存在就指向该文件，不存在则指向该文件路径。
  SAYF(cCYA "afl-analyze " cBRI VERSION cRST " by <lcamtuf@google.com>\n");
  while ((opt = getopt(argc,argv,"+i:f:m:t:eQ")) > 0)  //getopt():用来解析命令行选项参数，其中argc：main()函数传递过来的参数的个数 ,argv：main()函数传递过来的参数的字符串指针数组,optstring：选项字符串，告知 getopt()可以处理哪个选项以及哪个选项需要参数。
  //如果选项成功找到，返回选项字母；如果所有命令行选项都解析完毕，返回 -1，退出循环。选项后边有冒号的，表示有参数，如果有两个冒号的，则该选项可选可不选。

    switch (opt) {
      case 'i':  //输入测试用例

        if (in_file) FATAL("Multiple -i options not supported");  //这里如果前面分析过输入测试用例，就出错：不提供多个i选项。
        in_file = optarg; //令分析输入测试用例的指针=指向i选项参数的指针
        break;

      case 'f':  //目标程序读入文件

        if (prog_in) FATAL("Multiple -f options not supported");  //目标程序输入文件如果被解析过，同上，没有多个f选项提供
        use_stdin = 0;  //这个参数的意思是，是否使用标准输入stdin，就是是否是从键盘输入，标准输入的文件标识符=0，则这里就是接受从键盘的输入。
        prog_in   = optarg;
        break;

      case 'e':  //只寻找边缘覆盖（分支覆盖），忽略命中计数

        if (edges_only) FATAL("Multiple -e options not supported"); //同上，这里是之前解析过忽略命中计数了，就不再解析了。
        edges_only = 1; //忽略命中计数
        break;

      case 'm': {  //内存限制

          u8 suffix = 'M';

          if (mem_limit_given) FATAL("Multiple -m options not supported");//这里我理解的是给定的内存限制
          mem_limit_given = 1;

          if (!strcmp(optarg, "none")) { //如果m选项没有参数

            mem_limit = 0; //没有内存限制
            break;

          }

          if (sscanf(optarg, "%llu%c", &mem_limit, &suffix) < 1 ||   //scanf函数的返回值是成功读入数据的项数，这里要求读入3个数据，如果都成功读入，则返回3.
          //这里的判断条件是：如果这三个数据一个都没有读入成功或者指向选项参数的指针的第一个内容为'-'，则报错：-m使用的是不正确的语法
              optarg[0] == '-') FATAL("Bad syntax used for -m");

          switch (suffix) {  //对内存的限制，上面对suffix进行了输入

            case 'T': mem_limit *= 1024 * 1024; break;
            case 'G': mem_limit *= 1024; break;
            case 'k': mem_limit /= 1024; break;
            case 'M': break;

            default:  FATAL("Unsupported suffix or bad syntax for -m");

          }

          if (mem_limit < 5) FATAL("Dangerously low value of -m"); //如果内存限制小于5，则报错：-m的值小，是危险的

          if (sizeof(rlim_t) == 4 && mem_limit > 2000) //内存太大，超过32位操作范围
            FATAL("Value of -m out of range on 32-bit systems");

        }

        break;

      case 't':  //每次运行的时间

        if (timeout_given) FATAL("Multiple -t options not supported");
        timeout_given = 1;

        exec_tmout = atoi(optarg); //执行时间=t选项参数转换成整数的值

        if (exec_tmout < 10 || optarg[0] == '-') //t选项的危险值的判断
          FATAL("Dangerously low value of -t");

        break;

      case 'Q':   //使用qemu模式进行插桩

        if (qemu_mode) FATAL("Multiple -Q options not supported");
        if (!mem_limit_given) mem_limit = MEM_LIMIT_QEMU;

        qemu_mode = 1;
        break;

      default:

        usage(argv[0]);

    }

  if (optind == argc || !in_file) usage(argv[0]);

  use_hex_offsets = !!getenv("AFL_ANALYZE_HEX");

  setup_shm();  //创建共享内存
  setup_signal_handlers(); //设置信号处理程序

  set_up_environment(); //设置环境

  find_binary(argv[optind]);  //找二进制文件
  detect_file_args(argv + optind);  //在参数中检测@@

  if (qemu_mode)
    use_argv = get_qemu_argv(argv[0], argv + optind, argc - optind);
  else
    use_argv = argv + optind;

  SAYF("\n");

  read_initial_file();  //读取初始文件

  ACTF("Performing dry run (mem limit = %llu MB, timeout = %u ms%s)...",
       mem_limit, exec_tmout, edges_only ? ", edges only" : "");

  run_target(use_argv, in_data, in_len, 1);  //运行
  if (child_timed_out)
    FATAL("Target binary times out (adjusting -t may help).");
  if (!anything_set()) FATAL("No instrumentation detected.");
  analyze(use_argv);
  OKF("We're done here. Have a nice day!\n");
  exit(0);
}

```