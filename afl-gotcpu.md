# afl-gotcpu.c源码阅读

```C
//定义一个静态函数去获取当前时间               
static u64 get_cur_time_us(void) {                      
  struct timeval tv;          //timeval是Linux下定义的结构体 
  struct timezone tz;	      // timezone为获取时区 
  gettimeofday(&tv, &tz);		//tv是保存获取时间结果的结构体，参数tz用于保存时区结果;gettimeofday计算代码执行时间 
  return (tv.tv_sec * 1000000ULL) + tv.tv_usec;  //以微秒为单位返回时间 

}
/* Get CPU usage in microseconds. */
//定义一个静态函数去获取CPU使用率 ，以微秒形式表示 
static u64 get_cpu_usage_us(void) {    
  struct rusage u;
  //获取当前进程使用的资源，返回结果存储在struct rusage中
  getrusage(RUSAGE_SELF, &u);          
  return (u.ru_utime.tv_sec * 1000000ULL) + u.ru_utime.tv_usec + 		//utime表示用户态使用的时间，stime表示系统态使用的时间。此行代码表示使用返回当前进程在用户态以及系统态的时间之和，并且用微妙来表示，即以微秒来表示CPU使用率。
         (u.ru_stime.tv_sec * 1000000ULL) + u.ru_stime.tv_usec;
}

/* Measure preemption rate. */
static u32 measure_preemption(u32 target_ms) {
 //volatile类似const，但是确保本条指令不会因编译器的优化而省略，且要求每次直接读值。
  static volatile u32 v1, v2;  							
  //定义无符号64位整型变量 
  u64 st_t, en_t, st_c, en_c, real_delta, slice_delta;	
 //定义有符号32位整型变量 
  s32 loop_repeats = 0;									
  //令st_t为此时刻时间 T1，st_c为CPU使用率 C1
  st_t = get_cur_time_us();					
  st_c = get_cpu_usage_us();			
  repeat_loop:								//进入loop 
  v1 = CTEST_BUSY_CYCLES;					// #define  CTEST_BUSY_CYCLES  (10 * 1000 * 1000)	
  while (v1--) v2++;					
  //这个函数可以使用另一个级别等于或高于当前线程的线程先运行。如果没有符合条件的线程，那么这个函数将会立刻返回然后继续执行当前线程的程序。
  sched_yield();							

  en_t = get_cur_time_us();					//定义en_t为此时刻时间 T2 

  if (en_t - st_t < target_ms * 1000) {		//时间T1减去时间T2小于参数target_ms*1000，则继续循环 
    loop_repeats++;
    goto repeat_loop;
  }

  /* Let's see what percentage of this time we actually had a chance to
     run, and how much time was spent in the penalty box. */

  en_c = get_cpu_usage_us();  				//令en_c为CPU使用率 C2

  real_delta  = (en_t - st_t) / 1000;		//除以1000是为了以微秒表示，下一行同理 
  slice_delta = (en_c - st_c) / 1000;
  return real_delta * 100 / slice_delta;	
}

/* Do the benchmark thing. */
int main(int argc, char** argv) {

#ifdef HAVE_AFFINITY
  u32 cpu_cnt = sysconf(_SC_NPROCESSORS_ONLN),		//sysconf() 返回选项 (_SC_NPROCESSORS_ONLN在线处理器) 的当前值，如果正确，则返回当前值，如果错误，则返回 -1 ，并适当地设置 errno。  
      idle_cpus = 0, maybe_cpus = 0, i;

  SAYF(cCYA "afl-gotcpu " cBRI VERSION cRST " by <lcamtuf@google.com>\n");	 //SAYF(x...)=printf(x) else fprintf(stderr,x) 

  ACTF("Measuring per-core preemption rate (this will take %0.02f sec)...",		//ACTF(x...) do { SAYF(cLBL "[*] " cRST x); SAYF(cRST "\n");  } while (0) 
       ((double)CTEST_CORE_TRG_MS) / 1000);		//#define  CTEST_CORE_TRG_MS  1000 						

  for (i = 0; i < cpu_cnt; i++) {
    //分支函数创建两个相同的进程。在父进程中，fork返回新创建子进程的进程ID；在子进程中，fork返回0；如果出现错误，fork返回一个负值； 
    s32 fr = fork();				
    if (fr < 0) PFATAL("fork failed");  //PFATAL函数类似于printf 
    if (!fr) {							//如果fr为假，即fork函数返回0或者负值。 
     //可以理解为cpu集，也是通过约定好的宏来进行清除、设置以及判断
      cpu_set_t c;					
      u32 util_perc;
      CPU_ZERO(&c);					//将某个cpu加入cpu集中 
      CPU_SET(i, &c);				// void CPU_SET (int cpu, cpu_set_t *set); //将某个cpu从cpu集中移出 
	    //使当前进程运行在c所设定的那些CPU上
      if (sched_setaffinity(0, sizeof(c), &c))		
        PFATAL("sched_setaffinity failed");
      // 获得 Measure preemption rate 
      util_perc = measure_preemption(CTEST_CORE_TRG_MS);		

      if (util_perc < 110) {
        SAYF("    Core #%u: " cLGN "AVAILABLE\n" cRST, i);
        exit(0);
      } else if (util_perc < 250) {
        SAYF("    Core #%u: " cYEL "CAUTION " cRST "(%u%%)\n", i, util_perc); 
        exit(1);
      }
      SAYF("    Core #%u: " cLRD "OVERBOOKED " cRST "(%u%%)\n" cRST, i,
           util_perc);
      exit(2);
    }
  }
  for (i = 0; i < cpu_cnt; i++) {

    int ret;
    if (waitpid(-1, &ret, 0) < 0) PFATAL("waitpid failed");	//等待任一一个子进程退出运行，若成功则返回该子进程号；若失败则返回-1； 

    if (WEXITSTATUS(ret) == 0) idle_cpus++;		//WEXITSTATUS函数：如果子进程正常退出，则提取子进程的返回值；如果子进程不是正常退出，则返回0； 
    if (WEXITSTATUS(ret) <= 1) maybe_cpus++;

  }

  SAYF(cGRA "\n>>> ");

  if (idle_cpus) {
    if (maybe_cpus == idle_cpus) {
      SAYF(cLGN "PASS: " cRST "You can run more processes on %u core%s.",
           idle_cpus, idle_cpus > 1 ? "s" : "");
    } else {
      SAYF(cLGN "PASS: " cRST "You can run more processes on %u to %u core%s.",
           idle_cpus, maybe_cpus, maybe_cpus > 1 ? "s" : "");
    }
    SAYF(cGRA " <<<" cRST "\n\n");
    return 0;
  }

  if (maybe_cpus) {
    SAYF(cYEL "CAUTION: " cRST "You may still have %u core%s available.",
         maybe_cpus, maybe_cpus > 1 ? "s" : "");
    SAYF(cGRA " <<<" cRST "\n\n");
    return 1;
  }
  SAYF(cLRD "FAIL: " cRST "All cores are overbooked.");
  SAYF(cGRA " <<<" cRST "\n\n");
  return 2;
#else
  u32 util_perc;
  SAYF(cCYA "afl-gotcpu " cBRI VERSION cRST " by <lcamtuf@google.com>\n");
  /* Run a busy loop for CTEST_TARGET_MS. */
  ACTF("Measuring gross preemption rate (this will take %0.02f sec)...",
       ((double)CTEST_TARGET_MS) / 1000);
  util_perc = measure_preemption(CTEST_TARGET_MS);
  /* Deliver the final verdict. */
  SAYF(cGRA "\n>>> ");
  if (util_perc < 105) {
    SAYF(cLGN "PASS: " cRST "You can probably run additional processes.");
  } else if (util_perc < 130) {
    SAYF(cYEL "CAUTION: " cRST "Your CPU may be somewhat overbooked (%u%%).", util_perc);
  } else {
    SAYF(cLRD "FAIL: " cRST "Your CPU is overbooked (%u%%).", util_perc);
  }
  SAYF(cGRA " <<<" cRST "\n\n");
  return (util_perc > 105) + (util_perc > 130);

#endif /* ^HAVE_AFFINITY */

}

```