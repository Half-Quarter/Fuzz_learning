
```
 virgin_bits[MAP_SIZE],     /* 没有被模糊测试修改的区域 */
 virgin_tmout[MAP_SIZE],    /* 我们没有在tmout中看到的bit  */
 virgin_crash[MAP_SIZE];    /* 我们没有在crash中看到的bit  */
```

``` c
/* Check if the result of an execve() during routine fuzzing is interesting, save or queue the input test case for further analysis if so. Returns 1 if entry is saved, 0 otherwise. */
//检查在fuzz期间 execve ()的结果是否感有趣，保存或排队输入测试用例，以便进一步分析。 如果保存，则返回1，否则返回0。
static u8 save_if_interesting(char** argv, void* mem, u32 len, u8 fault) {
  u8  *fn = "";
  u8  hnb;
  s32 fd;
  u8  keeping = 0, res;
//如果属于crash模式
  if (fault == crash_mode) {

    /* Keep only if there are new bits in the map, add to queue for
       future fuzzing, etc. */
  //如果
    if (!(hnb = has_new_bits(virgin_bits))) {
      if (crash_mode) total_crashes++;
      return 0;
    }    

#ifndef SIMPLE_FILES

    fn = alloc_printf("%s/queue/id:%06u,%s", out_dir, queued_paths,
                      describe_op(hnb));

#else

    fn = alloc_printf("%s/queue/id_%06u", out_dir, queued_paths);

#endif /* ^!SIMPLE_FILES */
    //添加新的测试用例到队列中
    add_to_queue(fn, len, 0);
   
    if (hnb == 2) {
      queue_top->has_new_cov = 1;
      queued_with_cov++;
    }
    //当前队列的测试用例的校验和计算
    queue_top->exec_cksum = hash32(trace_bits, MAP_SIZE, HASH_CONST);

    /* Try to calibrate inline; this also calls update_bitmap_score() when successful. */

    res = calibrate_case(argv, queue_top, mem, queue_cycle - 1, 0);

    if (res == FAULT_ERROR)
      FATAL("Unable to execute target application");

    fd = open(fn, O_WRONLY | O_CREAT | O_EXCL, 0600);
    if (fd < 0) PFATAL("Unable to create '%s'", fn);
    ck_write(fd, mem, len, fn);
    close(fd);

    keeping = 1;

  }

  switch (fault) {

    case FAULT_TMOUT:

 
      /* 引起超时的样本并不令人感兴趣，但是我们仍然要保存一些样本，我们使用挂起map中的新作用位作为唯一信号，在dumb模式，我们保留所有东西 */
      total_tmouts++;

      if (unique_hangs >= KEEP_UNIQUE_HANG) return keeping;

      if (!dumb_mode) {

#ifdef __x86_64__
        simplify_trace((u64*)trace_bits);
#else
        simplify_trace((u32*)trace_bits);
#endif /* ^__x86_64__ */

        if (!has_new_bits(virgin_tmout)) return keeping;

      }

      unique_tmouts++;

      /* Before saving, we make sure that it's a genuine hang by re-running the target with a more generous timeout (unless the default timeout is already generous). */

      if (exec_tmout < hang_tmout) {

        u8 new_fault;
        write_to_testcase(mem, len);
        new_fault = run_target(argv, hang_tmout);

        /* A corner case that one user reported bumping into: increasing the timeout actually uncovers a crash. Make sure we don't discard it if
 so. */

        if (!stop_soon && new_fault == FAULT_CRASH) goto keep_as_crash;

        if (stop_soon || new_fault != FAULT_TMOUT) return keeping;

      }

#ifndef SIMPLE_FILES

      fn = alloc_printf("%s/hangs/id:%06llu,%s", out_dir,
                        unique_hangs, describe_op(0));

#else

      fn = alloc_printf("%s/hangs/id_%06llu", out_dir,
                        unique_hangs);

#endif /* ^!SIMPLE_FILES */

      unique_hangs++;

      last_hang_time = get_cur_time();

      break;

    case FAULT_CRASH:

keep_as_crash:

      /* This is handled in a manner roughly similar to timeouts,
         except for slightly different limits and no need to re-run test
         cases. */

      total_crashes++;

      if (unique_crashes >= KEEP_UNIQUE_CRASH) return keeping;

      if (!dumb_mode) {

#ifdef __x86_64__
        simplify_trace((u64*)trace_bits);
#else
        simplify_trace((u32*)trace_bits);
#endif /* ^__x86_64__ */

        if (!has_new_bits(virgin_crash)) return keeping;

      }

      if (!unique_crashes) write_crash_readme();

#ifndef SIMPLE_FILES

      fn = alloc_printf("%s/crashes/id:%06llu,sig:%02u,%s", out_dir,
                        unique_crashes, kill_signal, describe_op(0));

#else

      fn = alloc_printf("%s/crashes/id_%06llu_%02u", out_dir, unique_crashes,
                        kill_signal);

#endif /* ^!SIMPLE_FILES */

      unique_crashes++;

      last_crash_time = get_cur_time();
      last_crash_execs = total_execs;

      break;

    case FAULT_ERROR: FATAL("Unable to execute target application");

    default: return keeping;

  }

  /* If we're here, we apparently want to save the crash or hang
     test case, too. */

  fd = open(fn, O_WRONLY | O_CREAT | O_EXCL, 0600);
  if (fd < 0) PFATAL("Unable to create '%s'", fn);
  ck_write(fd, mem, len, fn);
  close(fd);

  ck_free(fn);

  return keeping;

}
```

 其中涉及的重要函数
---
```c
/* 检查当前执行路径是否给表带来了新的东西。
    更新原始位以反映发现。 如果唯一的变化是特定元组的命中数，则返回1。返回2，如果看到新的元组，更新map，因此后续调用将始终返回0。
    在相当大的缓冲区中的每个exec（）之后调用此函数，因此它需要快速。 我们以32位和64位版本进行此操作。 */

static inline u8 has_new_bits(u8* virgin_map) {
// 32/64位系统
#ifdef __x86_64__

  u64* current = (u64*)trace_bits;
  u64* virgin  = (u64*)virgin_map;

  u32  i = (MAP_SIZE >> 3);

#else

  u32* current = (u32*)trace_bits;
  u32* virgin  = (u32*)virgin_map;

  u32  i = (MAP_SIZE >> 2);

#endif /* ^__x86_64__ */

  u8   ret = 0;

  while (i--) {

    /* Optimize for (*current & *virgin) == 0 - i.e., no bits in current bitmap that have not been already cleared from the virgin map - since this will almost always be the case. */
 //使用unlikely()说明执行else的可能性大 使用likely()说明执行if的可能性大，目的是提高系统的运行速度
    //current和virgin按位与
    if (unlikely(*current) && unlikely(*current & *virgin)) {
       //如果返回值小于2
      if (likely(ret < 2)) {

        u8* cur = (u8*)current;
        u8* vir = (u8*)virgin;

     /* 看起来我们还没有找到任何新的字节； 查看current []中的任何非零字节是否在virgin []中是原始的。 */

#ifdef __x86_64__
  //64位中cur和vir的任何对应一位若都为FF 则返回2 否则返回1
        if ((cur[0] && vir[0] == 0xff) || (cur[1] && vir[1] == 0xff) ||
            (cur[2] && vir[2] == 0xff) || (cur[3] && vir[3] == 0xff) ||
            (cur[4] && vir[4] == 0xff) || (cur[5] && vir[5] == 0xff) ||
            (cur[6] && vir[6] == 0xff) || (cur[7] && vir[7] == 0xff)) 
            ret = 2;
        else ret = 1;

#else
  //32位中cur和vir的前四对应位若为FF 则返回2 否则返回1
        if ((cur[0] && vir[0] == 0xff) || (cur[1] && vir[1] == 0xff) ||
            (cur[2] && vir[2] == 0xff) || (cur[3] && vir[3] == 0xff))
            ret = 2;
        else ret = 1;

#endif /* ^__x86_64__ */

      }
      //virgin和current按位与后把结果存储到virgin里
      *virgin &= ~*current;
    }
    current++;
    virgin++;
  }
  //如果返回值不为0且
  if (ret && virgin_map == virgin_bits) bitmap_changed = 1;
  return ret;

}
```