# afl-fuzz.c源码阅读

## 全局变量的说明

### queue

`queue_entry`是一个静态全局结构体变量。

`static struct queue_entry *queue`是一个链表，afl中用链表存储输入队列，链表queue中的每一个结点表示一个测试用例（testcase）。

afl中的每一个测试用例都是存储在一个文件中，afl将文件中的内容看成字节序列。

```C
struct queue_entry {

  u8* fname;                          /* File name for the test case      */
  u32 len;                            /* Input length                     */

  u8  cal_failed,                     /* Calibration failed?              */
      trim_done,                      /* Trimmed?                         */
      was_fuzzed,                     /* Had any fuzzing done yet?        */
      passed_det,                     /* Deterministic stages passed?     */
      has_new_cov,                    /* Triggers new coverage?           */
      var_behavior,                   /* Variable behavior?               */
      favored,                        /* Currently favored?               */
      fs_redundant;                   /* Marked as redundant in the fs?   */

  u32 bitmap_size,                    /* Number of bits set in bitmap     */
      exec_cksum;                     /* Checksum of the execution trace  */

  u64 exec_us,                        /* Execution time (us)              */
      handicap,                       /* Number of queue cycles behind    */
      depth;                          /* Path depth                       */

  u8* trace_mini;                     /* Trace bytes, if kept             */
  u32 tc_ref;                         /* Trace bytes ref count            */

  struct queue_entry *next,           /* Next element, if any             */
                     *next_100;       /* 100 elements ahead               */

};

static struct queue_entry *queue,     /* Fuzzing queue (linked list)      */
                          *queue_cur, /* Current offset within the queue  */
                          *queue_top, /* Top of the list                  */
                          *q_prev100; /* Previous 100 marker              */

```

### trace_bits

afl使用bitmap存储边缘覆盖情况。具体到afl-fuzz.c这个文件中，就是使用trace_bits这个全局变量存储。具体的定义和初始化情况如下。最终达到的效果，可以看成是设置为`u8* trace_bits`为`u8 trace_bit[2^16]`。所以trace_bit的空间大小就是64kb。

```c
EXP_ST u8* trace_bits;                /* SHM with instrumentation bitmap  *

static void setup_shm(void) {

  u8* shm_str;

  shm_id = shmget(IPC_PRIVATE, MAP_SIZE, IPC_CREAT | IPC_EXCL | 0600);

  if (shm_id < 0) PFATAL("shmget() failed");

  atexit(remove_shm);

  shm_str = alloc_printf("%d", shm_id);

  setenv(SHM_ENV_VAR, shm_str, 1);

  ck_free(shm_str);

  trace_bits = shmat(shm_id, NULL, 0);
  
  if (!trace_bits) PFATAL("shmat() failed");

}
```

那么trace_bit具体是如何存储边缘覆盖情况的呢？

假设有基本块A、基本块B，afl在编译阶段对每个基本块进行插桩，为每个基本块分配了一个在[0,2^16-1]的ID。假设A的ID为a，B的ID为b，afl将A->B这条边缘信息用`a>>1 xor b`表示，将该值记为index，也就是说index代表A->B这条边，将这条边记为`edge-index`。那么`trace_bit[index]`就表示`edge-index`被执行的次数。

### top_rated

`top_rated`是一个数组，数组的容量是MAP_SIZE=2^16。数组中的每一个元素是一个`queue_entry *`类型的指针。top_rated数组的索引同样代表一条边，也就是说，`top_rated`数组的索引和`trace_bits`数组的索引所代表的含义是一致的。

一条边可能被多个testcase执行，而这些testcase的长度和运行时间基本是不同的。`top_rated[index]`表示在众多执行了`edge-index`的testcase中、`长度*运行时间`最短的那个testcase（我们称这个testcase更favored的）。

```c
static struct queue_entry*
  top_rated[MAP_SIZE];                /* Top entries for bitmap bytes     */
```

## update_bitmap_score

```C
/* When we bump into a new path, we call this to see if the path appears
   more "favorable" than any of the existing ones. The purpose of the
   "favorables" is to have a minimal set of paths that trigger all the bits
   seen in the bitmap so far, and focus on fuzzing them at the expense of
   the rest.

   The first step of the process is to maintain a list of top_rated[] entries
   for every byte in the bitmap. We win that slot if there is no previous
   contender, or if the contender has a more favorable speed x size factor. */
//函数的参数是一个testcase
static void update_bitmap_score(struct queue_entry* q) {

  u32 i;
  //fav_factor是一个判断标准，其值为：当前testcase的执行时间x当前case的长度
  //fav_factor值越小越好
  u64 fav_factor = q->exec_us * q->len;

  /* For every byte set in trace_bits[], see if there is a previous winner,
     and how it compares to us. */
  //遍历trace_bits[]中的每一个字节
  for (i = 0; i < MAP_SIZE; i++)
    //如果trace_bits[i]!=0,表示edge-i已经被执行过
    if (trace_bits[i]) {
       //如果top_rated[i]!=NULL
       if (top_rated[i]) {

         /* Faster-executing or smaller test cases are favored. */
         //当前testcase不如top_rated[i]，进行下一次循环
         if (fav_factor > top_rated[i]->exec_us * top_rated[i]->len) continue;

         /* Looks like we're going to win. Decrease ref count for the
            previous winner, discard its trace_bits[] if necessary. 
            top_rated[i]->tc_ref = top_rated[i]->tc_ref-1
            if(top_rated[i]->tc_ref == 0){
            	...
            }
         */
         if (!--top_rated[i]->tc_ref) {
           ck_free(top_rated[i]->trace_mini);
           top_rated[i]->trace_mini = 0;
         }

       }
        
       /* Insert ourselves as the new winner. 
       	  将top_rated[i]设置为当前testcase
       */
       top_rated[i] = q;
       q->tc_ref++;

       //if(q->trace_mini == NULL)
       if (!q->trace_mini) {
         q->trace_mini = ck_alloc(MAP_SIZE >> 3); //结构体u8* trace_mini;
         minimize_bits(q->trace_mini, trace_bits);
       }
	   //Scoring for favorites changed?
       score_changed = 1; 

     }
}
```

函数功能和获取的信息总结：

* 当一个新的testcase、q被执行以后，调用该函数，更新top_rated[]
* `q->tc_ref`表示 q是多少条边的favored
* 如果`q->tc_ref==0`表示top_rated[i]中，没有一个元素的值是q，afl会将q->trace_mini释放掉。
* `q->trace_mini`是一个8kb的bitmap，存储的是q的覆盖信息（q所覆盖的边）

### minimize_bits

因为该函数只被`update_bitmap_score`调用，所以就直接总结在这部分。该函数的定义如下：

```C
/* Compact trace bytes into a smaller bitmap. We effectively just drop the
   count information here. This is called only sporadically, for some
   new paths. 
   参数src：trace_bits
   参数dst：比trace_bist更小的一个bitmap，实际大小是8KB（64KB>>3）
   函数功能：src记录了hit count（每一条边被目前所有输入执行的次数）信息，而dst的目的是记录每条边是否被执行，没有记录hit count。所以可以将src紧凑一下，得到一个更小的bitmap：dst。
*/

static void minimize_bits(u8* dst, u8* src) {

  u32 i = 0;

  while (i < MAP_SIZE) {

    if (*(src++)) dst[i >> 3] |= 1 << (i & 7);
    i++;

  }

}
```

关于这部分函数的解释：

* src（也就是trace_bits）使用1bytes存储一条边的执行次数
* dst（也就是q->trace_mini）则是使用1bit存储一条边是否被执行，0表示没有被执行，1表示被执行。
* 例如，dst[0]的 低位 到 高位 依次表示index为[0,7]的边的执行情况。
* 假设dst[0] = 0000 0101b，表示`edge-0`、`edge-2`被执行了。

函数`update_bitmap_score`调用该函数，afl将q这个testcase覆盖的所有边存储在了q->trace_mini这个大小为8kb的bitmap中（注意，不存储执行次数，只存储是否被执行）

```
  minimize_bits(q->trace_mini, trace_bits);
```

## cull_queue

这个是在精简输入的测试用例

```C
/* The second part of the mechanism discussed above is a routine that
   goes over top_rated[] entries, and then sequentially grabs winners for
   previously-unseen bytes (temp_v) and marks them as favored, at least
   until the next run. The favored entries are given more air time during
   all fuzzing steps. 
   函数功能：精简队列。简而言之，就是从当前的输入队列集合set中选出一个子集subset，使得执行subset达到的覆盖率和执行set达到的覆盖率相同。
*/

static void cull_queue(void) {

  struct queue_entry* q;
  //temp_v的定义方式和q->trace_mini的定义方式类似
  static u8 temp_v[MAP_SIZE >> 3];
  u32 i;

  //dumb_mode下是没有插桩的
  //score_changed = 0表示top_rated[]和trace_bits[]都没有改变，也就没有必要进行此步骤
  if (dumb_mode || !score_changed) return;

  score_changed = 0;
 
  //将temp_v的所有字节的所有位都设置位1
  //temp_v队列中所有的输入的覆盖的边的情况，1表示还没有被覆盖，0表示已经被覆盖。
  memset(temp_v, 255, MAP_SIZE >> 3);
  
  //subset集合元素的数量，初始值位0
  queued_favored  = 0;
  pending_favored = 0;

  q = queue;

  //将输入队列中，所有的q->favored设置位0
  while (q) {
    q->favored = 0;
    q = q->next;
  }

  /* Let's see if anything in the bitmap isn't captured in temp_v.
     If yes, and if it has a top_rated[] contender, let's use it. */

  for (i = 0; i < MAP_SIZE; i++)
    //temp_v[i >> 3] & (1 << (i & 7)))==1表示edge-i还没有被之前遍历的输入覆执行
    //top_rated[i] != NULL 表示edge-i被队列中的输入执行，被top_rated[i]执行过
    if (top_rated[i] && (temp_v[i >> 3] & (1 << (i & 7)))) {

      u32 j = MAP_SIZE >> 3;

      /* Remove all bits belonging to the current entry from temp_v. */
      //top_rated[i]执行过的边，从temp_v[]中移除（通过设置对应的值为0进行移除）
      while (j--) 
        if (top_rated[i]->trace_mini[j])
          temp_v[j] &= ~top_rated[i]->trace_mini[j];
	  //top_rated[i]这个输入被认为是favored的
      top_rated[i]->favored = 1;
      queued_favored++;

      if (!top_rated[i]->was_fuzzed) pending_favored++;
    }
    

  q = queue;

  while (q) {
    //标记为多余的
    mark_as_redundant(q, !q->favored);
    q = q->next;
  }

}
```

### mark_as_redundant

不太懂标记的这波操作，q->fs_redundant的含义是什么？？？不是很清楚

```c
/* Mark / unmark as redundant (edge-only). This is not used for restoring state,
   but may be useful for post-processing datasets. */

static void mark_as_redundant(struct queue_entry* q, u8 state) {

  u8* fn;
  s32 fd;
  //q->fs_redundant:Marked as redundant in the fs
  if (state == q->fs_redundant) return;

  q->fs_redundant = state;
  //The strrchr() function returns a pointer to the last occurrence of the character c in the string s.
  fn = strrchr(q->fname, '/');
  //fn+1指向的输入文件（不是输入目录，afl中，每一个测试用例都单独放在一个文件中）的名字
  //返回的是一个指针，指向了一串字符串，字符串的内容是参数里的内容
  fn = alloc_printf("%s/queue/.state/redundant_edges/%s", out_dir, fn + 1);

  if (state) {
    //mode = 0600，表示文件所有者具有读写权限
    //flag = 以只写的方式打开文件，如果文件不存在，则创建文件
    fd = open(fn, O_WRONLY | O_CREAT | O_EXCL, 0600);
    if (fd < 0) PFATAL("Unable to create '%s'", fn);
    close(fd);

  } else {
    //unlink：Call the unlink function to remove the specified FILE
    if (unlink(fn)) PFATAL("Unable to remove '%s'", fn);

  }
  //ck_free，带有check error的free。
  ck_free(fn);
}
```

