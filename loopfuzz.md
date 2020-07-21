### CWE-1050:循环内过多的平台资源消耗

URL：https://cwe.mitre.org/data/definitions/1050.html

 该软件具有一个循环主体或循环条件，其中包括一个控制元素，该控制元素直接或间接消耗平台资源。该问题会让软件执行速度变慢，如果攻击者可以影响循环中的迭代次数，则可能会出现DOS问题。

---

### CWE-606:循环条件输入未经检查

URL:https://cwe.mitre.org/data/definitions/606.html

程序没有正确检查用于循环条件的输入，可能由于过度循环而导致拒绝服务或其他后果。
 e1:iterate函数里的for循环，循环条件取决于用户输入，所以可以随便决定循环次数，存在危险。
``` c
 void iterate(int n){
int i;
for (i = 0; i < n; i++){
foo();
}
}
void iterateFoo()
{
unsigned int num;
scanf("%u",&num);
iterate(num);
}
```

 e2:在下面的C/C++示例中，方法processMessageFromSocket（）将从套接字获取一条消息，并将其放入缓冲区中，并将缓冲区的内容解析为包含消息长度和消息正文的结构。for循环将消息征文复制到本地字符串中，该字符串将传递给另一种方法进行处理。但是，来自结构的消息长度变量用作结束for循环的条件，而无需验证消息长度变量是否准确反映了消息正文的长度。如果消息长度变量指示的长度大于消息主体的长度，则可能会通过从内存读取超过缓冲区范围的缓冲区来导致缓冲区over-read。

``` c
int processMessageFromSocket(int socket) {
int success;

char buffer[BUFFER_SIZE];
char message[MESSAGE_SIZE];

// get message from socket and store into buffer

//Ignoring possibliity that buffer > BUFFER_SIZE
if (getMessage(socket, buffer, BUFFER_SIZE) > 0) {

// place contents of the buffer into message structure
ExMessage *msg = recastBuffer(buffer);

// copy message body into string for processing
int index;
for (index = 0; index < msg->msgLength; index++) {
message[index] = msg->msgBody[index];
}
message[index] = '\0';

// process message
success = processMessage(message);
}
return success;
}
```
---

### CWE-835:无法到达退出条件的循环（无限循环）

URL：https://cwe.mitre.org/data/definitions/835.html 

 该程序包含具有无法达到的退出条件的迭代或循环，如果循环受到攻击者的影响，则此弱点可能被消耗过多的资源，例如CPU或内存。

e1:下面的代码中，方法processMessagesFromServer尝试建立与服务器的连接，从服务器读取和处理信息，该方法使用do/while循环在尝试失败时继续建立与服务器的连接。但是如果服务器不响应，则会创建无限循环，此无限循环将消耗系统资源，并可能产生DOS攻击。要解决该问题，应使用计数器来限制尝试建立与服务器的连接的次数。
``` c
int processMessagesFromServer(char *hostaddr, int port) {
...
int servsock;
int connected;
struct sockaddr_in servaddr;

// create socket to connect to server
servsock = socket( AF_INET, SOCK_STREAM, 0);
memset( &servaddr, 0, sizeof(servaddr));
servaddr.sin_family = AF_INET;
servaddr.sin_port = htons(port);
servaddr.sin_addr.s_addr = inet_addr(hostaddr);

do {

// establish connection to server
connected = connect(servsock, (struct sockaddr *)&servaddr, sizeof(servaddr));

// if connected then read and process messages from server
if (connected > -1) {

// read and process messages
...
}

// keep trying to establish connection to the server
} while (connected < 0);

// close socket and return success or failure
...
}
```

---
### CWE-1095：循环中的条件值在循环中更新

 URL：https://cwe.mitre.org/data/definitions/1095.html
 系统中使用了一个循环，该循环的控制流条件基于在循环体内更新的值。这个问题让理解和维护软件变得更加困难，修复漏洞会变得更加困难，从而间接影响了安全性。

---


### 汇编语言的For循环实现：？

for(){}:可以分为四个部分：初始化语句，条件语句，主体后续语句和供循环重复执行的主体
 在汇编代码中按下面的顺序排列：
  - 1.初始化语句； 然后跳转到3
  - 2.后续工作语句；
  - 3.条件语句； 条件不满足时跳转到5
  - 4.循环体内部主体； 然后跳转到2
  - 5.循环体外执行后面的代码

``` c
for(i=0;i<length;i++){
   ???
}
```

初始化语句 i=0
``` c
  mov [address_i],0      //设定i=0
  jmp address_ifjudge  //跳转到条件判断语句
```

后续语句 i++ （地址为address_continue）
``` c
  mov ecx,[address_i]
  add ecx,1
  mov [address_i],ecx //i=i+1;
```

条件判读语句 i<length （地址为address_ifjudge）

``` c
  mov edx,[address_i] 
  cmp edx,[address_length]   //比较i和length的大小
  jge address_out  //如果i>=length 则直接跳出循环 
```

循环主体部分

``` c
  ???
  jmp address_continue //跳转到i++处
```

---

 是自己开发？还是在AFL/？的基础上修改？
 在AFL/fuzzer的基础上修改：
  1.插桩。我们修改插桩的哪一部分？对Loop部分要着重做什么吗？这部分源码应该位于afl-as.h中
  ##### afl插桩参考资料：  
  - https://muzibing.github.io/2019/09/07/2019.09.07%EF%BC%8880%EF%BC%89/
  - 

  2.判断某条路径是不是我们favourite的。
    update_bitmap_score();
    save_if_interesting();
  3.种子的变异策略需不需要修改？我们需不需要在静态分析的时候获取循环条件的信息，然后定向的进行变异？fuzz_one();
  4.对种子的评分标准？（测试用例执行的时间*测试用例的长度）/路径长度*危险函数系数
   calculate_score()

 自己开发：
 一个最简单的fuzz器至少要有两个组件：变异引擎和执行引擎
 还需要插桩吗？
 用什么语言做开发？ C/C++ Rust Go还是python
  ##### python开发fuzzer资料：
   - https://h0mbre.github.io/Fuzzing-Like-A-Caveman/#
   - https://bbs.pediy.com/thread-259382.htm
   - https://bbs.pediy.com/thread-259397.htm

---

  AFL-fast是在AFL的基础上修改的。修改：大多数生成的输入都使用相同的“高频”路径，并且开发了趋向于低频路径的策略，在相同的时间内出发更多的程序行为。设计了几种**搜索策略**，这些策略决定了应该以何种顺序对种子进行模糊处理，并且通过功率调度调节了对种子进行模糊测试所花费的时间。种子产生投入的数量，即种子的能量。

---

calculate_score()评分：
``` c
/* Calculate case desirability score to adjust the length of havoc fuzzing.
   A helper function for fuzz_one(). Maybe some of these constants should
   go into config.h. */

static u32 calculate_score(struct queue_entry* q) {

  u32 avg_exec_us = total_cal_us / total_cal_cycles;
  u32 avg_bitmap_size = total_bitmap_size / total_bitmap_entries;
  u32 perf_score = 100;

  /* Adjust score based on execution speed of this path, compared to the
     global average. Multiplier ranges from 0.1x to 3x. Fast inputs are
     less expensive to fuzz, so we're giving them more air time. */
//路径的执行速度？
  if (q->exec_us * 0.1 > avg_exec_us) perf_score = 10;
  else if (q->exec_us * 0.25 > avg_exec_us) perf_score = 25;
  else if (q->exec_us * 0.5 > avg_exec_us) perf_score = 50;
  else if (q->exec_us * 0.75 > avg_exec_us) perf_score = 75;
  else if (q->exec_us * 4 < avg_exec_us) perf_score = 300;
  else if (q->exec_us * 3 < avg_exec_us) perf_score = 200;
  else if (q->exec_us * 2 < avg_exec_us) perf_score = 150;

  /* Adjust score based on bitmap size. The working theory is that better
     coverage translates to better targets. Multiplier from 0.25x to 3x. */
 //根据位图大小调整分数

  if (q->bitmap_size * 0.3 > avg_bitmap_size) perf_score *= 3;
  else if (q->bitmap_size * 0.5 > avg_bitmap_size) perf_score *= 2;
  else if (q->bitmap_size * 0.75 > avg_bitmap_size) perf_score *= 1.5;
  else if (q->bitmap_size * 3 < avg_bitmap_size) perf_score *= 0.25;
  else if (q->bitmap_size * 2 < avg_bitmap_size) perf_score *= 0.5;
  else if (q->bitmap_size * 1.5 < avg_bitmap_size) perf_score *= 0.75;

  /* Adjust score based on handicap. Handicap is proportional to how late
     in the game we learned about this path. Latecomers are allowed to run
     for a bit longer until they catch up with the rest. */
//handicap 障碍、阻碍
  if (q->handicap >= 4) {

    perf_score *= 4;
    q->handicap -= 4;

  } else if (q->handicap) {

    perf_score *= 2;
    q->handicap--;

  }
```

---
### AFL-fast
 马尔可夫链：下一个状态的概率分布只由当前状态决定，在时间序列中它前面的事件都和他无关。
 AFL-fast对AFL的源码进行改进的部分分析：
  Search Strategy（搜索策略）：
- s(i)优先：种子t(i)之前在队列中选到的次数。
- f(i)优先：表示执行状态为i的生成的输入数量（fuzz频率）。
  代码位置afl-fuzz.c-->1248行：
``` c
  static void update_bitmap_score(struct queue_entry* q) {

  u32 i;
  u64 fuzz_p2      = next_p2 (q->n_fuzz);
  u64 fav_factor = q->exec_us * q->len;

  /* For every byte set in trace_bits[], see if there is a previous winner,
     and how it compares to us. */

  for (i = 0; i < MAP_SIZE; i++)

    if (trace_bits[i]) {

       if (top_rated[i]) {
         u64 top_rated_fuzz_p2    = next_p2 (top_rated[i]->n_fuzz);
         u64 top_rated_fav_factor = top_rated[i]->exec_us * top_rated[i]->len;
         if (fuzz_p2 > top_rated_fuzz_p2) continue;
         else if (fuzz_p2 == top_rated_fuzz_p2) {

           if (fav_factor > top_rated_fav_factor) continue;

         }

         /* Looks like we're going to win. Decrease ref count for the
            previous winner, discard its trace_bits[] if necessary. */

         if (!--top_rated[i]->tc_ref) {
           ck_free(top_rated[i]->trace_mini);
           top_rated[i]->trace_mini = 0;
         }
       }
       /* Insert ourselves as the new winner. */

       top_rated[i] = q;
       q->tc_ref++;

       if (!q->trace_mini) {
         q->trace_mini = ck_alloc(MAP_SIZE >> 3);
         minimize_bits(q->trace_mini, trace_bits);
       }
       score_changed = 1;
     }
}
```
 Power Schedule（能量表）：
 afl-fuzz.c-->100行、4765行、7992行、8029行
``` c
static u8 schedule = 0;               /* Power schedule (default: FAST)   */
enum {
  /* 00 */ FAST,                      /* Exponential schedule             */
  /* 01 */ COE,                       /* Cut-Off Exponential schedule     */
  /* 02 */ EXPLORE,                   /* Exploration-based constant sch.  */
  /* 03 */ LIN,                       /* Linear schedule                  */
  /* 04 */ QUAD,                      /* Quadratic schedule               */
  /* 05 */ EXPLOIT                    /* AFL's exploitation-based const.  */
};
```
- Exploitation-based constant schedule (EXPLOIT)：
**p(i)=α(i)**,其中$α(i)$是算法中assignEnergy的实现，AFL根据exec_us、bitmap_size、handicap、depth计算的score
- Exploration-based constant schedule (EXPLORE):
**p(i)=\frac {α(i)}{β}** ，其中α(i)是afl原本的score计算结果，β>1 是一个常数
- Cut-Off Exponential (COE)：指数截断
其中α(i)保持模糊的原始判断，β>1是一个常数，s(i)值较低，μ是执行已发现路径的模糊平均数，且\frac {\sum _{i\in S^+}f(i)}{S^+}是发现的路径集合，直观的说，f(i)>μ为高频路径，即使从模糊其他种子接收大量模糊，也被视为低优先级，直到它们再次低于平均值才模糊。常数M提供了每次模糊迭代生成的输入数量的上限。
- Exponential schedule (FAST) ：快速截断
p(i)=(\frac {α(i)}{β} \frac {2^{s(i)}}{f(i)},M)
当 f(i)>μ 时，Power Schedule不会使$t_i$模糊，而是使t(i)和执行路径t(i)的模糊f(i)成反比，分母中的f(i)利用过去没有收到大量模糊的t(i)，因此更可能位于低频区域，这样，s(i)的指数增长允许越来越多的能量用于低频路径。（就是输入队列中选择的t(i)输入次数越少，执行路径i就越少，看代码发现这个数就是该种子被fuzz的轮数，一般比较小，所以放在指数上，赋予低频路径越多的能量值，让它多变异）
- Linear schedule (LINEAR)：线性规划
**p(i)=(\frac {α(i)}{β} \frac {s(i)}{f(i)},M)**
- Quadratic schedule (QUAD)：二次规划
**p(i)=(\frac {α(i)}{β} \frac {s(i)^2}{f(i)},M)**
对于每个种子输入fuzz的次数，在AFL原有计算结果的基础上，再乘以一个以指数增长的系数，然后设定一个最大值M，如果超过了这个最大值，进行截断。

通过能量表的策略，AFLFast能智能地控制种子fuzz次数，从而使队列调度给予低频路径更多机会。
``` c
   u64 fuzz = q->n_fuzz;
  u64 fuzz_total;

  u32 n_paths, fuzz_mu;
  u32 factor = 1;

  switch (schedule) {

    case EXPLORE: 
      break;

    case EXPLOIT:
      factor = MAX_FACTOR;
      break;

    case COE:
      fuzz_total = 0;
      n_paths = 0;

      struct queue_entry *queue_it = queue;	
      while (queue_it) {
        fuzz_total += queue_it->n_fuzz;
        n_paths ++;
        queue_it = queue_it->next;
      }

      fuzz_mu = fuzz_total / n_paths;
      if (fuzz <= fuzz_mu) {
        if (q->fuzz_level < 16)
          factor = ((u32) (1 << q->fuzz_level));
        else 
          factor = MAX_FACTOR;
      } else {
        factor = 0;
      }
      break;
    
    case FAST:
      if (q->fuzz_level < 16) {
         factor = ((u32) (1 << q->fuzz_level)) / (fuzz == 0 ? 1 : fuzz); 
      } else
        factor = MAX_FACTOR / (fuzz == 0 ? 1 : next_p2 (fuzz));
      break;

    case LIN:
      factor = q->fuzz_level / (fuzz == 0 ? 1 : fuzz); 
      break;

    case QUAD:
      factor = q->fuzz_level * q->fuzz_level / (fuzz == 0 ? 1 : fuzz);
      break;

    default:
      PFATAL ("Unkown Power Schedule");
  }
  if (factor > MAX_FACTOR) 
    factor = MAX_FACTOR;

  perf_score *= factor / POWER_BETA;
```
---
``` c
      case 'p': /* Power schedule */
        if (!stricmp(optarg, "fast")) {
          schedule = FAST;
        } else if (!stricmp(optarg, "coe")) {
          schedule = COE;
        } else if (!stricmp(optarg, "exploit")) {
          schedule = EXPLOIT;
        } else if (!stricmp(optarg, "lin")) {
          schedule = LIN;
        } else if (!stricmp(optarg, "quad")) {
          schedule = QUAD;
        } else if (!stricmp(optarg, "explore")) {
          schedule = EXPLORE;
        }
        break;
```
---
``` c
  switch (schedule) {
    case FAST:    OKF ("Using exponential power schedule (FAST)"); break;
    case COE:     OKF ("Using cut-off exponential power schedule (COE)"); break;
    case EXPLOIT: OKF ("Using exploitation-based constant power schedule (EXPLOIT)"); break;
    case LIN:     OKF ("Using linear power schedule (LIN)"); break;
    case QUAD:    OKF ("Using quadratic power schedule (QUAD)"); break;
    case EXPLORE: OKF ("Using exploration-based constant power schedule (EXPLORE)"); break;
    default : FATAL ("Unkown power schedule"); break;
```