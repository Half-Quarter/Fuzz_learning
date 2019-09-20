---
afl-fuzzing
---

### afl是什么？fuzzing是什么？
- 模糊测试（Fuzzing）技术是漏洞挖掘最有效的手段之一，本质是依赖随机函数生成随机测试用例。
- AFL、LibFuzzer、honggfuzz等操作简单友好的工具相继出现，极大地降低了模糊测试的门槛。
- AFL是一款模糊测试工具，通过记录输入样本的代码覆盖率，从而调整输入样本以提高覆盖率，增加发现漏洞的概率。

### afl的工作流程：
1.从源码编译程序时进行插桩，以记录代码覆盖率；

​      (插桩是在保证被测程序原有逻辑完整性的基础上插入探针，获取程序控制流和数据流信息)

   （代码覆盖率是一种度量代码的覆盖程度的方式，也就是指源代码中的某行代码是否已执行；对二进制程序，可理解为汇编代码中的某条指令是否已执行。）
2.选择一些输入文件，作为初始测试集加入输入队列；
3.将队列中的文件按一定的策略进行“突变”；
4.如果经过变异文件更新了覆盖范围，则将其保留添加到队列中;
5.上述过程会一直循环进行，期间触发了crash的文件会被记录下来。

### 选择测试的目标：
1.AFL主要用于C/C++程序的测试
2.AFL既可以对源码进行编译时插桩，也可以使用AFL的QEMU mode对二进制文件进行插桩，但是前者的效率相对来说要高很多。
3.目标应该是该软件的最新版本
4.如果某个程序曾曝出过多次漏洞，那么该程序有仍有很大可能存在未被发现的安全漏洞。

### 构建语料库：
 AFL需要一些初始输入数据（也叫种子文件）作为Fuzzing的起点，这些输入可以是随意输入的毫无意义的数据，AFL可以通过启发式算法自动确定文件格式结构。
 选择语料库：
   - 有效的输入：尽管有时候无效输入会产生bug和崩溃，但有效输入可以更快的找到更多执行路径。
   - 尽量小的体积：较小的文件会不仅可以减少测试和处理的时间，也能节约更多的内存，AFL给出的建议是最好小于1 KB

### 构建被测试程序：
 AFL从源码编译程序时进行插桩，以记录代码覆盖率。这个工作需要使用其提供的两种编译器的wrapper编译目标程序，和普通的编译过程没有太大区别
 (1)afl-gcc模式：
 直接修改Makefile文件中的编译器为afl-gcc/g++也行。
```
 $ ./configure CC="afl-gcc" CXX="afl-g++"
```
编译：

afl-gcc -g -o afl_test afl_test.c'

 (2)LLVM模式
 LLVM Mode模式编译程序可以获得更快的Fuzzing速度，进入llvm_mode目录进行编译，之后使用afl-clang-fast构建序程序:

```
 $ cd llvm_mode
 $ apt-get install clang
 $ export LLVM_CONFIG=`which llvm-config` && make && cd ..
 $ ./configure --disable-shared CC="afl-clang-fast" CXX="afl-clang-fast++" 
```

### 开始Fuzzing:
 1.白盒测试
  （测试插桩程序）可以选择使用afl-showmap跟踪单个输入的执行路径，并打印程序执行的输出、捕获的元组
              使用不同的输入，正常情况下afl-showmap会捕获到不同的tuples，这就说明我们的的插桩是有效的。	执行fuzzer程序：
	之后就可以执行afl-fuzz了，通常的格式是：
`$ afl-fuzz -i testcase_dir -o findings_dir /path/to/program [params]`
    或者使用“@@”替换输入文件，Fuzzer会将其替换为实际执行的文件
`$ afl-fuzz -i testcase_dir -o findings_dir /path/to/program @@`

 2.黑盒测试
    就是对没有源代码的程序进行测试，这时就要用到AFL的QEMU模式了。启用方式和LLVM模式类似，也要先编译。
	（这里qemu的安装可能会在Ubuntu上报错）
	安装之后添加-Q选项即可使用QEMU模式进行Fuzzing。

```
 $ afl-fuzz -Q -i testcase_dir -o findings_dir /path/to/program [params] @@
```

### AFL状态窗口
 (1) Process timing:Fuzzer运行时长、以及距离最近发现的路径、崩溃和挂起经过了多长时间。
 (2) Overall results：Fuzzer当前状态的概述。
 (3) Cycle progress：我们输入队列的距离。
 (4) Map coverage：目标二进制文件中的插桩代码所观察到覆盖范围的细节。
 (5) Stage progress：Fuzzer现在正在执行的文件变异策略、执行次数和执行速度。
 (6) Findings in depth：有关我们找到的执行路径，异常和挂起数量的信息。
 (7) Fuzzing strategy yields：关于突变策略产生的最新行为和结果的详细信息。
 (8) Path geometry：有关Fuzzer找到的执行路径的信息。
 (9) CPU load：CPU利用率

### fuzzier工作状态
 因为afl-fuzz永远不会停止，所以何时停止测试很多时候就是依靠afl-fuzz提供的状态来决定的。
 （1）状态窗口中”cycles done”字段颜色变为绿色该字段的颜色可以作为何时停止测试的参考，随着周期数不断增大，其颜色也会由洋红色，逐步变为黄色、蓝色、绿色。当其变为绿色时，继续Fuzzing下去也很难有新的发现了，这时便可以通过Ctrl-C停止afl-fuzz。
 （2）目标程序的代码几乎被测试用例完全覆盖，这种情况好像很少见，但是对于某些小型程序应该还是可能的.
 （3）距上一次发现新路径（或崩溃）已经过去很长时间了。



### 相关链接

安装和测试：https://stfpeak.github.io/2017/06/11/Finding-bugs-using-AFL/

Fuzzing技术总结：https://blog.csdn.net/wcventure/article/details/82085251#commentBox

Qemu-mode安装bug的fix：https://www.mail-archive.com/debian-bugs-dist@lists.debian.org/msg1643066.html

