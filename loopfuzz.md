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
