### afl-plot 使用指南
---

##### Afl-plot是afl-fuzz的进度绘图实用插件

#### 安装
 sudo apt-get install gunplot
 
#### 使用
 afl-plot <afl_state_dir> <graph_output_dir>
- afl_state_dir是指fuzz后的输出路径 fuzz_out/
- graph_output_dir 是自定义的plot图表输出路径
 其中包含一个index.html和三个PNG图像
 
#### 解析
- total paths增长趋于缓和时，pending favs的数量趋近于零时，fuzzer有新发现的可能性变小
- crashes和hangs 超时和崩溃
- 执行速度的变化
