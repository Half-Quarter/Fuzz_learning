
  为了提升AFL-FUZZ的工作效率，可以采用LLVM模式使用afl-fast-clang & afl-fast-clang++ 取代a f l-gcc进行插桩。
### 下载源码包
  - cfe
  - clang-tools-extra
  - compiler-rt
  - llvm

### 解压文件
```
 xz -d filename.tar.xz
 tar xvf filename.tar
```

### 整合文件
```
 mv cfe-3.5.2.src clang
 mv clang llvm-3.5.2.src/tools
 mv clang-tools-extra-3.5.2.src extra
 mv extra/ llvm-3.5.2.src/tools/clang/
 mv compiler-rt-3.5.2.src compiler-rt
 mv compiler-rt llvm-3.5.2.src/projects/
```

### 编译并安装（这一步很长）
```
 mkdir build
 cd build/
 ../llvm-3.5.2.src/configure --enable-optimized --enable-targets=host-only
 make -j 4
 make install
```

### 回到afl-fuzz重新编译llvm模块
```
 cd afl/
 cd llvm_mode/
 make
 make install
```

