# FDexDump

基于Frida的Android脱壳机

核心参考 https://github.com/hluwa/FRIDA-DEXDump 

为了学习和适配我自己的手机版本以及Frida版本重新开了一个版本。

## 逻辑

### 具体的检索流程

1.遍历当前进程所有可以读的内存段 

2.判断所谓的内存段到底是不是dex

3.把文件dump下来


#### 1.检索遍历进程内存


使用函数 `Process.enumerateRanges('r--')` 枚举读出可以读出的内存区块

这个函数返回一个列表 我们可以遍历这个内存区块列表 

找出基址和内存大小 



#### 2.过滤内存区块


`Memory.scanSync`函数可以加载内存区块传入 基址 大小 第三个参数是 过滤大小

使用正则过滤加载自己需要的大小

比如这个"64 65 78 0a 30 ?? ?? 00" 的意思就是 只加载这个区间的内存 也就是所谓的dex内存地址


#### 3.检索遍历进程内存

开始过滤符合要求的dex

过滤掉系统的dex文件

```js
if (range.file && range.file.path
                        && (range.file.path.startsWith("/data/dalvik-cache/") ||
                            range.file.path.startsWith("/system/"))) {
                        return;
                    }

```

我们这里只过滤一下就是大小要大于0x70，为什么呢 因为dex head大小就是0x70


```js
function verify_dex(dex_ptr, range) {
    if (range != null) {
        var range_end = range.base.add(range.size);
        // verify header_size 
        if (dex_ptr.add(0x70) > range_end) {
            return false;
        }
        // 这里+0x3C 是 string_ids_off， 也就是 string_ids 段的偏移位置 这里的值要正好等于0x70
        return dex_ptr.add(0x3C).readUInt() === 0x70;
    }
    return false;
}

```

#### 4.返回真正的dex文件地址和大小

前面已经拿到了想要的内存开始地址，但是dex的大小还是没有拿到

这个dex文件大小需要额外的获取

在header头信息里面的0x20字段写了dex文件大小

直接读取即可

var dex_size = dex_ptr.add(0x20).readUInt();

## 运行环境(供参考)

电脑系统: win10 

Frida版本: 14.7

手机信息: Android9.0 miui12.0 已经ROOT

## 测试通过的壳版本

1.梆梆加固


