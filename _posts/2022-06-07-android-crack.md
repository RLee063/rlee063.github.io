---
layout: post
title: "第一次破解 APP 小记"
tag: note
---

| 之前打比赛做题也很少做到安卓的逆向题，pwn 更是几乎没有。不过应朋友之请，看了一下两个 APP，没有特别的加固还是很好处理的。本帖内容仅供学习交流使用。

- [com.eleven.gage\*\*\*\*roid](#comelevengageroid)
- [com.anto\*\*\*bert.acti\*\*\*rite [old version]](#comantobertactirite-old-version)
- [com.anto\*\*\*bert.acti\*\*\*rite](#comantobertactirite)
- [附录：破解 apk 的一般流程](#附录破解-apk-的一般流程)

## com.eleven.gage\*\*\*\*roid

丢 JEB 后看 MainActivity 里没什么逻辑代码，还没看明白是一个什么 Cordova 框架？

```java
public class MainActivity extends CordovaActivity {
    @Override  // org.apache.cordova.CordovaActivity
    public void onCreate(Bundle arg3) {
        super.onCreate(arg3);
        Bundle v3 = this.getIntent().getExtras();
        if(v3 != null && (v3.getBoolean("cdvStartInBackground", false))) {
            this.moveTaskToBack(true);
        }

        this.loadUrl(this.launchUrl);
    }
}
```

搜了一下发现是用前端那一套来写 APP，在解包后的 assets 目录中可以找到主要的代码：

```shell
├───assets
│   └───www
│       ├───audio
│       ├───cordova-js-src
│       │   ├───android
│       │   └───plugin
│       │       └───android
│       ├───css
│       ├───img
│       ├───js
│       ├───lib
│       │   └───angular-admob
│       ├───plugins
│       │   ├───cordova-launch-review
│       │   │   └───www
│       │   ├───cordova-plugin-app-version
│       │   │   └───www
│       │   ├───cordova-plugin-device
│       │   │   └───www
│       │   ├───cordova-plugin-file
│       │   │   └───www
│       │   │       ├───android
│       │   │       └───browser
...
│       │   └───cordova-plugin-tts
│       │       └───www
│       └───res
│           ├───icon
│           │   ├───android
│           │   └───ios
│           ├───screen
│           │   ├───android
│           │   └───ios
│           └───xml
```

然后就是读 html 和 js 代码，可以在代码里找到付费成功的回调函数：

```js
function packBuyed(alias){
	disable("#"+alias);
	$("#"+alias).removeClass("buy-load");
	$("#"+alias+"-inp").val(1);
	depli(alias, true);
	if(alias == "nopub"){
		destroyPub();
	}else{
		enableGroup("."+alias);
	}
	setLocal('pack-'+alias, 1);
}
```

只需要简单地在其他会执行代码地方加上对所有 pack 的 packBuyed 调用即可。

## com.anto\*\*\*bert.acti\*\*\*rite [old version]

| ⚠️ 注意某些 APK 直接从 QQ 文件传送中拉出来的并不是最初的 APK，会丢失 lib，可能和安卓 APP 安装的细节有关，暂不深究。

| 最开始 apk downloader 下载的 APK 是旧版，破解完了才发现。。。

JEB 打开更是混乱，毛都没有，JAVA 代码还是经过混淆。好在，心灵感应足够强大，对一些库函数进行谷歌大法，可以知道这款 APP 使用的是 React Native 框架。

网上已有一些对 React Native APP 逆向分析不错的文章 [[1]](http://davidblus.top/wordpress/index.php/2018/10/08/android_react_native_ying_yong_ni_xiang_fen_xi_chu_tan/) [[2]](https://cloud.tencent.com/developer/article/1593007)，核心的思想就是 JS 代码在 `assets/index.android.bundle` 中，这是一个 JS 文件。

大部分变量名称都经过了混淆，然而关键的函数和变量名称都还保留，一边心灵感应一边读代码逻辑最终明白 isOwned() 函数是判断付费内容解锁与否的关键，直接修改返回永真完成破解。

```js
    v.isOwned = function(t) {
        return !0
        // return !(!this.isReady() || !p[t] || 1 != p[t].owned)
    }
```

## com.anto\*\*\*bert.acti\*\*\*rite

换了一个 downloader 终于下载到了最新的 APK（其实是先破解了最新版，但是有差错没能装上，细节就不多说了，为了阅读观感修改下顺序）。有了上一节的铺垫，想着直接拿 `index.android.bundle` 就开干呗，一打开 VSCODE 傻眼了，提示是一个二进制文件。

查了一下是说，新版的 React Native 直接把 `index.android.bundle` 从 JS 代码编译成了 [Hermes 字节码](https://github.com/facebook/hermes)。

```shell
$❯ file index.android.bundle
index.android.bundle: Hermes JavaScript bytecode, version 84
```

好在，也只能说好在找到了一个工具 [hbctool](https://github.com/bongtrop/hbctool)，能够直接把字节码反汇编成 Hermes 的可读汇编代码，并且还能直接从汇编代码汇编回字节码，给作者磕一个。

然而，官方只支持到了 Hermes Bytecode version 76，这个是 version 84 的。好在好在 [issue](https://github.com/bongtrop/hbctool/issues/12) 中有大佬修改了一个["部分"支持 84 的版本](https://github.com/niosega/hbctool/tree/draft/hbc-v84)，给大佬也磕一个。

```shell
# 安装命令
$> pip install git+https://github.com/niosega/hbctool@draft/hbc-v84

# help
$> hbctool --help   
A command-line interface for disassembling and assembling
the Hermes Bytecode.

Usage:
    hbctool disasm <HBC_FILE> <HASM_PATH>
    hbctool asm <HASM_PATH> <HBC_FILE>
    hbctool --help
    hbctool --version
```

HASM_PATH 会得到三个文件，一些 metadata 和 string 的映射作用不大，主要代码都在 instruction.hasm 文件中，而且对于字符串的引用也直接通过注释的方式写到了 hasm 文件中。


```js
Function<isOwned>8851(3 params, 14 registers, 0 symbols):
	LoadParam           	Reg8:5, UInt8:1
	GetEnvironment      	Reg8:1, UInt8:0
	LoadFromEnvironment 	Reg8:0, Reg8:1, UInt8:8
	GetById             	Reg8:0, Reg8:0, UInt8:1, UInt16:12441
	; Oper[3]: String(12441) 'ProductDetails'

	GetByVal            	Reg8:0, Reg8:0, Reg8:5
	GetById             	Reg8:0, Reg8:0, UInt8:2, UInt16:14308
	; Oper[3]: String(14308) 'isFree'

	JmpTrue             	Addr8:41, Reg8:0
	LoadFromEnvironment 	Reg8:2, Reg8:1, UInt8:6
	GetByIdShort        	Reg8:2, Reg8:2, UInt8:3, UInt8:117
	; Oper[3]: String(117) 'default'

	GetByIdShort        	Reg8:4, Reg8:2, UInt8:4, UInt8:160
	; Oper[3]: String(160) 'instance'

	GetById             	Reg8:3, Reg8:4, UInt8:5, UInt16:14329
	; Oper[3]: String(14329) 'isOwned'

	LoadFromEnvironment 	Reg8:2, Reg8:1, UInt8:7
	GetByIdShort        	Reg8:2, Reg8:2, UInt8:3, UInt8:117
	; Oper[3]: String(117) 'default'

	GetByVal            	Reg8:2, Reg8:2, Reg8:5
	Call2               	Reg8:0, Reg8:3, Reg8:4, Reg8:2
	JmpTrue             	Addr8:64, Reg8:0
	LoadFromEnvironment 	Reg8:2, Reg8:1, UInt8:6
	GetByIdShort        	Reg8:2, Reg8:2, UInt8:3, UInt8:117
	; Oper[3]: String(117) 'default'

	GetByIdShort        	Reg8:3, Reg8:2, UInt8:4, UInt8:160
	; Oper[3]: String(160) 'instance'

	GetById             	Reg8:2, Reg8:3, UInt8:5, UInt16:14329
	; Oper[3]: String(14329) 'isOwned'

	LoadFromEnvironment 	Reg8:4, Reg8:1, UInt8:7
	GetByIdShort        	Reg8:4, Reg8:4, UInt8:3, UInt8:117
	; Oper[3]: String(117) 'default'

	LoadFromEnvironment 	Reg8:1, Reg8:1, UInt8:8
	GetById             	Reg8:5, Reg8:1, UInt8:6, UInt16:12432
	; Oper[3]: String(12432) 'PremiumDetails'

	LoadParam           	Reg8:1, UInt8:2
	GetByVal            	Reg8:1, Reg8:5, Reg8:1
	GetById             	Reg8:1, Reg8:1, UInt8:7, UInt16:14564
	; Oper[3]: String(14564) 'unlockAllProduct'

	GetByVal            	Reg8:1, Reg8:4, Reg8:1
	Call2               	Reg8:0, Reg8:2, Reg8:3, Reg8:1
	Ret                 	Reg8:0
EndFunction
```

上面给了 isOwned() 的示例代码，很奇怪的指令集，不过多看一会儿还是能理解大多数指令的意思。
* LoadParam: 把第 n 个参数载入到寄存器中
* GetEnvironment: 获得某个 Env 存入寄存器，可以看作一堆全局变量的集合
* LoadFromEnvironment: 从某个 Env 取出某个变量？
* GetById/GetByVal：取属性？
* Jmp*：跳转，注意指令集是变长的，这里的偏移还不是很好手酸
* Call*：调用函数（Closure）
* Ret：从函数返回

最开始以为和旧版一样，只要把这个“名为”（我认为尖括号里的可能是函数的名字）isOwned 的函数改为返回永真就行了。

```js
Function<isOwned>8851(3 params, 14 registers, 0 symbols):
	LoadConstTrue			Reg8:0
	Ret                 	Reg8:0
EndFunction
```

后来发现这样只能部分生效，在付费页面显示已经全部解锁，但是不能直接进行高级版的游戏。后来继续在汇编代码中心灵感应，最后理清楚了大概的逻辑，原因是还有一个 isOwned() 函数没有修改，为什么最开始没发现呢？因为这个新的 isowned() 函数是通过不同的方式调用的。

对于第一个 isOwned(8851) 是这样一个调用流程：

```js
    // create
	CreateClosure       	Reg8:0, Reg8:2, UInt16:8851
	StoreToEnvironment  	Reg8:2, UInt8:12, Reg8:0

    // call
	LoadFromEnvironment 	Reg8:4, Reg8:1, UInt8:12
	Call2               	Reg8:4, Reg8:4, Reg8:2, Reg8:3
```

第二个 isOwned()：

```js
    // create
	CreateClosure       	Reg8:4, Reg8:1, UInt16:7123
	PutById             	Reg8:0, Reg8:4, UInt8:21, UInt16:14329
	; Oper[3]: String(14329) 'isOwned'

    // call
    GetById             	Reg8:4, Reg8:10, UInt8:6, UInt16:14329
	; Oper[3]: String(14329) 'isOwned'
    ; prepare params
    ...
	Call2               	Reg8:3, Reg8:4, Reg8:10, Reg8:3
```

可能两种函数的性质不同，导致调用的方式和名称的存放方式也不一样，这里就暂不细究编译器的实现细节了。总结一下就是都需要首先调用 CreateClosure 创建一个闭包，然后以某种方式存放在一个地方，最后调用的时候取出来 Call。

所以 isOwned() 还有一个对应 id 为 7123 的函数实现，同样也需要 patch 掉：

```js
Function<>7123(2 params, 11 registers, 0 symbols):
	LoadConstTrue       	Reg8:0
	Ret                 	Reg8:0
EndFunction
```

最后再汇编回 `index.android.bundle` 打包、签名、安装就一切搞定 ：）

| 不是什么正经🔞APP，就不放破解截图和样本了

## 附录：破解 apk 的一般流程

1. 解包：`apktool d ${apk}`
2. 修改文件
3. 打包：`apktool b ${apk_folder}`
4. 签名
    1. 生成 key：`keytool -genkey -alias abc.keystore -keyalg RSA -validity 20000 -keystore abc.keystore`
    2. 签名：`jarsigner -verbose -keystore abc.keystore -signedjar ${apk_signed} ${apk} abc.keystore`