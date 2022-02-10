# frida源码分析

frida使用ptrace attach到进程之后，往进程中注入一个frida-agent-32.so模块，此模块是frida和frida-server通信的重要模块，所以frida不会一直占用ptrace，注入模块完成后便detach

主要看了一下frida是如何hook so层和java层的 java层的和xposed差不多 改了native的入口 c层采取了inline hook 写的模块特别清晰，最后说一下anti frida的方法

`frida-gum`是底层hook框架，跨平台；

`frida-python` , `frida-node`啥的是 bindings，暂时不管，不理解原理看也看不懂；

`capstone` 牛逼的反汇编框架，`frida-gum`中用到了，用于指令的读；

`releng` 编译相关的；

`frida-core` server/agent相关；

`frida-tools` 一些工具，比如frida-ps啥的。

`frida-java-bridge`: 主要负责hook java层的

## frida-java-bridge

##### 获得javavm

调用JNi_GetCreatedJavaVms获得javavm的指针

```c
  const vms = Memory.alloc(pointerSize);
  const vmCount = Memory.alloc(jsizeSize);
  checkJniResult('JNI_GetCreatedJavaVMs', temporaryApi.JNI_GetCreatedJavaVMs(vms, 1, vmCount));
  if (vmCount.readInt() === 0) {
    return null;
  }
  temporaryApi.vm = vms.readPointer();

  const allocatorFunctions = {
    $new: ['_Znwm', 'pointer', ['ulong']],
    $delete: ['_ZdlPv', 'void', ['pointer']]
  };
  for (const [name, [rawName, retType, argTypes]] of Object.entries(allocatorFunctions)) {
    let address = Module.findExportByName(null, rawName);
    if (address === null) {
      address = DebugSymbol.fromName(rawName).address;
      if (address.isNull()) {
        throw new Error(`unable to find C++ allocator API, missing: '${rawName}'`);
      }
    }
    temporaryApi[name] = new NativeFunction(address, retType, argTypes, nativeFunctionOptions);
  }
temporaryApi.jvmti = getEnvJvmti(temporaryApi);
```

temporaryApi包装好后，调用getEnvJvmti(这个函数实现了获得javavm和jnienv)

```c
function getEnvJvmti (api) {
  const vm = new VM(api);

  let env;
  vm.perform(() => {
    const getEnv = new NativeFunction(vm.handle.readPointer().add(6 * pointerSize).readPointer(), 'int32', ['pointer', 'pointer', 'int32'],
      nativeFunctionOptions);
    const envBuf = Memory.alloc(pointerSize);
    let result = getEnv(vm.handle, envBuf, JVMTI_VERSION_1_0);
    checkJniResult('getEnvJvmti::GetEnv', result);
    env = new EnvJvmti(envBuf.readPointer(), vm);

    const capaBuf = Memory.alloc(8);
    capaBuf.writeU64(jvmtiCapabilities.canTagObjects);
    result = env.addCapabilities(capaBuf);
    checkJniResult('getEnvJvmti::AddCapabilities', result);
  });

  return env;
}
```

首先是获得vm调用了vm函数 ，vm函数首先初始化,读取javavm在内存中的指针封装了一些JavaVM的方法，如getEnv，其中vm.handle中保存的是原始的JavaVM对象。

```c
function VM (api) {
  const handle = api.vm;
  let attachCurrentThread = null;
  let detachCurrentThread = null;
  let getEnv = null;
  const attachedThreads = new Map();

  function initialize () {
    const vtable = handle.readPointer();
    const options = {
      exceptions: 'propagate'
    };
    attachCurrentThread = new NativeFunction(vtable.add(4 * pointerSize).readPointer(), 'int32', ['pointer', 'pointer', 'pointer'], options);
    detachCurrentThread = new NativeFunction(vtable.add(5 * pointerSize).readPointer(), 'int32', ['pointer'], options);
    getEnv = new NativeFunction(vtable.add(6 * pointerSize).readPointer(), 'int32', ['pointer', 'pointer', 'int32'], options);
  }
```

VM的初始化过程为首先获取JavaVM的指针（通过JNI_GetCreatedJavaVMs调用），然后读取JavaVM的虚函数表，获得JavaVM的一些重要方法，并在js层包装一层，这样就在js层实现了一个JavaVM的代理，可以通过调用VM.getEnv来实现native层的JavaVM.getEnV调用。

##### 获得env

```c
vm.perform(() => {
    const getEnv = new NativeFunction(vm.handle.readPointer().add(6 * pointerSize).readPointer(), 'int32', ['pointer', 'pointer', 'int32'],
      nativeFunctionOptions);
    const envBuf = Memory.alloc(pointerSize);
    let result = getEnv(vm.handle, envBuf, JVMTI_VERSION_1_0);
    checkJniResult('getEnvJvmti::GetEnv', result);
    env = new EnvJvmti(envBuf.readPointer(), vm);

    const capaBuf = Memory.alloc(8);
    capaBuf.writeU64(jvmtiCapabilities.canTagObjects);
    result = env.addCapabilities(capaBuf);
    checkJniResult('getEnvJvmti::AddCapabilities', result);
  });



// perform函数
 this.perform = function (fn) {
    const threadId = Process.getCurrentThreadId();

    const isJsThread = threadId === jsThreadID;
    if (isJsThread && jsEnv !== null) {
      return fn(jsEnv);
    }

    let env = this.tryGetEnv(); //将当前线程附加到JavaVM，获取JNIEnv对象
    const alreadyAttached = env !== null;
    if (!alreadyAttached) {
      env = this.attachCurrentThread();
      if (isJsThread) {
        jsEnv = env;
      } else {
        attachedThreads.set(threadId, true);
      }
    }

    try {
      return fn(env);
    } finally {
      if (!alreadyAttached && !isJsThread) {
        const allowedToDetach = attachedThreads.get(threadId);
        attachedThreads.delete(threadId);

        if (allowedToDetach) {
          this.detachCurrentThread();
        }
      }
    }
  };
```

##### 获得java类的class引用

```javascript
  performNow (fn) {
    this._checkAvailable();

    return this.vm.perform(() => {
      const { classFactory: factory } = this;

      if (this._isAppProcess() && factory.loader === null) {
        const ActivityThread = factory.use('android.app.ActivityThread');
        const app = ActivityThread.currentApplication();
        if (app !== null) {
          initFactoryFromApplication(factory, app);
        }
      }

      return fn();
    });
  }




function initFactoryFromApplication (factory, app) {
  const Process = factory.use('android.os.Process');

  factory.loader = app.getClassLoader();

  if (Process.myUid() === Process.SYSTEM_UID.value) {
    factory.cacheDir = '/data/system';
    factory.codeCacheDir = '/data/dalvik-cache';
  } else {
    if ('getCodeCacheDir' in app) {
      factory.cacheDir = app.getCacheDir().getCanonicalPath();
      factory.codeCacheDir = app.getCodeCacheDir().getCanonicalPath();
    } else {
      factory.cacheDir = app.getFilesDir().getCanonicalPath();
      factory.codeCacheDir = app.getCacheDir().getCanonicalPath();
    }
  }
}
```

和JNI操作方式一样，我们在native层获得了JNIEnv后，要想操作java类，可以通过调用env->findClass来获得java类的class引用。但是这里有个问题，因为frida-java所在的线程是通过pthread_create创造的，然后通过AttachCurrentThread获取的JNIEnv，此时FindClass只会从系统的classloader开始查找，所以app自身的类是无法通过env->findClass来获取。因此需要手工的获取到加载该app的classloader。Java.perform在调用VM.perform之前会先获取加载该app的classloader，并保存到classFactory.loader。



Java.use("classname")是这样走的

frida-java使用Java.use来获得java类的class引用，Java.use(className),返回java类的一个wrapper,在js世界里，用该wrapper来操作对应的java类。

```javascript
 use (className, options = {}) {
    const allowCached = options.cache !== 'skip';

    let C = allowCached ? this._getUsedClass(className) : undefined;//先从缓存中查找
    if (C === undefined) {
      try {
        const env = vm.getEnv();//获取jni_env, 调用native层的JavaVm.GetEnv

        const { _loader: loader } = this;//loader已经在Java.perform中初始化了
        const getClassHandle = (loader !== null)
          ? makeLoaderClassHandleGetter(className, loader, env)
          : makeBasicClassHandleGetter(className);

        C = this._make(className, getClassHandle, env);//构建对应java类的wrapper
      } finally {
        if (allowCached) {
          this._setUsedClass(className, C);
        }
      }
    }

    return C;
  }




  _make (name, getClassHandle, env) {
    const C = makeClassWrapperConstructor();
    const proto = Object.create(Wrapper.prototype, {
      $n: {
        value: name
      },
      $C: {
        value: C
      },
      $w: {
        value: null,
        writable: true
      },
      $_s: {
        writable: true
      },
      $c: {
        value: [null]
      },
      $m: {
        value: new Map()
      },
      $l: {
        value: null,
        writable: true
      },
      $gch: {
        value: getClassHandle
      },
      $f: {
        value: this
      }
    });
    C.prototype = proto;

    const classWrapper = new C(null);
    proto.$w = classWrapper;

    const h = classWrapper.$borrowClassHandle(env);
    try {
      const classHandle = h.value;

      ensureClassInitialized(env, classHandle);

      proto.$l = ClassModel.build(classHandle, env);
    } finally {
      h.unref(env);
    }

    return classWrapper;
  }
```

借助于该wrapper，可以对java类进行操作，如调用构造函数创建对象。该wrapper的初始化过程如下：



```c
//定义了一些每个类都公有的函数和属性
    Object.defineProperty(klass.prototype, '$new', {});
    Object.defineProperty(klass.prototype, '$alloc', {});
    Object.defineProperty(klass.prototype, '$init', {});
    klass.prototype.$dispose = dispose;
    klass.prototype.$isSameObject = function (obj) {});
    Object.defineProperty(klass.prototype, 'class', {});
    Object.defineProperty(klass.prototype, '$className', {});
    //添加该类特有的函数和属性
```

### frida-gum原码分析

在此只分析最重要的`interceptor`这种hook方式(inline hook)

核心在gum那个目录下

gum
├── arch-arm
├── arch-arm64
├── arch-mips
├── arch-x86
├── backend-arm
├── backend-arm64
├── backend-darwin
├── backend-dbghelp
├── backend-elf
├── backend-libdwarf
├── backend-libunwind
├── backend-linux
├── backend-mips
├── backend-posix
├── backend-qnx
├── backend-windows
└── backend-x86
....// gum下其他文件



这里有必要说一下，`frida-gum` 为了实现跨平台，抽象出来 `构架无关/平台无关/系统无关`的api，比如一些内存操作，在`frida-gum`里可能就是`gum_xxxxx`，但是根据不同平台，调用到对应平台的api里去，正是做了很好的封装，上层代码才会看起来“平台无关”。

frida模块化做的特别好

- 内存分配 模块

- 指令写 模块

- 指令读 模块(capstone负责)

- 指令修复 模块 relocator

- 跳板 模块

  跳板模块的设计是希望各个模块的实现更浅的耦合, 跳板函数主要作用就是进行跳转, 并准备 `跳转目标` 需要的参数. 举个例子, 被 hook 的函数经过入口跳板(`enter_trampoline`), 跳转到调度函数(`enter_chunk`), 需要被 hook 的函数相关信息等, 这个就需要在构造跳板时完成.

- 调度器 模块 enter_thunk部分实现

- 栈 模块

以下主要是根据frida官方的test.c来进行源码分析和调试的

这个主要是interceptor拦截器的初始化，主要初始化内存分配模块和交易gum_interceptor_init，主要是在goobject模块特性决定的

```c
GumInterceptor *
gum_interceptor_obtain (void) //初始化interceptor对象 内存分配模块初始化 交易初始化
{
  GumInterceptor * interceptor;

  g_mutex_lock (&_gum_interceptor_lock);

#ifndef GUM_DIET
  if (_the_interceptor != NULL)
  {
    interceptor = GUM_INTERCEPTOR (g_object_ref (_the_interceptor));
  }
  else
  {
    _the_interceptor = g_object_new (GUM_TYPE_INTERCEPTOR, NULL);
    g_object_weak_ref (G_OBJECT (_the_interceptor),
        the_interceptor_weak_notify, NULL);

    interceptor = _the_interceptor;
  }
#else
  if (_the_interceptor != NULL)
  {
    interceptor = gum_object_ref (_the_interceptor);
  }
  else
  {
    _the_interceptor = g_new0 (GumInterceptor, 1);
    _the_interceptor->parent.ref_count = 1;
    _the_interceptor->parent.finalize = gum_interceptor_finalize;
    gum_interceptor_init (_the_interceptor);

    interceptor = _the_interceptor;
  }
#endif

  g_mutex_unlock (&_gum_interceptor_lock);

  return interceptor;
}


static void
gum_interceptor_init (GumInterceptor * self)
{
  g_rec_mutex_init (&self->mutex);

  self->function_by_address = g_hash_table_new_full (NULL, NULL, NULL,
      (GDestroyNotify) gum_function_context_destroy);

  gum_code_allocator_init (&self->allocator, GUM_INTERCEPTOR_CODE_SLICE_SIZE); //// 分配器初始化

  gum_interceptor_transaction_init (&self->current_transaction, self); //交易初始化
}

```

这个函数就是frida inline hook实现的关键，当运行完这个函数时，inline hook就此宣布完成，接下来好好分析这个函数

```c
GumAttachReturn
gum_interceptor_attach (GumInterceptor * self,
                        gpointer function_address,
                        GumInvocationListener * listener,
                        gpointer listener_function_data)
{
  GumAttachReturn result = GUM_ATTACH_OK;
  GumFunctionContext * function_ctx;
  GumInstrumentationError error;

  gum_interceptor_ignore_current_thread (self);
  GUM_INTERCEPTOR_LOCK (self);
  gum_interceptor_transaction_begin (&self->current_transaction); //交易+1
  self->current_transaction.is_dirty = TRUE;

  function_address = gum_interceptor_resolve (self, function_address); //interceptor解析 （首先在自己的hashtable中查看是否解过，无的话在确保所解析的code可读的情况下，根据地址解析到真正的函数地址）

  function_ctx = gum_interceptor_instrument (self, function_address, &error);//interceptor指示   // 获取这个函数的 GumFunctionContext 对象
  // 没有就新建一个
  // 这里已经 准备好了跳板，写好了hook
  // 添加任务,设置相对应的回调函数
  if (function_ctx == NULL)
    goto instrumentation_error;

  if (gum_function_context_has_listener (function_ctx, listener))
    goto already_attached;

  gum_function_context_add_listener (function_ctx, listener, //这里是添加hook函数
      listener_function_data);

  goto beach;

instrumentation_error:
  {
    switch (error)
    {
      case GUM_INSTRUMENTATION_ERROR_WRONG_SIGNATURE:
        result = GUM_ATTACH_WRONG_SIGNATURE;
        break;
      case GUM_INSTRUMENTATION_ERROR_POLICY_VIOLATION:
        result = GUM_ATTACH_POLICY_VIOLATION;
        break;
      default:
        g_assert_not_reached ();
    }
    goto beach;
  }
already_attached:
  {
    result = GUM_ATTACH_ALREADY_ATTACHED;
    goto beach;
  }
beach:
  {
    gum_interceptor_transaction_end (&self->current_transaction);//主要在这里激活跳板 主要通过执行gum_interceptor_activate来对原函数进行liine hook
    GUM_INTERCEPTOR_UNLOCK (self);
    gum_interceptor_unignore_current_thread (self);

    return result;
  }
}
```

gum_interceptor_resolve没什么好说的，就是根据我们输入的地址check一下，gum_interceptor_instrument要好好分析一下

```c
static GumFunctionContext *
gum_interceptor_instrument (GumInterceptor * self,
                            gpointer function_address,
                            GumInstrumentationError * error)  // 获取这个函数的 GumFunctionContext 对象
  // 没有就新建一个
  // 这里已经 准备好了跳板，写好了hook
  // 添加任务,设置相对应的回调函数
{
  GumFunctionContext * ctx;

  *error = GUM_INSTRUMENTATION_ERROR_NONE;

  ctx = (GumFunctionContext *) g_hash_table_lookup (self->function_by_address,
      function_address); 
  if (ctx != NULL)
    return ctx;

  if (self->backend == NULL)
  {
    self->backend =
        _gum_interceptor_backend_create (&self->mutex, &self->allocator); //创建拦截器后端（创造写模块 恢复模块 和thunk用于调度）
  }

  ctx = gum_function_context_new (self, function_address);//根据函数地址构造GumFunctionContext

  if (gum_process_get_code_signing_policy () == GUM_CODE_SIGNING_REQUIRED)
  {
    if (!_gum_interceptor_backend_claim_grafted_trampoline (self->backend, ctx))
      goto policy_violation;
  }
  else
  {
    if (!_gum_interceptor_backend_create_trampoline (self->backend, ctx))//// 创建跳板
      goto wrong_signature;
  }

  // 设置完成后， 添加到哈希表
  // hash_table, key, value
  // hook函数地址，GumFunctionContext对象对应， 方便查找
  g_hash_table_insert (self->function_by_address, function_address, ctx);

  // 当前 transaction 添加到 任务中， 设置回调 函数 gum_interceptor_activate 拦截器激活函数
  gum_interceptor_transaction_schedule_update (&self->current_transaction, ctx,
      gum_interceptor_activate);

```

在gum_interceptor_instrument中要重点关注一下_gum_interceptor_backend_create ，_gum_interceptor_backend_create_trampoline这两个 函数是hook的前置步骤

```c
GumInterceptorBackend *
_gum_interceptor_backend_create (GRecMutex * mutex,
                                 GumCodeAllocator * allocator)
{
  GumInterceptorBackend * backend;

  backend = g_slice_new (GumInterceptorBackend);
  backend->allocator = allocator;

  gum_x86_writer_init (&backend->writer, NULL);
  gum_x86_relocator_init (&backend->relocator, NULL, &backend->writer);

  gum_interceptor_backend_create_thunks (backend);//调度器的初始化 初始化hook函数前  原函数执行后hook  调度器可以理解为所有被 hook 的函数都必须经过的函数 构造虚拟栈 在这里通过栈返回值来控制函数（跳往replace 函数 跳往之后的）

  return backend;
}

```

_gum_interceptor_backend_create初始化写模块，修复模块，调度器初始化，主要是thunks，分别初始化 enter_thunk leave_thunk

```
static void
gum_interceptor_backend_create_thunks (GumInterceptorBackend * self)
{
  GumX86Writer * cw = &self->writer;

  self->enter_thunk = gum_code_allocator_alloc_slice (self->allocator);
  gum_x86_writer_reset (cw, self->enter_thunk->data);
  gum_emit_enter_thunk (cw);
  gum_x86_writer_flush (cw);
  g_assert (gum_x86_writer_offset (cw) <= self->enter_thunk->size);

  self->leave_thunk = gum_code_allocator_alloc_slice (self->allocator);
  gum_x86_writer_reset (cw, self->leave_thunk->data);
  gum_emit_leave_thunk (cw);
  gum_x86_writer_flush (cw);
  g_assert (gum_x86_writer_offset (cw) <= self->leave_thunk->size);
}

static void
gum_emit_enter_thunk (GumX86Writer * cw)
{
  const gssize return_address_stack_displacement = 0;

  gum_emit_prolog (cw, return_address_stack_displacement);

  gum_x86_writer_put_lea_reg_reg_offset (cw, GUM_REG_XSI,
      GUM_REG_XBP, GUM_FRAME_OFFSET_CPU_CONTEXT);
  gum_x86_writer_put_lea_reg_reg_offset (cw, GUM_REG_XDX,
      GUM_REG_XBP, GUM_FRAME_OFFSET_TOP);
  gum_x86_writer_put_lea_reg_reg_offset (cw, GUM_REG_XCX,//首先要保存现场, 构造栈帧，随后进入下一个函数
      GUM_REG_XBP, GUM_FRAME_OFFSET_NEXT_HOP);

  gum_x86_writer_put_call_address_with_aligned_arguments (cw, GUM_CALL_CAPI,
      GUM_ADDRESS (_gum_function_context_begin_invocation), 4, //`__gum_function_context_begin_invocatio通过设置栈(ret addr)控制执行流程 
      GUM_ARG_REGISTER, GUM_REG_XBX,
      GUM_ARG_REGISTER, GUM_REG_XSI,
      GUM_ARG_REGISTER, GUM_REG_XDX,
      GUM_ARG_REGISTER, GUM_REG_XCX);

  gum_emit_epilog (cw);
}

```

而_gum_interceptor_backend_create_trampoline主要是创造跳板，但是还没有对原函数hook,还没将跳板写入，接着回到attach函数，来看看  gum_interceptor_transaction_end，这里主要就是正式hook了，所以准备都好了，调度器，replace function 跳板 。这个函数太长了，只截取重要部分

```c
guint page_size;
    gboolean rwx_supported, code_segment_supported;

    page_size = gum_query_page_size ();//获得页的大小

    rwx_supported = gum_query_is_rwx_supported ();//是否有rwx权限
    code_segment_supported = gum_code_segment_is_supported ();

    if (rwx_supported || !code_segment_supported)
    {
      GumPageProtection protection;

      protection = rwx_supported ? GUM_PAGE_RWX : GUM_PAGE_RW;

      for (cur = addresses; cur != NULL; cur = cur->next)
      {
        gpointer target_page = cur->data;

        gum_mprotect (target_page, page_size, protection);
      }

      for (cur = addresses; cur != NULL; cur = cur->next)
      {
        gpointer target_page = cur->data;
        GArray * pending;
        guint i;

        pending = g_hash_table_lookup (self->pending_update_tasks,
            target_page);
        g_assert (pending != NULL);

        for (i = 0; i != pending->len; i++)
        {
          GumUpdateTask * update;

          update = &g_array_index (pending, GumUpdateTask, i);

          update->func (interceptor, update->ctx,
              _gum_interceptor_backend_get_function_address (update->ctx));
        }
      }

      if (!rwx_supported)
      {
        for (cur = addresses; cur != NULL; cur = cur->next)
        {
          gpointer target_page = cur->data;

          gum_mprotect (target_page, page_size, GUM_PAGE_RX);
        }
      }
```



这里一块比较重要，主要就是判断text段那页是否可写，可以的话  update->func (interceptor, update->ctx,
              _gum_interceptor_backend_get_function_address (update->ctx));进入gum_interceptor_activate，其中里面就是设置跳板，将跳板覆盖那几条指令

最终的效果是这样的

```
原函数
----------------------------------------------------
跳板 0（这里主要是通过end_transaaction实现）
----------------------------------------------------
`enter_chunk`  // （这里是chunk的初始化实现的）首先要保存现场, 构造栈帧，随后进入下一个函数 ⬇️
`__gum_function_context_begin_invocation` // 通过设置栈(ret addr)控制执行流程 (在里面执行replacement)
----------------------------------------------------
replacement_function（__gum_function_context_begin_invocation里卖弄的）
----------------------------------------------------
----------------------------------------------------
`leave_chunk`(恢复现场)
`__gum_function_context_end_invocation` 
----------------------------------------------------
执行原来两个指令（被inline patch了）
跳向原函数
继续执行
```

​        

## frida的反调试

1.cat /proc/pid/maps 查看frida-agent.so

2.ls 查看 frida-server

3.查看frida的端口 是否被占用

4.搜索字符串v8 因为frida 用到js引擎

5.查看线程名字

gum js 引擎的线程名字： Name: gum-js-loop

vala 引擎的线程名字： Name: gmain

dbus 线程名字： Name: gdbus

Frida-gadget 和 Frida-server 在检测下的进程中创建新线程。由于这些线程被命名为 gmain、gum-js-loop 等线程，因此可以检测到此类线程的存在

6.遍历tcp开放端口，查看dbus(frida_server无解) 

7./data/local/tmp查看frida

8. 查看frida 特定的命名管道 （与frida server的通信是通过管道的） 可以遍历 /proc/<pid>/fd 下的不同文件以找到与 frida 对应的命名管道。