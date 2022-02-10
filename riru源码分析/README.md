# riru源码分析

riru主要是注入zygote来实现，而原理是十分简单的，总的来说在startvm里会dlopen一个固定的库，只要修改库的名字就可以dlopen我们的库了，从而注入进入zygote

## riru原理

### 它的原理

通过系统的native bridge实现注入zygote

在app_process->runtime.start->startvm->runtime.init

```c
 std::string native_bridge_file_name = runtime_options.ReleaseOrDefault(Opt::NativeBridge);
    is_native_bridge_loaded_ = LoadNativeBridge(native_bridge_file_name);
```

```c
bool LoadNativeBridge(const char* nb_library_filename,
                      const NativeBridgeRuntimeCallbacks* runtime_cbs) {
  // We expect only one place that calls LoadNativeBridge: Runtime::Init. At that point we are not
  // multi-threaded, so we do not need locking here.

  if (nb_library_filename == nullptr || *nb_library_filename == 0) {
    CloseNativeBridge(false);
    return false;
  } else {
    if (!NativeBridgeNameAcceptable(nb_library_filename)) {
      CloseNativeBridge(true);
    } else {
      // Try to open the library.
      void* handle = dlopen(nb_library_filename, RTLD_LAZY);
      if (handle != nullptr) {
        callbacks = reinterpret_cast<NativeBridgeCallbacks*>(dlsym(handle,
                                                                   kNativeBridgeInterfaceSymbol));
        if (callbacks != nullptr) {
          if (isCompatibleWith(NAMESPACE_VERSION)) {
            // Store the handle for later.
            native_bridge_handle = handle;
          } else {
            callbacks = nullptr;
            dlclose(handle);
            ALOGW("Unsupported native bridge interface.");
          }
        } else {
          dlclose(handle);
        }
      }

      // Two failure conditions: could not find library (dlopen failed), or could not find native
      // bridge interface (dlsym failed). Both are an error and close the native bridge.
      if (callbacks == nullptr) {
        CloseNativeBridge(true);
      } else {
        runtime_callbacks = runtime_cbs;
        state = NativeBridgeState::kOpened;
      }
    }
    return state == NativeBridgeState::kOpened;
  }
}
```

native bridge是在AndroidRuntime::startVm

```c
/*
 * Start the Dalvik Virtual Machine.
 *
 * Various arguments, most determined by system properties, are passed in.
 * The "mOptions" vector is updated.
 *
 * CAUTION: when adding options in here, be careful not to put the
 * char buffer inside a nested scope.  Adding the buffer to the
 * options using mOptions.add() does not copy the buffer, so if the
 * buffer goes out of scope the option may be overwritten.  It's best
 * to put the buffer at the top of the function so that it is more
 * unlikely that someone will surround it in a scope at a later time
 * and thus introduce a bug.
 *
 * Returns 0 on success.
 */
int AndroidRuntime::startVm(JavaVM** pJavaVM, JNIEnv** pEnv, bool zygote, bool primary_zygote)
{
    JavaVMInitArgs initArgs;
    // ...

    // Native bridge library. "0" means that native bridge is disabled.
    //
    // Note: bridging is only enabled for the zygote. Other runs of
    //       app_process may not have the permissions to mount etc.
    property_get("ro.dalvik.vm.native.bridge", propBuf, "");
    if (propBuf[0] == '\0') {
        ALOGW("ro.dalvik.vm.native.bridge is not expected to be empty");
    } else if (zygote && strcmp(propBuf, "0") != 0) {
        snprintf(nativeBridgeLibrary, sizeof("-XX:NativeBridge=") + PROPERTY_VALUE_MAX,
                 "-XX:NativeBridge=%s", propBuf);
        addOption(nativeBridgeLibrary);
    }
    // ...
    initArgs.version = JNI_VERSION_1_4;
    initArgs.options = mOptions.editArray();
    initArgs.nOptions = mOptions.size();
    initArgs.ignoreUnrecognized = JNI_FALSE;

    /*
     * Initialize the VM.
     *
     * The JavaVM* is essentially per-process, and the JNIEnv* is per-thread.
     * If this call succeeds, the VM is ready, and we can start issuing
     * JNI calls.
     */
    if (JNI_CreateJavaVM(pJavaVM, pEnv, &initArgs) < 0) {
        ALOGE("JNI_CreateJavaVM failed\n");
        return -1;
    }

    return 0;
}
```

读取的`ro.dalvik.vm.native.bridge`这个系统属性啊,由于是只读，所以riru得基于magisk得插件，才能修改，之后的事那就是伪造native bridge来让它正常运行

native bridge这东西对arm设备上来说基本没啥用，然而对x86设备来说，没有这玩意你就没法用只支持arm的app，

所以要在我们自己的so里init_array里来伪造

系统是这样来调用的

```c
void* NativeBridgeGetTrampoline(void* handle, const char* name, const char* shorty,
                                uint32_t len) {
  if (NativeBridgeInitialized()) {
    return callbacks->getTrampoline(handle, name, shorty, len);
  }
  return nullptr;
}
```

```c
// Native bridge interfaces to runtime.
struct NativeBridgeCallbacks {
  // Version number of the interface.
  uint32_t version;

  bool (*initialize)(const struct NativeBridgeRuntimeCallbacks* runtime_cbs,
                     const char* private_dir, const char* instruction_set);

  void* (*loadLibrary)(const char* libpath, int flag);

  void* (*getTrampoline)(void* handle, const char* name, const char* shorty, uint32_t len);
  // ...
}

// Pointer to the callbacks. Available as soon as LoadNativeBridge succeeds, but only initialized
// later.
static const NativeBridgeCallbacks* callbacks = nullptr;
```

初始化

```c
// The symbol name exposed by native-bridge with the type of NativeBridgeCallbacks.
static constexpr const char* kNativeBridgeInterfaceSymbol = "NativeBridgeItf";

bool LoadNativeBridge(const char* nb_library_filename,
                      const NativeBridgeRuntimeCallbacks* runtime_cbs) {
      // Try to open the library.
      void* handle = dlopen(nb_library_filename, RTLD_LAZY);
      if (handle != nullptr) {
        callbacks = reinterpret_cast<NativeBridgeCallbacks*>(dlsym(handle,
                                                                   kNativeBridgeInterfaceSymbol));
        if (callbacks != nullptr) {
          if (isCompatibleWith(NAMESPACE_VERSION)) {
            // Store the handle for later.
            native_bridge_handle = handle;
          } else {
            callbacks = nullptr;
            dlclose(handle);
            ALOGW("Unsupported native bridge interface.");
          }
        } else {
          dlclose(handle);
        }
      }
    return state == NativeBridgeState::kOpened;
  }
}
```

是从native bridge的so库中找到的，对应符号是`NativeBridgeItf`。
既然系统是这样做的，那我们就顺着系统来，在合适的时候偷梁换柱一下。
首先声明一个对应类型的变量NativeBridgeItf：

```
COPY__attribute__ ((visibility ("default"))) NativeBridgeCallbacks NativeBridgeItf;
```

注：如果你使用c++，记得加上`extern "C"`。
然后，在系统dlopen我们的库时，会执行`.init_array`里的函数，我们可以在这里动手脚：

```
COPYif (real_nb_filename[0] == '\0') {
    LOGW("ro.dalvik.vm.native.bridge is not expected to be empty");
} else if (strcmp(real_nb_filename, "0") != 0) {
    LOGI("The system has real native bridge support, libname %s", real_nb_filename);
    const char* error_msg;
    void* handle = dlopen(real_nb_filename, RTLD_LAZY);
    if (handle) {
        void* real_nb_itf = dlsym(handle, "NativeBridgeItf");
        if (real_nb_itf) {
            // sizeof(NativeBridgeCallbacks) maybe changed in other android version
            memcpy(&NativeBridgeItf, real_nb_itf, sizeof(NativeBridgeCallbacks));
            return;
        }
        errro_msg = dlerror();
        dlclose(handle);
    } else {
        errro_msg = dlerror();
    }
    LOGE("Could not setup NativeBridgeItf for real lib %s: %s", real_nb_filename, error_msg);
}
```

简单解释一下：系统是通过读取我们的`NativeBridgeItf`这个变量来获取要执行的对应函数的，那我们就可以仿照系统，从真正的native bridge中读取这个变量，覆盖掉我们暴露出去的那个`NativeBridgeItf`，这样就会走真实的native bridge callbacks。
注：这里还有个坑，NativeBridgeCallbacks这个结构体的大小在其他系统版本是不同的，如果只复制固定大小，要么复制不全要么越界；所以这里需要按照版本判断一下。

但是它无法驻留在内存

1.

```c
void* handle = dlopen(nb_library_filename, RTLD_LAZY);
if (handle != nullptr) {
    callbacks = reinterpret_cast<NativeBridgeCallbacks*>(dlsym(handle, kNativeBridgeInterfaceSymbol));
    if (callbacks != nullptr) {
      if (isCompatibleWith(NAMESPACE_VERSION)) {
        // Store the handle for later.
        native_bridge_handle = handle;
      } else {
        callbacks = nullptr;
        dlclose(handle);
        ALOGW("Unsupported native bridge interface.");
      }
    } else {
      dlclose(handle);
    }
}
```

```c
// The policy of invoking Nativebridge changed in v3 with/without namespace.
// Suggest Nativebridge implementation not maintain backward-compatible.
static bool isCompatibleWith(const uint32_t version) {
  // Libnativebridge is now designed to be forward-compatible. So only "0" is an unsupported
  // version.
  if (callbacks == nullptr || callbacks->version == 0 || version == 0) {
    return false;
  }

  // If this is a v2+ bridge, it may not be forwards- or backwards-compatible. Check.
  if (callbacks->version >= SIGNAL_VERSION) {
    return callbacks->isCompatibleWith(version);
  }

  return true;
}
```

这个好解决，到时候设置一下jiux

2.so库能成功驻留在zygote进程的内存中了；然而，你在应用进程中找不到这个so库，这是因为新进程fork出来以后，如果不需要native bridge，系统会卸载它

因此换个思路，把这个so已经在zygote 任意代码执行了，所以加载一个hook的so就行了，，在这个假的native bridge里dlopen()这个新库，假的native bridge直接当个loader不就好了嘛！而且这样的话实际上我们不用实现那堆函数，只需要把version设置成一个无效的值（比如0），这样系统检测到版本无效就会自动关闭我们的假native bridge库，也不用担心那些回调函数会被调用

### riru源码分析

原理的话就是前面的，修改ro.dalvik.vm.native.bridge的so文件名改成我们自己的，于是实现zygote注入，作为loader加载我们自己的代码,然后伪造使用原来的nativebridge.so

主要逻辑在loader.cpp

```c
   ...
    auto *handle = DlopenExt(riru_path, 0);
    if (handle) {
        auto init = reinterpret_cast<void (*)(void *, const char *, const RirudSocket &)>(dlsym(
                handle, "init"));
        if (init) {
            init(handle, magisk_path.data(), rirud);
        } else {
            LOGE("dlsym init %s", dlerror());
        }
    } else {
        LOGE("dlopen riru.so %s", dlerror());
    }

#ifdef HAS_NATIVE_BRIDGE

    auto native_bridge = rirud.ReadNativeBridge();
    if (native_bridge.empty()) {
        LOGW("Failed to read original native bridge from socket");
        return;
    }

    LOGI("original native bridge: %s", native_bridge.data());

    if (native_bridge == "0") {
        return;
    }

    original_bridge = dlopen(native_bridge.data(), RTLD_NOW);
    if (original_bridge == nullptr) {
        LOGE("dlopen failed: %s", dlerror());
        return;
    }

    auto *original_native_bridge_itf = dlsym(original_bridge, "NativeBridgeItf");
    if (original_native_bridge_itf == nullptr) {
        LOGE("dlsym failed: %s", dlerror());
        return;
    }

    int sdk = 0;
    std::array<char, PROP_VALUE_MAX + 1> value;
    if (__system_property_get("ro.build.version.sdk", value.data()) > 0) {
        sdk = atoi(value.data());
    }

    auto callbacks_size = 0;
    if (sdk >= __ANDROID_API_R__) {
        callbacks_size = sizeof(NativeBridgeCallbacks<__ANDROID_API_R__>);
    } else if (sdk == __ANDROID_API_Q__) {
        callbacks_size = sizeof(NativeBridgeCallbacks<__ANDROID_API_Q__>);
    } else if (sdk == __ANDROID_API_P__) {
        callbacks_size = sizeof(NativeBridgeCallbacks<__ANDROID_API_P__>);
    } else if (sdk == __ANDROID_API_O_MR1__) {
        callbacks_size = sizeof(NativeBridgeCallbacks<__ANDROID_API_O_MR1__>);
    } else if (sdk == __ANDROID_API_O__) {
        callbacks_size = sizeof(NativeBridgeCallbacks<__ANDROID_API_O__>);
    } else if (sdk == __ANDROID_API_N_MR1__) {
        callbacks_size = sizeof(NativeBridgeCallbacks<__ANDROID_API_N_MR1__>);
    } else if (sdk == __ANDROID_API_N__) {
        callbacks_size = sizeof(NativeBridgeCallbacks<__ANDROID_API_N__>);
    } else if (sdk == __ANDROID_API_M__) {
        callbacks_size = sizeof(NativeBridgeCallbacks<__ANDROID_API_M__>);
    }

    memcpy(NativeBridgeItf, original_native_bridge_itf, callbacks_size);
#endif
}
```

执行libriru.so的init 之后伪造native bridge

而libriru.so init在entry.cpp

```c
init(void *handle, const char* magisk_path, const RirudSocket& rirud) {
    self_handle = handle;

    magisk::SetPath(magisk_path);
    hide::PrepareMapsHideLibrary();
    jni::InstallHooks();
    modules::Load(rirud);
}

```

magisk：：setpath就是设置路径

hide::PrepareMapsHideLibrary

```c
void PrepareMapsHideLibrary() {
        auto hide_lib_path = magisk::GetPathForSelfLib("libriruhide.so");

        // load riruhide.so and run the hide
        LOGD("dlopen libriruhide");
        riru_hide_handle = DlopenExt(hide_lib_path.c_str(), 0);
        if (!riru_hide_handle) {
            LOGE("dlopen %s failed: %s", hide_lib_path.c_str(), dlerror());
            return;
        }
        riru_hide_func = reinterpret_cast<riru_hide_t *>(dlsym(riru_hide_handle, "riru_hide"));
        if (!riru_hide_func) {
            LOGE("dlsym failed: %s", dlerror());
            dlclose(riru_hide_handle);
            return;
        }
    }
```

就是得到hide.cpp里面的函数，

hide的机制也明白了 就是将libriru.so的start end改成anoymous | private 满好实现的，就是先map 一段 把内容复制过去，对于自己mumap，再重新map就行

```c
static int do_hide(hide_struct *data) {
    auto procstruct = data->original;
    auto start = (uintptr_t) procstruct->addr_start;
    auto end = (uintptr_t) procstruct->addr_end;
    auto length = end - start;
    int prot = get_prot(procstruct);

    // backup
    data->backup_address = (uintptr_t) FAILURE_RETURN(
            mmap(nullptr, length, PROT_READ | PROT_WRITE, MAP_ANONYMOUS | MAP_PRIVATE, -1, 0),
            MAP_FAILED);
    
    //map一个相同长度的作为备份
    LOGD("%" PRIxPTR"-%" PRIxPTR" %s %ld %s is backup to %" PRIxPTR, start, end, procstruct->perm,
         procstruct->offset,
         procstruct->pathname, data->backup_address);

    if (!procstruct->is_r) {
        LOGD("mprotect +r");
        FAILURE_RETURN(mprotect((void *) start, length, prot | PROT_READ), -1);
    }
    LOGD("memcpy -> backup");
    memcpy((void *) data->backup_address, (void *) start, length);

    // munmap original
    LOGD("munmap original");
    //先取消自己的 mumap
    FAILURE_RETURN(munmap((void *) start, length), -1);

    // restore
    LOGD("mmap original");
    //再重新mmap自己 同时加权限
    FAILURE_RETURN(mmap((void *) start, length, prot, MAP_ANONYMOUS | MAP_PRIVATE, -1, 0),
                   MAP_FAILED);
    LOGD("mprotect +w");
    FAILURE_RETURN(mprotect((void *) start, length, prot | PROT_WRITE), -1);
    LOGD("memcpy -> original");
    memcpy((void *) start, (void *) data->backup_address, length);
    if (!procstruct->is_w) {
        LOGD("mprotect -w");
        FAILURE_RETURN(mprotect((void *) start, length, prot), -1);
    }
    return 0;
}

int riru_hide(const std::set<std::string_view> &names) {
    procmaps_iterator *maps = pmparser_parse(-1);
    if (maps == nullptr) {
        LOGE("cannot parse the memory map");
        return false;
    }

    char buf[PATH_MAX];
    hide_struct *data = nullptr;
    size_t data_count = 0;
    procmaps_struct *maps_tmp;
    while ((maps_tmp = pmparser_next(maps)) != nullptr) {
        bool matched = false;
#ifdef DEBUG_APP
        matched = strstr(maps_tmp->pathname, "libriru.so");
#endif
        matched = names.count(maps_tmp->pathname);

        if (!matched) continue;

        auto start = (uintptr_t) maps_tmp->addr_start;
        auto end = (uintptr_t) maps_tmp->addr_end;
        if (maps_tmp->is_r) {
            if (data) {
                data = (hide_struct *) realloc(data, sizeof(hide_struct) * (data_count + 1));
            } else {
                data = (hide_struct *) malloc(sizeof(hide_struct));
            }
            data[data_count].original = maps_tmp;
            data_count += 1;
        }
        LOGD("%" PRIxPTR"-%" PRIxPTR" %s %ld %s", start, end, maps_tmp->perm, maps_tmp->offset,
             maps_tmp->pathname);
    }
//在、proc/maps找到libriru.so之后就是hide
    for (int i = 0; i < data_count; ++i) {
        do_hide(&data[i]);
    }

    if (data) free(data);
    pmparser_free(maps);
    return 0;
}
```

之后就是jni::InstallHooks();

这里引用一下riru说的原理

```c
一些 JNI 函数 ( com.android.internal.os.Zygote#nativeForkAndSpecialize& com.android.internal.os.Zygote#nativeForkSystemServer) 是 fork 应用程序进程或系统服务器进程。所以我们需要用我们的替换这些函数。这部分很简单，hookjniRegisterNativeMethods因为所有的 Java 原生方法libandroid_runtime.so都是通过这个函数注册的。然后我们可以再次调用原来的jniRegisterNativeMethods来替换它们。
```

也是这样的主要是这段代码

```c
NEW_FUNC_DEF(int, jniRegisterNativeMethods, JNIEnv *env, const char *className,
             const JNINativeMethod *methods, int numMethods) {
    LOGD("jniRegisterNativeMethods %s", className);

    auto newMethods = handleRegisterNative(className, methods, numMethods);
    int res = old_jniRegisterNativeMethods(env, className, newMethods ? newMethods.get() : methods,
                                           numMethods);
    /*if (!newMethods) {
        NativeMethod::jniRegisterNativeMethodsPost(env, className, methods, numMethods);
    }*/
    return res;
}
```



```c
static std::unique_ptr<JNINativeMethod[]>
handleRegisterNative(const char *className, const JNINativeMethod *methods, int numMethods) {
    if (strcmp("com/android/internal/os/Zygote", className) == 0) {
        return onRegisterZygote(className, methods, numMethods);
    } else {
        return nullptr;
    }
}
```



```c
static std::unique_ptr<JNINativeMethod[]>
onRegisterZygote(const char *className, const JNINativeMethod *methods, int numMethods) {

    auto newMethods = std::make_unique<JNINativeMethod[]>(numMethods);
    memcpy(newMethods.get(), methods, sizeof(JNINativeMethod) * numMethods);

    JNINativeMethod method;
    for (int i = 0; i < numMethods; ++i) {
        method = methods[i];

        if (strcmp(method.name, "nativeForkAndSpecialize") == 0) {
            jni::zygote::nativeForkAndSpecialize = new JNINativeMethod{method.name,
                                                                       method.signature,
                                                                       method.fnPtr};

            if (strcmp(nativeForkAndSpecialize_r_sig, method.signature) == 0)
                newMethods[i].fnPtr = (void *) nativeForkAndSpecialize_r;
            ....
          return newMethods;        
                
        
```

主要是重新注册 hook了，举个例子来看看nativeForkAndSpecialize_r是怎么写的

```c
jint nativeForkAndSpecialize_r(
        JNIEnv *env, jclass clazz, jint uid, jint gid, jintArray gids, jint runtime_flags,
        jobjectArray rlimits, jint mount_external, jstring se_info, jstring se_name,
        jintArray fdsToClose, jintArray fdsToIgnore, jboolean is_child_zygote,
        jstring instructionSet, jstring appDataDir, jboolean isTopApp, jobjectArray pkgDataInfoList,
        jobjectArray whitelistedDataInfoList, jboolean bindMountAppDataDirs,
        jboolean bindMountAppStorageDirs) {

    nativeForkAndSpecialize_pre(env, clazz, uid, gid, gids, runtime_flags, rlimits, mount_external,
                                se_info, se_name, fdsToClose, fdsToIgnore, is_child_zygote,
                                instructionSet, appDataDir, isTopApp, pkgDataInfoList,
                                whitelistedDataInfoList,
                                bindMountAppDataDirs, bindMountAppStorageDirs);

    jint res = ((nativeForkAndSpecialize_r_t *) jni::zygote::nativeForkAndSpecialize->fnPtr)(
            env, clazz, uid, gid, gids, runtime_flags, rlimits, mount_external, se_info, se_name,
            fdsToClose, fdsToIgnore, is_child_zygote, instructionSet, appDataDir, isTopApp,
            pkgDataInfoList,
            whitelistedDataInfoList, bindMountAppDataDirs, bindMountAppStorageDirs);

    nativeForkAndSpecialize_post(env, clazz, uid, is_child_zygote, res);
    return res;
}
```

和xposed差不多 来看看nativeForkAndSpecialize_pre

```c
static void nativeForkAndSpecialize_pre(
        JNIEnv *env, jclass clazz, jint &uid, jint &gid, jintArray &gids, jint &runtime_flags,
        jobjectArray &rlimits, jint &mount_external, jstring &se_info, jstring &se_name,
        jintArray &fdsToClose, jintArray &fdsToIgnore, jboolean &is_child_zygote,
        jstring &instructionSet, jstring &appDataDir, jboolean &isTopApp,
        jobjectArray &pkgDataInfoList,
        jobjectArray &whitelistedDataInfoList, jboolean &bindMountAppDataDirs,
        jboolean &bindMountAppStorageDirs) {

    for (const auto &module : modules::Get()) {
        if (!module.hasForkAndSpecializePre())
            continue;

        module.resetAllowUnload();

        if (module.apiVersion < 25) {
            if (module.hasShouldSkipUid() && module.shouldSkipUid(uid))
                continue;

            if (!module.hasShouldSkipUid() && shouldSkipUid(uid))
                continue;
        }

        module.forkAndSpecializePre(
                env, clazz, &uid, &gid, &gids, &runtime_flags, &rlimits, &mount_external,
                &se_info, &se_name, &fdsToClose, &fdsToIgnore, &is_child_zygote,
                &instructionSet, &appDataDir, &isTopApp, &pkgDataInfoList, &whitelistedDataInfoList,
                &bindMountAppDataDirs, &bindMountAppStorageDirs);
    }
}
```

这个主要是module.forkAndSpecializePre这个是后面加载load实现的

最后一个modules::Load(rirud);

就只是加载 没什么内容

