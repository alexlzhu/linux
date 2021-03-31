# all of the debug options that we support building with
# the strings in these dict values will be appended to the .config file
# generated, overriding earlier declarations disabling these debug options
DEBUG_OPTIONS_DEF = {
    "DEBUG_PAGEALLOC": "CONFIG_DEBUG_PAGEALLOC=y",
    "DEBUG_SLUB": "CONFIG_DEBUG_SLUB_DEBUG_ON=y",
    "DEBUG_KASAN": "CONFIG_DEBUG_KASAN=y",
    "DEBUG_LOCKING": (
        "CONFIG_DEBUG_RT_MUTEXES=y\n" +
        "CONFIG_DEBUG_MUTEXES=y\n" +
        "CONFIG_DEBUG_SPINLOCK=y\n" +
        "CONFIG_DEBUG_WW_MUTEX_SLOWPATH=y\n" +
        "CONFIG_DEBUG_LOCK_ALLOC=y\n" +
        "CONFIG_PROVE_LOCKING=y\n" +
        "CONFIG_DEBUG_ATOMIC_SLEEP=y\n"
    ),
    "DEBUG_BTRFS_ASSERT": "CONFIG_BTRFS_ASSERT=y",
}

# these configs will be enabled on all debug builds (combined with each of the individual option sets above)
COMMON_DEBUG_OPTS = (
    "CONFIG_DEBUG_KERNEL=y\n" +
    "CONFIG_DEBUG_LIST=y\n" +
    "CONFIG_DEBUG_PI_LIST=y\n" +
    "CONFIG_RCU_CPU_STALL_TIMEOUT=60\n" +
    "CONFIG_DEBUG_VM=y\n" +
    "CONFIG_DEBUG_VIRTUAL=y\n" +
    "CONFIG_DEBUG_PER_CPU_MAPS=y\n" +
    "CONFIG_DEBUG_SG=y\n" +
    "CONFIG_DEBUG_NOTIFIERS=y\n" +
    "CONFIG_HARDENED_USERCOPY=y\n" +
    "CONFIG_DEBUG_TIMEKEEPING=y\n" +
    "CONFIG_DMA_API_DEBUG=y\n" +
    "CONFIG_DMA_API_DEBUG_SG=y\n" +
    # DEBUG_OBJECTS
    "CONFIG_DEBUG_OBJECTS=y\n" +
    "CONFIG_DEBUG_OBJECTS_FREE=y\n" +
    "CONFIG_DEBUG_OBJECTS_TIMERS=y\n" +
    "CONFIG_DEBUG_OBJECTS_WORK=y\n" +
    "CONFIG_DEBUG_OBJECTS_RCU_HEAD=y\n" +
    "CONFIG_DEBUG_OBJECTS_PERCPU_COUNTER=y\n" +
    "CONFIG_DEBUG_KOBJECT_RELEASE=y\n"
)
