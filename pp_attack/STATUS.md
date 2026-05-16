# Prime+Probe Attack Status

## Working Components
- libflush: compiled at /opt/armageddon/libflush/build/armv8/release/
- Eviction strategy: e=21, a=1, d=6 (100% eviction rate)
- RSA victim: /opt/armageddon/pp_attack/rsa_victim (blinding OFF)
- Prime+Probe binary: /opt/armageddon/pp_attack/prime_probe
- Run script: /opt/armageddon/pp_attack/run_pp.sh

## Key Parameters (rpi3.yml)
- arch: armv8
- threshold: 180
- cache: 512KB, 16-way, 512 sets, 64-byte lines
- TIME_SOURCE: monotonic_clock

## Compile Command
gcc -o /opt/armageddon/pp_attack/prime_probe \
    /opt/armageddon/pp_attack/prime_probe.c \
    -I/opt/armageddon/libflush/libflush \
    -I/opt/armageddon/eviction_strategy_evaluator/builds/rpi3/26-1-6-1-m \
    -L/opt/armageddon/libflush/build/armv8/release \
    -lflush -march=armv8-a -O2 \
    -D__ARM_ARCH_8A__ \
    -DTIME_SOURCE=TIME_SOURCE_MONOTONIC_CLOCK \
    -DDEVICE_CONFIGURATION=\"/opt/armageddon/eviction_strategy_evaluator/builds/rpi3/26-1-6-1-m/strategy.h\" \
    -DUSE_EVICTION=1 -DHAVE_PAGEMAP_ACCESS=1 \
    -DES_EVICTION_COUNTER=21 \
    -DES_NUMBER_OF_ACCESSES_IN_LOOP=1 \
    -DES_DIFFERENT_ADDRESSES_IN_LOOP=6 \
    -Wl,-rpath,/opt/armageddon/libflush/build/armv8/release \
    -lm -lpthread -Wno-format -Wno-unused-result

## Next Step
Run: bash /opt/armageddon/pp_attack/run_pp.sh
Then paste pp_results.txt in new chat for analysis.
