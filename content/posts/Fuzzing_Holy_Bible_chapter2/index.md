---
title: "LibAFL Fuzzing Holy Bible - Chapter II: Fuzzing Libexif - CVE-2009-3895 & CVE-2012-2836"
date: 2023-11-27
draft: false
summary: "Using LibAFL fuzzer to reproduce CVE-2009-3895 & CVE-2012-2836"
tags: ["libafl"]
---

###### tags: `libafl`


### Background
[Antonio Morales](https://twitter.com/nosoynadiemas?lang=en) đã tạo một cái repo [Fuzzing 101](https://github.com/antonio-morales/Fuzzing101) với mục đích là tạo ra các challenge liên quan đến những kiến thức và basic skill của fuzzing dành cho những ai muốn học nó và sử dụng nó để tìm ra các vulnerabilities. Repo này tập trung vào cách sử dụng của AFL++ nhưng trong series mình viết với mục đích là solve những challenge sử dụng LibAFL thay vì là AFL++.  

Trong series này thì mình sẽ tìm hiểu các thư viện và viết fuzzers bằng ngôn ngữ Rust, mình sẽ cố gắng solve các challenges gần giống với solution nhất mà mình có thể làm được. 

Và trong series này mình sẽ sử dụng ngôn ngữ Rust để viết fuzzers. Nếu như bạn chưa biết Rust và Fuzzers là gì thì mình khuyến khích bạn nên tìm hiểu về nó trước khi đọc những gì tiếp theo.

### About LibAFL

LibAFL là một sự cải tiến từ AFL++ được viết bằng ngôn ngữ Rust. Nó nhanh hơn, đa dạng nền tảng, no_std compatibles và nó tận dụng tốt nguồn tài nguyên của máy. 

Để hiểu rõ hơn về LibAFL bạn có thể coi cái này [Fuzzers Like Lego @rC3](https://www.youtube.com/watch?v=3RWkT1Q5IV0)

### Prequesite

#### Rust installation: 

`curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh`

#### AFL++ installation:

- Dependencies: 

```
sudo apt-get update
sudo apt-get install -y python3-pip cmake build-essential git gcc
sudo apt-get install -y build-essential python3-dev automake cmake git flex bison libglib2.0-dev libpixman-1-dev python3-setuptools cargo libgtk-3-dev
# try to install llvm 14 and install the distro default if that fails
sudo apt-get install -y lld-14 llvm-14 llvm-14-dev clang-14 || sudo apt-get install -y lld llvm llvm-dev clang
sudo apt-get install -y gcc-$(gcc --version|head -n1|sed 's/\..*//'|sed 's/.* //')-plugin-dev libstdc++-$(gcc --version|head -n1|sed 's/\..*//'|sed 's/.* //')-dev
sudo apt-get install -y ninja-build # for QEMU mode
```

- Build AFL++:

```
git clone https://github.com/AFLplusplus/AFLplusplus && cd AFLplusplus
export LLVM_CONFIG="llvm-config-15"
make distrib
sudo make install
```
Nếu như bạn gặp lỗi với unicornafl thì hãy thử downgrade version của python xuống 3.10.8.
```bash
curl https://pyenv.run | bash
pyenv install 3.10.8
pyenv global 3.10.8
```

- Test installation: 
```cmd=
cd ~
export PATH=$PATH :~/AFLplusplus
afl-fuzz -h
```

Result: 
```cmd=
gh0st@pl4y-Gr0und:~$ afl-fuzz -h
afl-fuzz++4.09a based on afl by Michal Zalewski and a large online community

afl-fuzz [ options ] -- /path/to/fuzzed_app [ ... ]

Required parameters:
  -i dir        - input directory with test cases (or '-' to resume, also see 
                  AFL_AUTORESUME)
  -o dir        - output directory for fuzzer findings

Execution control settings:
  -P strategy   - set fix mutation strategy: explore (focus on new coverage),
                  exploit (focus on triggering crashes). You can also set a
                  number of seconds after without any finds it switches to
                  exploit mode, and back on new coverage (default: 1000)
  -p schedule   - power schedules compute a seed's performance score:
                  fast(default), explore, exploit, seek, rare, mmopt, coe, lin
                  quad -- see docs/FAQ.md for more information
  -f file       - location read by the fuzzed program (default: stdin or @@)
  -t msec       - timeout for each run (auto-scaled, default 1000 ms). Add a '+'
                  to auto-calculate the timeout, the value being the maximum.
  -m megs       - memory limit for child process (0 MB, 0 = no limit [default])
  -O            - use binary-only instrumentation (FRIDA mode)
  -Q            - use binary-only instrumentation (QEMU mode)
  -U            - use unicorn-based instrumentation (Unicorn mode)
  -W            - use qemu-based instrumentation with Wine (Wine mode)
  -X            - use VM fuzzing (NYX mode - standalone mode)
  -Y            - use VM fuzzing (NYX mode - multiple instances mode)

Mutator settings:
  -a            - target input format, "text" or "binary" (default: generic)
  -g minlength  - set min length of generated fuzz input (default: 1)
  -G maxlength  - set max length of generated fuzz input (default: 1048576)
  -D            - enable deterministic fuzzing (once per queue entry)
  -L minutes    - use MOpt(imize) mode and set the time limit for entering the
                  pacemaker mode (minutes of no new finds). 0 = immediately,
                  -1 = immediately and together with normal mutation.
                  Note: this option is usually not very effective
  -c program    - enable CmpLog by specifying a binary compiled for it.
                  if using QEMU/FRIDA or the fuzzing target is compiled
                  for CmpLog then use '-c 0'. To disable Cmplog use '-c -'.
  -l cmplog_opts - CmpLog configuration values (e.g. "2ATR"):
                  1=small files, 2=larger files (default), 3=all files,
                  A=arithmetic solving, T=transformational solving,
                  X=extreme transform solving, R=random colorization bytes.

Fuzzing behavior settings:
  -Z            - sequential queue selection instead of weighted random
  -N            - do not unlink the fuzzing input file (for devices etc.)
  -n            - fuzz without instrumentation (non-instrumented mode)
  -x dict_file  - fuzzer dictionary (see README.md, specify up to 4 times)

Test settings:
  -s seed       - use a fixed seed for the RNG
  -V seconds    - fuzz for a specified time then terminate
  -E execs      - fuzz for an approx. no. of total executions then terminate
                  Note: not precise and can have several more executions.

Other stuff:
  -M/-S id      - distributed mode (-M sets -Z and disables trimming)
                  see docs/fuzzing_in_depth.md#c-using-multiple-cores
                  for effective recommendations for parallel fuzzing.
  -F path       - sync to a foreign fuzzer queue directory (requires -M, can
                  be specified up to 32 times)
  -T text       - text banner to show on the screen
  -I command    - execute this command/script when a new crash is found
  -C            - crash exploration mode (the peruvian rabbit thing)
  -b cpu_id     - bind the fuzzing process to the specified CPU core (0-...)
  -e ext        - file extension for the fuzz test input file (if needed)

To view also the supported environment variables of afl-fuzz please use "-hh".

Compiled with Python 3.11.4 module support, see docs/custom_mutators.md
Compiled without AFL_PERSISTENT_RECORD support.
Compiled with shmat support.
For additional help please consult docs/README.md :)

```
### Objective 

Ở chapter lần này tương ứng với exercise-2 trong [Fuzzing 101](https://github.com/antonio-morales/Fuzzing101/tree/main/Exercise%202). Mục đích của exercise này đó là chúng ta cần phải tìm một cái PoC/crash cho CVE-2009-3895 & CVE-2012-2836. 

[CVE-2009](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2009-3895)

> Heap-based buffer overflow in the exif_entry_fix function (aka the tag fixup routine) in libexif/exif-entry.c in libexif 0.6.18 allows remote attackers to cause a denial of service or possibly execute arbitrary code via an invalid EXIF image. NOTE: some of these details are obtained from third party information.

[CVE-2012-2836](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2012-2836)

> The exif_data_load_data function in exif-data.c in the EXIF Tag Parsing Library (aka libexif) before 0.6.21 allows remote attackers to cause a denial of service (out-of-bounds read) or possibly obtain sensitive information from process memory via crafted EXIF tags in an image.

### Before Fuzzing 

Trước khi bắt đầu fuzzing chúng ta cần phải chuẩn bị một số thứ 

#### Setup our target 

```!
gh0st@fuzzing-bible:~/fuzzing-101-solutions$ cargo new --lib exercise-2 
```

Chúng ta update member cho file Cargo.toml gốc 

> fuzzing-101-solutions/Cargo.toml
```
[workspace]

members = [
    "exercise-1",
    "exercise-2",
]
```

#### Install libexif 

```!
gh0st@fuzzing-bible:~/fuzzing-101-solutions/exercise-2$ wget https://github.com/libexif/libexif/archive/refs/tags/libexif-0_6_14-release.tar.gz
gh0st@fuzzing-bible:~/fuzzing-101-solutions/exercise-2$ tar -xvf libexif-0_6_14-release.tar.gz
gh0st@fuzzing-bible:~/fuzzing-101-solutions/exercise-2$ rm libexif-0_6_14-release.tar.gz
gh0st@fuzzing-bible:~/fuzzing-101-solutions/exercise-2$ mv libexif-libexif-0_6_14-release libexif
```

Install requirements 
```!
gh0st@fuzzing-bible:~/fuzzing-101-solutions/exercise-2$  sudo apt-get install autopoint libtool gettext libpopt-dev
```
#### Build our target 

Lần này mình tiếp tục sử dụng Makefile.toml vì sự tiện lợi của nó trong việc build những task mình cần cho fuzzing 

Nếu bạn chưa biết Makefile.toml là gì thì mình suggest bạn xem blog trước của mình, mình nói khá kỹ về tool này 
https://hackmd.io/jW6RBTbjTfqjGxRvR-DiLQ#Makefiletoml


```rust!=
[tasks.clean]
dependencies = ["cargo-clean", "libexif-clean", "build-clean"]

[tasks.cargo-clean]
command = "cargo"
args = ["clean"]

[tasks.libexif-clean]
command = "make"
args = ["-C", "libexif", "clean", "-i"]

[tasks.build-clean]
command = "rm"
args = ["-rf", "build/"]

[tasks.build]
dependencies = ["clean", "build-libexif"]
command = "cargo"
args = ["build"]


[tasks.build-libexif]
cwd = "libexif"
script = """
autoreconf -fi
./configure --enable-shared=no --prefix="${CARGO_MAKE_WORKING_DIRECTORY}/../build/"
make -i
make install -i
"""
```

Run the build 
```cmd!
gh0st@fuzzing-bible:~/fuzzing-101-solutions/exercise-2$ cargo make build 
```

Confirm build thành công 

```cmd
gh0st@fuzzing-bible:~/fuzzing-101-solutions/exercise-2$ ls build/lib/libexif.a
build/lib/libexif.a
```

### Get into fuzzing 


#### Setting up fuzzer 

> ~/fuzzing-101-solutions/exercise-2/Cargo.toml 

```rust!=
[dependencies]
libafl = {version = "0.10.1"}
libafl_cc = {version = "0.10.1"}
libafl_targets = {version = "0.10.1", features = [
    "libfuzzer",
    "sancov_pcguard_hitcounts",
    "sancov_cmplog",
]}
clap = "3.0.0-beta.5"
[lib]
name="exercisetwo"
crate-type=["staticlib]
```

#### Get some corpus 

```!
gh0st@fuzzing-bible:~/fuzzing-101-solutions/exercise-2$ mkdir corpus solutions
```

Ở trong [libexif repo](https://github.com/libexif/libexif) họ để sẵn một số file jpg để làm test data, để thuận tiện thì chúng ta sẽ lấy các file jpg đó về làm test case cho fuzzer. 

> fuzzing-101-solutions/exercise-2/corpus

```
git clone --no-checkout --filter=blob:none https://github.com/libexif/libexif.git
```

> fuzzing-101-solutions/exercise-2/corpus

```=
cd libexif
git checkout master -- test/testdata
```

> fuzzing-101-solutions/exercise-2/corpus/libexif

```=
mv test/testdata/*.jpg ../
cd ..
rm -rf libexif
```

Và đây là những file để làm test case cho fuzzer
>gh0st@fuzzing-bible:~/fuzzing-101-solutions/exercise-2/corpus

```ruby
gh0st@fuzzing-bible:~/fuzzing-101-solutions/exercise-2/corpus$ ls -la
total 72
drwxrwxr-x 2 gh0st gh0st  4096 Thg 12 29 14:55 .
drwxrwxr-x 7 gh0st gh0st  4096 Thg 12 29 14:55 ..
-rw-rw-r-- 1 gh0st gh0st  2026 Thg 12 29 14:54 canon_makernote_variant_1.jpg
-rw-rw-r-- 1 gh0st gh0st  3978 Thg 12 29 14:54 fuji_makernote_variant_1.jpg
-rw-rw-r-- 1 gh0st gh0st  2850 Thg 12 29 14:54 olympus_makernote_variant_2.jpg
-rw-rw-r-- 1 gh0st gh0st  6140 Thg 12 29 14:54 olympus_makernote_variant_3.jpg
-rw-rw-r-- 1 gh0st gh0st 11458 Thg 12 29 14:54 olympus_makernote_variant_4.jpg
-rw-rw-r-- 1 gh0st gh0st  9604 Thg 12 29 14:54 olympus_makernote_variant_5.jpg
-rw-rw-r-- 1 gh0st gh0st  1346 Thg 12 29 14:54 pentax_makernote_variant_2.jpg
-rw-rw-r-- 1 gh0st gh0st  1918 Thg 12 29 14:54 pentax_makernote_variant_3.jpg
-rw-rw-r-- 1 gh0st gh0st  9132 Thg 12 29 14:54 pentax_makernote_variant_4.jpg
```












