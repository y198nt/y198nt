---
title: "LibAFL Fuzzing Holy Bible - Chapter I: Fuzzing Xpdf - CVE-2019-13288"
date: 2023-11-27
draft: false
summary: "Using LibAFL fuzzer to reproduce CVE-2019-13288"
tags: ["libafl"]
layoutBackgroundBlur: true
---

###### tags: `libafl`


### Background

Đây là lần đầu tiên mình tiếp cận với mảng fuzzing, trước đây thì mình hay reverse audit chay để tìm bug, nhưng sau  khi mình chơi pwn2own làm với target source base lớn thì mình nhận ra audit chay khá là "thọt" so với các đội khác và mình quyết định sẽ thử sức với fuzzing. 

Mình có hỏi sếp mình và sếp mình gợi ý cho mình học LibAFL. Về LibAFL thì vào tháng 8 năm 2021, [Antonio Morales](https://twitter.com/nosoynadiemas?lang=en) đã tạo một cái repo [Fuzzing 101](https://github.com/antonio-morales/Fuzzing101) với mục đích là tạo ra các challenge liên quan đến những kiến thức và basic skill của fuzzing dành cho những ai muốn học nó và sử dụng nó để tìm ra các vulnerabilities. Repo này tập trung vào cách sử dụng của AFL++ nhưng trong series mình viết với mục đích là solve những challenge sử dụng LibAFL thay vì là AFL++.  

Trong series này thì mình sẽ tìm hiểu các thư viện và viết fuzzers bằng ngôn ngữ Rust, mình sẽ cố gắng solve các challenges gần giống với solution nhất mà mình có thể làm được. 

Và trong series này mình sẽ sử dụng ngôn ngữ Rust để viết fuzzers. Nếu như bạn chưa biết Rust và Fuzzers là gì thì mình khuyến khích bạn nên tìm hiểu về nó trước khi đọc những gì tiếp theo.

Rust: [Rust Book](https://doc.rust-lang.org/book/)
Fuzzing: [What is fuzzing](https://github.com/antonio-morales/Fuzzing101#what-is-fuzzing)

### About LibAFL

LibAFL là một sự cải tiến từ AFL++ được viết bằng ngôn ngữ Rust. Nó nhanh hơn, đa dạng nền tảng, no_std compatibles và nó tận dụng tốt nguồn tài nguyên của máy. 

Để hiểu rõ hơn về LibAFL bạn có thể coi cái này [Fuzzers Like Lego @rC3](https://www.youtube.com/watch?v=3RWkT1Q5IV0)

### Objective

Mục đích của fuzzers chúng ta lần này đó là gây ra crash và tạo PoC cho CVE-2019-13288 trong XPDF 3.02.

`In Xpdf 4.01.01, the Parser::getObj() function in Parser.cc may cause infinite recursion via a crafted file. A remote attacker can leverage this for a DoS attack. This is similar to CVE-2018-16646.`

Dựa vào mô tả của lỗ hổng thì nôm na nó chứa 1 bug có thể gây ra infinite recursion thông qua file pdf. Vậy PoC ta cần đó là tạo ra 1 file pdf có thể gây ra crash. 

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

#### Setup our target 

```cmd=
cd ~
mkdir fuzzing-101
cd fuzzing-101
cargo init
```

fuzzing-101 sẽ là directory root cái mà lưu trữ các challenge trong project của chúng ta. 

Trong directory này chúng ta sẽ chỉnh file Cargo.toml sao cho workspace nằm ở trong directory này.

```=
fuzzing-101/Cargo.toml
```

```rust!
[workspace]

members = [
    "exercise-1",
]

[profile.release]
lto = true
codegen-units = 1
opt-level = 3
debug = true
```

- **lto = true**: Sử dụng Link-Time Optimization (tối ưu hóa thời gian liên kết). Điều này có thể cải thiện hiệu suất bằng cách tối ưu hóa toàn bộ chương trình tại thời điểm liên kết.
- **codegen-units = 1**: Đặt số lượng đơn vị mã hóa để biên dịch chương trình. Trong trường hợp này, chỉ có một đơn vị.
- **opt-level = 3**: Đặt cấp độ tối ưu hóa là 3. Cấp độ tối ưu hóa cao nhất, thường dành cho release để tối ưu hóa hiệu suất.
- **debug = true**: Bật debug information trong phiên bản release.

Sau khi xong thì chúng ta tạo solution project cho challenge 1. 

`cargo new exercise-1`

### Install Xpdf


#### Download Xpdf 3.02

```
cd fuzzing-101/exercise-1
wget https://dl.xpdfreader.com/old/xpdf-3.02.tar.gz
tar -xvf xpdf-3.02.tar.gz
rm xpdf-3.02.tar.gz 
mv xpdf-3.02 xpdf
```

Sau khi thực hiện các bước trên thì bạn sẽ có source của Xpdf 3.02 nằm trong directory xpdf

### Fuzzing setup


#### Cargo.toml 

`exercise-1/cargo.toml`

```rust
[package]
name = "exercise-one-solution"
version = "0.1.0"
edition = "2021"


[dependencies]
libafl = { version = "0.10.1" }
```

#### Makefile.toml 

`exercise-1/Makefile.toml`

Có một tool khá là hay mình tìm được đó là [Cargo make](https://github.com/sagiegurari/cargo-make). Thay vì chúng ta sử dụng build như thông thường (dùng file build.rs hoặc là dùng commandline) thì chúng ta có thể sử dụng cargo make để có thể build project một cách tự động. 

Installation: 

```
cargo install --force cargo-make
```

Ví dụ để build xpdf với commandline: 

```
cd fuzzing-101-solutions/exercise-1/xpdf
make clean
rm -rf install 
export LLVM_CONFIG=llvm-config-15
CC=afl-clang-fast CXX=afl-clang-fast++ ./configure --prefix=./install
make
make install
```

Thì chuyển sang file Makefile.toml nó sẽ như thế này

```rust
# composite tasks
[tasks.clean]
dependencies = ["cargo-clean", "afl-clean", "clean-xpdf"]

[tasks.cargo-clean]
command = "cargo"
args = ["clean"]

[tasks.afl-clean]
script = '''
rm -rf .cur_input* timeouts
'''

[tasks.clean-xpdf]
cwd = "xpdf"
script = """
make --silent clean
rm -rf built-with-* ../build/* ${CARGO_MAKE_WORKING_DIRECTORY}/xpdf/install
"""

[tasks.build]
dependencies = ["afl-clean", "clean-xpdf", "build-xpdf", "build-fuzzer"]

[tasks.build-xpdf]
cwd = "xpdf"
script = """
export LLVM_CONFIG=llvm-config-15
CC=afl-clang-fast CXX=afl-clang-fast++ ./configure --prefix=${CARGO_MAKE_WORKING_DIRECTORY}/xpdf/install
make
make install
"""

[tasks.build-fuzzer]
script = """
cargo build --release
"""
```

Và việc còn lại của chúng ta chỉ cần làm là 

`cargo make build` 

Nó sẽ chạy các tác vụ bên trong nó bao gồm afl-clean, clean-xpdf, build-xpdf và build-fuzzer

```rust
[tasks.build]
dependencies = ["afl-clean", "clean-xpdf", "build-xpdf", "build-fuzzer"]
```

Sau khi chạy thành công thì chúng ta sẽ có được các binary file của xpdf 

![image](https://hackmd.io/_uploads/H1RWiO0VT.png)

#### Corpus

Corpus là nơi mà các testcases của chúng ta được lưu tại đó. Chúng ta xem các testcase là input của chúng ta, một corpus có thể lưu trữ các testcases ở nhiều dạng, có thể lưu trực tiếp trên thư mục thành file, memory,.... Trong exercise-1 thì corpus sẽ lưu trữ các file pdf để có thể thực thi các file binary của xpdf. 

install corpus: 

```bash
cd fuzzing-101-solutions/exercise-1
mkdir corpus
cd corpus
wget https://github.com/mozilla/pdf.js-sample-files/raw/master/helloworld.pdf
wget http://www.africau.edu/images/default/sample.pdf
wget https://www.melbpc.org.au/wp-content/uploads/2017/10/small-example-pdf-file.pdf
```
![image](https://hackmd.io/_uploads/BJZ3hOR4a.png)

Chúng ta chỉ cần một vài sample để làm input cho fuzzer.

### Fuzz Everything 

Mọi thứ đã setup ok, chúng ta đi vào phần cuối, đó là viết file fuzz để tìm ra PoC gây crash. 

File main.rs sẽ chịu trách nhiệm cho việc fuzzing, chúng ta sẽ sử dụng các component khác nhau để tiến hành fuzz. Trong file main.rs mình sử dụng concept của [forkserver_simple](https://github.com/AFLplusplus/LibAFL/blob/main/fuzzers/forkserver_simple/src/main.rs). 

Dựa vào concept trên thì component của mình sẽ bao gồm: Corpus & Input, Observer, Feedback, Objective, State,  Monitor, EventManager, Scheduler, Fuzzer, Executor, Mutator, Stage. 

Trong main.rs mình sẽ cố gắng giải thích rõ các components mà mình sử dụng và cách nó liên kết với ý tưởng của fuzzing của mình. 

#### 1st Component: Corpus & Input

Trước khi bắt đầu cho tất cả mọi thứ chúng ta cần phải xác định input và output cho fuzzing. Input ở đây đó chính là các file sample pdf trong exercise-1/corpus. Để lấy các sample trong corpus thì mình sử dụng [InMemoryCorpus](https://docs.rs/libafl/latest/libafl/corpus/inmemory/) để tránh việc reads or writes vào trong directory, việc này sẽ cải thiện tốc độ fuzzing bằng cách ngăn chặn nó tiếp cận vào directory corpus. 

```rust
let corpus_directory = vec![PathBuf::from("./corpus")];
```

Tiếp theo, chúng ta không thể truyền file pdf một cách trực tiếp được mà phải cần chuyển nó thành dạng dữ liệu phù hợp cho fuzzer. Ở đây mình sẽ dùng `BytesInput` để fuzzer có thể đọc được input và xử lý nó. 

```rust
let corpus_BytesInput = InMemoryCorpus::<BytesInput>::new();
```

Output cho fuzzing hay gọi cách khác đó chính là "solutions", nó chính là file pdf sẽ gây ra crash cho chương trình, hay nói cách khác nữa nó chính là PoC khiến cho chương trình rơi vào infinite recursion. Mình sẽ sử dụng [OnDiskCorpus](https://docs.rs/libafl/latest/libafl/corpus/ondisk/struct.OnDiskCorpus.html) để lưu cái PoC đó vô trong corpus.

```rust
let crash_corpus = OnDiskCorpus::new(PathBuf::from("./crash"));
```

Vậy là chúng ta đã xác định được input và output cho fuzzer. 

#### 2nd Component: Observer

Theo trong libafl book thì [Observer](https://aflplus.plus/libafl-book/core_concepts/observer.html) là một loại component được sử dụng để cung cấp các thông tin trong quá trình thực thi của testcase hiện tại đang được fuzz. Trong concept của [forkserver_simple](https://github.com/AFLplusplus/LibAFL/blob/main/fuzzers/forkserver_simple/src/main.rs) thì mình sẽ sử dụng [TimeObserver](https://docs.rs/libafl/latest/libafl/observers/struct.TimeObserver.html). Như mình đã mô tả về observer ở trên thì TimeObserver nó sẽ lấy dữ liệu về runtime cho testcase đang được fuzz. Mỗi lần fuzz thì TimeObserver nó sẽ gửi giá trị về thời gian cho mỗi lần mà testcase được thực thi thông qua Feedback component (tí nữa mình sẽ nói rõ hơn về nó). Ví dụ mình có một file pdf gọi là x, và thời gian để chạy file pdftotext x tốn 5 giây thì TimeObserver sẽ lấy 5 giây đó thông qua Feedback component và gửi nó cho fuzzer. 

```rust
let timeObserver = TimeObserver::new("time");
```

Bên cạnh TimeObserver thì chúng ta cần phải có thêm Coverage Map theo như trong concept của forkserver_simple, Coverage Map sẽ được sử dụng như là coverage guided cho fuzzing, nó sẽ tập trung vào tối đa code coverage để tìm ra lỗ hổng cho chúng ta. Để có thể build Coverage Map thì chúng ta cần shared memory. 

Đầu tiên thì chúng ta cần tạo SharedMemProvider, nó sẽ cung cấp quyền truy cập vào shared memory được mapping trực tiếp vô. Chúng ta sử dụng unix shared memory trong AFL++. 

```rust 
const MAP_SIZE: usize = 65536;
let mut shmem_provider = StdShMemProvider::new().unwrap();
let mut shmem = shmem_provider.new_shmem(MAP_SIZE).unwrap();
```

Coverage map sẽ chia sẻ lẫn nhau giữa observer và executor. Để executor biết được coverage map thì mình sẽ ghi shared memory id thì mình sẽ ghi nó vào environment. 

```rust
shmem.write_to_env("__AFL_SHM_ID").unwrap();
```

Tiếp theo chúng ta cần phải xử lý shared memory sao cho nó có thể thay đổi trong quá trình fuzzing. 

```rust
let shmem_buf = shmem.as_mut_slice();
```

Và cuối cùng mình sẽ build Observer sau khi có được TimeObserver và ShareMemoryMap. Với Observer thì mình chỉ cần đưa vào giá trị của ShareMemoryMap và mình gọi nó là shared_mem (dựa vào concept của forkserver_simple). 

Mình sẽ sử dụng [HitCountsMapObserver](https://docs.rs/libafl/latest/libafl/observers/map/struct.HitcountsMapObserver.html). Theo như mô tả trong libafl docs thì HitCountsMapObserver cần một "base object" để làm constructor, base object mình sử dụng đó là [MapObserver](https://docs.rs/libafl/latest/libafl/observers/map/trait.MapObserver.html). Object này sẽ xác định xem trong quá trình fuzzing liệu có testcase nào "suspicious" hay không. 

```rust=
let edges_observer =
        unsafe { HitcountsMapObserver::new(StdMapObserver::new("shared_mem", shmem_buf)) };
```

Chúng ta đã hoàn thành Observer, đi đến phần tiếp theo. 

#### 3rd Component: Feedback

Feedback nó giống như là output của Observer, nó sẽ xác định xem thử có outcome nào "suspicious" từ observer hay không, nếu như testcase đó có vẻ như là không ổn thì cái input được sử dụng cho lần fuzzing đó sẽ được đưa vào Corpus. Mình sẽ tạo Feedback dựa trên TimeObserver và CoverageMapObserver. 

```rust=
let mut feedback = feedback_or!(
    MaxMapFeedback::tracking(&edges_observer, true, false),
    TimeFeedback::with_observer(&timeObserver)
);
```

Đoạn mã rust ở trên, đối với CoverageMapObserver thì mình có sử dụng [MaxMapFeedback](https://docs.rs/libafl/latest/libafl/feedbacks/map/type.MaxMapFeedback.html) cái này được sử dụng để xác định output của HitcountsMapObserver’s coverage map, nếu như output của HitcountsMapObserver lớn hơn MAP_SIZE thì chắc chắn input của chúng ta có gì đó khiến cho nó như vậy. 
Đối với TimeObserver thì đơn giản mình sử dụng [TimeFeedback](https://docs.rs/libafl/0.10.1/libafl/feedbacks/struct.TimeFeedback.html). 

Với hai Observer ở trên, để kết hợp cả hai lại mình sử dụng `logical OR`, bởi vì mình chỉ cần một trong hai cái đó, nếu như outputt của HitcountsMapObserver lớn hơn so với entry của nó hoặc là TimeObserver lâu hơn so với thông thường thì có nghĩa là input của chúng ta có thể gây lỗi chương trình. 


Sau khi đã tìm được input có khả năng gây lỗi cho chương trình thì chúng ta cần phải xác định chính xác xem input có thực sự gây crash cho file thực thi hay không. Lần này thay vì sử dụng `logical OR` để xác định thì mình sẽ sử dụng `logical AND` để kết hợp cả hai lại với nhau, bởi vì một input gây crash cho chương trình thì chắc chắn thời gian nó sẽ bị timeout và input sẽ khiến cho chương trình  rẽ sang một hướng code khác trong coverage map.

```rust=
let mut objective = feedback_and_fast!(
        // Must be a crash
        TimeoutFeedback::new(),
        // Take it only if trigger new coverage over crashes
        MaxMapFeedback::new(&edges_observer)
```

Chúng ta di chuyển tới component State

#### 4th Component: State

Với component lần này thì mình sẽ sử dụng [StdState](https://docs.rs/libafl/latest/libafl/state/struct.StdState.html). StdState sẽ xác định state cho fuzzer, random number generator, corpora. 
```rust=
let mut state = StdState::new(
        StdRand::with_seed(current_nanos()),
        // Corpus that will be evolved, we keep it in memory for performance
        corpus_BytesInput,
        // Corpus in which we store solutions (crashes in this example),
        // on disk so the user can get them after stopping the fuzzer
        crash_corpus,
        // States of the feedbacks.
        // The feedbacks can report the data that should persist in the State.
        &mut feedback,
        // Same for objective feedbacks
        &mut objective,
    )
    .unwrap();
```

#### 5th Component: Monitor 

[Monitor](https://docs.rs/libafl/latest/libafl/monitors/trait.Monitor.html) sẽ theo dõi toàn bộ thông tin và đưa ra cách phù hợp nhất để có thể hiển thị các thông tin đó cho chúng ta. 

Mình sẽ sử dụng [SimpleMonitor](https://docs.rs/libafl/0.10.1/libafl/monitors/struct.SimpleMonitor.html), nó giống như printf trong C. Nó sẽ in ra các thông tin cho chúng ta trên terminal. 

```rust=
let monitor = SimpleMonitor::new(|s| println!("{s}"));
```

#### 6th Component: EventManager

Component này tương tự với Monitor, nó sẽ xử lý các Events trong quá trình fuzzing, ví dụ như là updating Monitor Component, logging và tìm các testcase khả nghi. 

`Simplest Methods as always`

```rust=
let mut mgr = SimpleEventManager::new(monitor);
```

#### 7th Component: Scheduler

Trong quá trình fuzzing chúng ta cần phải đưa vào các testcases khác nhau từ corpus thì [Scheduler](https://docs.rs/libafl/latest/libafl/schedulers/trait.Scheduler.html) sẽ đảm nhận vai trò này. Nó sẽ tạo ra các testcase mới phù hợp cho strategy của fuzzer từ corpus. Để ưu tiên các testcase "nhỏ, gọn" để tối ưu thời gian fuzzing thì mình sử dụng strategy [IndexesLenTimeMinimizerScheduler](https://docs.rs/libafl/0.10.1/libafl/schedulers/minimizer/type.IndexesLenTimeMinimizerScheduler.html) giống như trong concept của forkserver_simple. 

```rust=
let scheduler = IndexesLenTimeMinimizerScheduler::new(QueueScheduler::new());
```

#### 8th Component: Fuzzer

Đối với component này mình chọn [TimeoutForkserverExecutor](https://docs.rs/libafl/latest/libafl/executors/forkserver/struct.TimeoutForkserverExecutor.html). "Timeout forkserver" bao bọc quanh trình thực thi standard [ForkserverExecutor](https://docs.rs/libafl/0.10.1/libafl/executors/forkserver/struct.ForkserverExecutor.html) và thiết lập một thời gian chờ trước mỗi lần chạy. Có nghĩa trước khi chạy thì nó sẽ set timeout để có thể fork một process khác để fuzz. 

Chúng ta cần phải chỉ ra những gì mà chúng ta muốn thực thi cho Executor. Ở đây đó là

```bash=
exercise-1/xpdf/xpdf/install/bin/pdftotext PDF-FILE
```

```rust=
let mut fuzzer = StdFuzzer::new(scheduler, feedback, objective);
let mut forkserver = ForkserverExecutor::builder()
        .program("./xpdf/xpdf/install/bin/pdftotext")
        .parse_afl_cmdline(["@@"])
//Lí do có @@ ở đây đó chính là chỉ định cho ForkserverExecutor rằng chúng ta sử dụng BytesInput
        .coverage_map_size(MAP_SIZE)
        .build(tuple_list!(timeObserver, edges_observer))
        .unwrap();
let timeout = Duration::from_secs(5); //Chúng ta set timeout 5 giây
let mut executor = TimeoutForkserverExecutor::new(forkserver, timeout).unwrap();
```
Và chúng ta đi tới component cuối cùng: Mutator + Stage
#### 9th Component: Mutator + Stage

[Mutator](https://docs.rs/libafl/latest/libafl/mutators/trait.Mutator.html) như trong docs nói thì nó đơn giản chỉ nhận input vào và mutate nó. Và để chọn cho mutational stage thì mình sử dụng [Havoc Mutation](https://docs.rs/libafl/0.10.1/libafl/mutators/scheduled/fn.havoc_mutations.html). 

```rust=
let mutator = StdScheduledMutator::new(havoc_mutations());
let mut stages = tuple_list!(StdMutationalStage::new(mutator));
```

main.rs 
```rust=
use core::time::Duration;
use std::path::PathBuf;


use libafl::{
    corpus::{Corpus, InMemoryCorpus, OnDiskCorpus},
    events::SimpleEventManager,
    executors::{ForkserverExecutor, TimeoutForkserverExecutor},
    feedback_and_fast, feedback_or, Error, Fuzzer, StdFuzzer,
    feedbacks::{MaxMapFeedback, TimeFeedback, TimeoutFeedback},
    inputs::BytesInput,
    monitors::SimpleMonitor,
    mutators::{havoc_mutations, StdScheduledMutator},
    observers::{HitcountsMapObserver, StdMapObserver, TimeObserver},
    schedulers::{IndexesLenTimeMinimizerScheduler, QueueScheduler},
    stages::mutational::StdMutationalStage,
    state::{HasCorpus, StdState},
};
use libafl::bolts::{
    current_nanos,
    rands::StdRand,
    shmem::{ShMem, ShMemProvider, StdShMemProvider},
    tuples::{tuple_list, MatchName, Merge},
    AsMutSlice, Truncate,
};
const MAP_SIZE: usize = 65536;

fn main() -> Result<(), Error> {
    let corpus_directory = vec![PathBuf::from("./corpus")];
    let corpus_BytesInput = InMemoryCorpus::<BytesInput>::new();
    let crash_corpus = OnDiskCorpus::new(PathBuf::from("./crash"))?;
    let time_observer = TimeObserver::new("time");
    let mut shmem_provider = StdShMemProvider::new().unwrap();
    let mut shmem = shmem_provider.new_shmem(MAP_SIZE).unwrap();
    shmem.write_to_env("__AFL_SHM_ID").unwrap();
    let shmem_buf = shmem.as_mut_slice();
    let edges_observer =
        unsafe { HitcountsMapObserver::new(StdMapObserver::new("shared_mem", shmem_buf)) };
    let mut feedback = feedback_or!(
        MaxMapFeedback::tracking(&edges_observer, true, false),
        TimeFeedback::with_observer(&time_observer)
    );
    let mut objective = feedback_and_fast!(
        // Must be a crash
        TimeoutFeedback::new(),
        // Take it only if trigger new coverage over crashes
        // Uses `with_name` to create a different history from the `MaxMapFeedback` in `feedback` above
        MaxMapFeedback::new(&edges_observer)
    );
    let mut state = StdState::new(
        StdRand::with_seed(current_nanos()),
        // Corpus that will be evolved, we keep it in memory for performance
        corpus_BytesInput,
        // Corpus in which we store solutions (crashes in this example),
        // on disk so the user can get them after stopping the fuzzer
        crash_corpus,
        // States of the feedbacks.
        // The feedbacks can report the data that should persist in the State.
        &mut feedback,
        // Same for objective feedbacks
        &mut objective,
    )
    .unwrap();
    let monitor = SimpleMonitor::new(|s| println!("{s}"));
    let mut mgr = SimpleEventManager::new(monitor);
    let scheduler = IndexesLenTimeMinimizerScheduler::new(QueueScheduler::new());
    let mut fuzzer = StdFuzzer::new(scheduler, feedback, objective);
    let mut forkserver = ForkserverExecutor::builder()
        .program("./xpdf/install/bin/pdftotext")
        .parse_afl_cmdline(["@@"])
//Lí do có @@ ở đây đó chính là chỉ định cho ForkserverExecutor rằng chúng ta sử dụng BytesInput
        .coverage_map_size(MAP_SIZE)
        .build(tuple_list!(time_observer, edges_observer))
        .unwrap();
    let timeout = Duration::from_secs(5); //Chúng ta set timeout 5 giây
    let mut executor = TimeoutForkserverExecutor::new(forkserver, timeout).unwrap();
    if state.corpus().count() < 1 {
        state
            .load_initial_inputs(&mut fuzzer, &mut executor, &mut mgr, &corpus_directory)
            .unwrap_or_else(|err| {
                panic!(
                    "Failed to load initial corpus at {:?}: {:?}",
                    &corpus_directory, err
                )
            });
        println!("We imported {} inputs from disk.", state.corpus().count());
    }
    let mutator = StdScheduledMutator::new(havoc_mutations());
    let mut stages = tuple_list!(StdMutationalStage::new(mutator));
    fuzzer
        .fuzz_loop(&mut stages, &mut executor, &mut state, &mut mgr)
        .expect("Error in the fuzzing loop");
    
    Ok(())
}
```
### Fuzz'em All 

Sau khi đã hoàn thành build các component thì chúng ta thực hiện fuzz. Trong fuzzer thì chúng ta sẽ truyền vào  các component cần thiết như là: stages, executor, state, event manager. 

```rust=
fuzzer
        .fuzz_loop(&mut stages, &mut executor, &mut state, &mut mgr)
        .expect("Error in the fuzzing loop");
```

#### Build fuzzer 

Bởi vì trong file Makefile.toml mình đã đưa vào task cargo build nên nó sẽ tự động chạy fuzzing cho mình. 



```bash=
cd ~/fuzzing-101/exercise-1
cargo build --release
```
Sau khi build xong thì file thực thi 
#### And the magic happen

```bash=
../target/release/exercise-one-solution
```
Result
```
[Testcase #0] run time: 0h-15m-18s, clients: 1, corpus: 1230, objectives: 1, executions: 666438, exec/sec: 725.6
[Stats #0] run time: 0h-15m-19s, clients: 1, corpus: 1230, objectives: 1, executions: 666835, exec/sec: 725.6
[Stats #0] run time: 0h-15m-19s, clients: 1, corpus: 1230, objectives: 1, executions: 666835, exec/sec: 725.3
[Testcase #0] run time: 0h-15m-19s, clients: 1, corpus: 1231, objectives: 1, executions: 667085, exec/sec: 725.6
[Stats #0] run time: 0h-15m-19s, clients: 1, corpus: 1231, objectives: 1, executions: 667085, exec/sec: 725.4
[Testcase #0] run time: 0h-15m-19s, clients: 1, corpus: 1232, objectives: 1, executions: 667180, exec/sec: 725.5
[Stats #0] run time: 0h-15m-21s, clients: 1, corpus: 1232, objectives: 1, executions: 667180, exec/sec: 723.7
[Testcase #0] run time: 0h-15m-21s, clients: 1, corpus: 1233, objectives: 1, executions: 668717, exec/sec: 725.4
[Stats #0] run time: 0h-15m-30s, clients: 1, corpus: 1233, objectives: 1, executions: 668717, exec/sec: 718.6
[Testcase #0] run time: 0h-15m-30s, clients: 1, corpus: 1234, objectives: 1, executions: 675056, exec/sec: 725.5
[Stats #0] run time: 0h-15m-34s, clients: 1, corpus: 1234, objectives: 1, executions: 677239, exec/sec: 725.0
```


`Sample gây crash được tạo ra từ fuzzer`
![image](https://hackmd.io/_uploads/ryszLNbHp.png)

```bash=
./xpdf/install/bin/pdftotext crash/067cae960270b247
```

![image](https://hackmd.io/_uploads/B1Sh8Vbr6.png)


### Conclusion

Sau khi chạy cỡ 15p (tùy máy) thì đã có 1 file đạt được mục đích của chúng ta với bằng chứng là `objectives: 1` được in ra từ component `Monitor`. Mình nghĩ là có cách để tối ưu thời gian hơn, mình tìm hiểu thì sử dụng `afl-clang-cto` thay vì `afl-clang-fast` và sử dụng `in-process` executor thay vì là `forkserver`. 

Nếu như bạn có câu hỏi thì hay dm cho mình 

Twitter: @y198_nt
Discord: y198#6338

-------------------------
Thank you for reading 🫶 






































