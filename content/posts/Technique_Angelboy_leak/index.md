---
title: "Technique: Angelboy's Leak: using IO_FILE to leak libc"
date: 2022-09-16
draft: false
summary: "A technique for you to leak libc without output function"
tags: ["Technique"]
---

## :memo: Tản mạn một xíu về technique trên?

### Libc là gì :rocket: 
*`(nếu như các bạn đã biết libc là gì và biết technique ret2libc thì có thể bỏ qua phần này) `*
**Đối với một số bạn chơi Pwnable nói riêng và các bạn chơi CTF nói chung thì đã ít nhiều nghe đến cụm từ "Libc". Vậy libc là gì?** 
*`"Cụm từ "libc" thường được dùng như là một từ viết tắt cho "standard C library", một thư viện các hàm cái mà có thể dùng bởi tất cả C programs"`*

Vậy có nghĩa, địa chỉ gốc của libc rất là quan trọng, khi bạn đã có địa chỉ gốc của libc bạn có thể làm rất là nhiều thứ, điển hình nhất là  bạn có thể dùng one_gadget để execve('/bin/sh',0,0) hoặc là gọi system('/bin/sh'),..... Nôm na cuối cùng libc dùng để pop a shell.
Để có thể đối phó với vấn đề trên, một số  challenge's author sẽ không cho bất cứ function(puts, printf,....) để có thể leak ra địa chỉ của libc.
![](https://i.imgur.com/rGakA4H.png)


## How this technique works? :face_with_monocle: 

Mình không chắc ai là người tạo ra technique này nhưng mà lần đầu tiên mình thấy nó được áp dụng vào trong ctf là vào giải HITCON 2018 câu babytcache của angelboy.tw, sau đó anh ấy có publish solution cho câu này tại đây: github.com/scwuaptx/CTF/blob/master/2018-writeup/hitcon/baby_tcache.py

Vậy nên technique này yang hồ hay gọi là: **Angelboy's leak**
Technique này sẽ giải quyết vấn đề thay đổi cấu trúc stdout của IO_FILE để có thể biến nó thành hàm puts để leak địa chỉ của libc. Nó thay đổi cấu trúc của stdout của IO_FILE bằng cách modify flag bit của stdout thành `0xfbad1800` và khiến cho byte cuối của `_IO_write_base` nhỏ lại. Ở bên dưới mình sẽ nói tại sao modify flag bit của stdout thành 0xfbad1800. 

### Đầu tiên ta phải hiểu hàm puts hoạt động ra sao :face_with_raised_eyebrow: 

Một cái ví dụ cơ bản về hàm puts gọi trong libc, thì mình sẽ dùng một chương trình in ra "Hello world", một chương trình từ thuở sơ khai ai cũng phải tiếp xúc trong cái bộ môn này. 
```c
#include <stdio.h>
void main()
{
    printf("Hello World\n);
}
```
Ở các version sau này của libc thì khi compile ở assembly code thì nó sẽ gọi trực tiếp đến hàm printf luôn nhưng mà ở các libc cũ thì nó sẽ gọi đến hàm puts  nhưng mà điều đó vẫn không quan trọng cho lắm


```asm
  .file "hello.c"
  .section  .rodata
.LC0:
  .string "Hello World!"
  .text
  .globl  main
  .type main, @function
main:
  pushq %rbp
  movq  %rsp, %rbp
  movl  $.LC0, %edi
  call  puts
  popq  %rbp
  ret
```
Tiếp theo thì ta sẽ xem hàm puts làm gì ở libc-2.31 (phiên bản mà mình đang sử dụng hiện tại)
Thực tế thì codebase của glibc rất là rộng và cách hoạt động của nó nằm ở phạm vị vĩ mô, vì thế nên rất khó để có thể định hướng được mục tiêu mà mình cần. Khi nhìn vào codebase ta có thể thấy `weak_alias (_IO_puts, puts)` ở trong file `libio/ioputs.c`. Ở trong glibc, điều này có nghĩa là bất kỳ ai khi gọi hàm puts thì thực tế thay vào đó sẽ gọi IO_puts 
Hàm IO_puts như sau 
```c
int
_IO_puts (const char *str)
{
  int result = EOF;
  size_t len = strlen (str);
  _IO_acquire_lock (_IO_stdout);

  if ((_IO_vtable_offset (_IO_stdout) != 0
       || _IO_fwide (_IO_stdout, -1) == -1)
      && _IO_sputn (_IO_stdout, str, len) == len
      && _IO_putc_unlocked ('\n', _IO_stdout) != EOF)
    result = MIN (INT_MAX, len + 1);

  _IO_release_lock (_IO_stdout);
  return result;
}
```

Mớ ở trên chúng ta không cần phải để ý tất cả mà chỉ cần focus vô hàm IO_sputn. Hàm IO_sputn được định nghĩa tại `libio/libioP.h, line 374 (as a macro)` Đào sâu vào trong ta thấy nó là 1 nùi các macro nhìn mà không thấy đường ra 
![](https://i.imgur.com/QYvhPCB.png)
Sau một hồi mắt mình đảo như rang lạc thì mình đã tìm ra được một cái function liên quan đến vấn đề mà chúng ta đang đề cập, đó chính là `_IO_new_file_xsputn` được mô tả tại 
`libio/libioP.h, line 596 (as a prototype)` Sau một thời gian mò mẫm code của hàm `_IO_new_file_xsputn` thì cuối cùng nó cũng đã dừng lại tại hàm `_IO_OVERFLOW` được defined tại `libio/libioP.h, line 141 (as a macro)` 
(Làm cái mớ này mình cũng đang không biết đang làm mics hay làm pwn nữa ... :confused:) 
Và cuối cùng thì đây chính là cái mà chúng ta đang cần tìm: 

```c
int
_IO_new_file_overflow (FILE *f, int ch)
{
  if (f->_flags & _IO_NO_WRITES) /* SET ERROR */
    {
      f->_flags |= _IO_ERR_SEEN;
      __set_errno (EBADF);
      return EOF;
    }
  /* If currently reading or no buffer allocated. */
  if ((f->_flags & _IO_CURRENTLY_PUTTING) == 0 || f->_IO_write_base == NULL)
    {
      /* Allocate a buffer if needed. */
      if (f->_IO_write_base == NULL)
	{
	  _IO_doallocbuf (f);
	  _IO_setg (f, f->_IO_buf_base, f->_IO_buf_base, f->_IO_buf_base);
	}
      if (__glibc_unlikely (_IO_in_backup (f)))
	{
	  size_t nbackup = f->_IO_read_end - f->_IO_read_ptr;
	  _IO_free_backup_area (f);
	  f->_IO_read_base -= MIN (nbackup,
				   f->_IO_read_base - f->_IO_buf_base);
	  f->_IO_read_ptr = f->_IO_read_base;
	}

      if (f->_IO_read_ptr == f->_IO_buf_end)
	f->_IO_read_end = f->_IO_read_ptr = f->_IO_buf_base;
      f->_IO_write_ptr = f->_IO_read_ptr;
      f->_IO_write_base = f->_IO_write_ptr;
      f->_IO_write_end = f->_IO_buf_end;
      f->_IO_read_base = f->_IO_read_ptr = f->_IO_read_end;

      f->_flags |= _IO_CURRENTLY_PUTTING;
      if (f->_mode <= 0 && f->_flags & (_IO_LINE_BUF | _IO_UNBUFFERED))
	f->_IO_write_end = f->_IO_write_ptr;
    }
  if (ch == EOF)
    return _IO_do_write (f, f->_IO_write_base,
			 f->_IO_write_ptr - f->_IO_write_base);
  if (f->_IO_write_ptr == f->_IO_buf_end ) /* Buffer is really full */
    if (_IO_do_flush (f) == EOF)
      return EOF;
  *f->_IO_write_ptr++ = ch;
  if ((f->_flags & _IO_UNBUFFERED)
      || ((f->_flags & _IO_LINE_BUF) && ch == '\n'))
    if (_IO_do_write (f, f->_IO_write_base,
		      f->_IO_write_ptr - f->_IO_write_base) == EOF)
      return EOF;
  return (unsigned char) ch;
}
```
Để có thể giải thích cái hàm trên thì chắc đến mùa quýt mình mới giải quyết được vấn đề này mất, chúng ta hãy focus vào hàm `_IO_do_write` thì nó chính là hàm cuối cùng được gọi và `_IO_write_base` chính là tham số cuối cùng mà chúng ta cần modify. Để có thể chạm được đến hàm if cuối cùng thì chúng ta cần phải bypass tất cả hàm if ở trên, chúng ta không muốn phải vướng vào một trong các nhánh của hàm if đó đâu. Quay về bên trên cùng, chúng ta sẽ bypass từng hàm if một. 
* Ở hàm if đầu tiên cái giá trị `f->flag & _IO_NO_WRITES` phải là 0, để không dính vào bên trong hàm if. 
* Tiếp theo chúng ta phải set `f->flag & _IO_CURRENTLY_PUTTING` bằng 1 để không vào bên trong hàm if thứ 2
* Đào sâu một tí vào hàm `_IO_do_write` thì ta sẽ thấy một hàm nữa chạy cùng với hàm trên đó là `_IO_new_do_write`
```c
static size_t
new_do_write (FILE *fp, const char *data, size_t to_do)
{
  size_t count;
  if (fp->_flags & _IO_IS_APPENDING)
    fp->_offset = _IO_pos_BAD;
  else if (fp->_IO_read_end != fp->_IO_write_base)
    {
      off64_t new_pos
	= _IO_SYSSEEK (fp, fp->_IO_write_base - fp->_IO_read_end, 1);
      if (new_pos == _IO_pos_BAD)
	return 0;
      fp->_offset = new_pos;
    }
  count = _IO_SYSWRITE (fp, data, to_do); //our aim
 ...
  return count;
}
```
Và đây chính là mục tiêu cuối cùng của chúng ta (hoặc thứ gì đó xêm xêm) `_IO_SYSWRITE (fp, data, to_do)` Sau khi lược qua các hàm if thì để có thể bypass tất cả các hàm if trên là bất khả thi(nhiều lí do khó có thể mà khai thác được, có một cái vấn đề mà chúng ta không thể control nó được đó là `fp->_IO_write_base - fp->_IO_read_end`. Nếu như chúng ta set `fp->_IO_read_end` thành 0, dẫn tới hậu quả là tham số thứ 2 sẽ quá dài, và nếu ta set `fp->_IO_write_base > fp->_IO_read_end` thì chúng ta sẽ dính lỗi ở 1 chỗ khác, tại vì `_IO_write_base` sẽ trở nên lớn hơn `_IO_write_ptr` mà cái ta cần là `_IO_write_base` phải nhỏ hơn `_IO_write_ptr`), dường như chúng ta chỉ có lựa chọn skip qua hàm else if, để hiện thực hóa điều này thì  ta cần focus vào`fp->_IO_write_base` và `fp->_IO_read_end`, dựa vào source code trên thì ta có thể suy ra được đó là ta phải set `fp->flags & _IO_is_appending`
### Inconclusion
`_IO_file` được bao gồm trong `_IO_FILE_plus` có cấu trúc như bên dưới:
```c 
struct _IO_FILE_plus
{
    _IO_FILE file;
    const struct _IO_jump_t *vtable;
};
```
![](https://i.imgur.com/s7xIJqW.png)
`_IO_FILE` được định nghĩa dưới dạng linked list, đầu node của list trên là `_IO_list_all`. Tóm tắt sơ qua thì `IO_list_all` sẽ trỏ đến `stderr` (file descriptor là 2) tiếp theo sẽ trỏ đến `stdout`(file descriptor là 1) và cuối cùng trỏ đến stdin(file descriptor là 0). 
Dưới đây là những giá trị cần thiết cho việc bypass toàn bộ những hàm if ở bên trên và đạt đến mục tiêu cuối cùng. 
```c 
_flags = 0xfbad0000 //magic number
_flags &= _IO_NO_WRITE //flag = 0xfbad0000
_flag |= _IO_CURRENTLY_PUTTING //flag = 0xfbad0800
_flag |= _IO_IS_APPENDING //flag = 0xfbad1800
```

*Vậy tất cả những gì chúng ta cần làm đó chính là set `stdout->flags` thành 0xfbad1800 và để leak mà thứ chúng ta cần thì chúng ta phải tính toán offset cụ thể để có thể ghi đè, cụ thể ở đây đó chính là cái chức năng mà ta output ví dụ như là puts chẳng hạn phải dựa vào kết quả của `IO_write_ptr - IO_write_base`*


---

Trăm nghe thì không bằng một thấy, ở dưới mình demo technique trên bằng câu weapon của giải De1CTF

## Weapon 
---

### Analyze 

Như một thói quen thì mọi challenge pwn thì mình sẽ luôn check file, checksec, check các lỗi cơ bản, v...v..
![](https://i.imgur.com/hZJyPLt.png)

Nhìn vào thì đề bài cho một file ELF 64-bit, bị stripped và full mitigation (full đồ full giáp ....)
![](https://i.imgur.com/geNstgd.png)
"*Là một thằng đàn ông thì không chùn bước trước mọi thử thách*"

![](https://i.imgur.com/Ky5hu8F.png)

Đề cho ta 1 vòng lặp, trong đó có 3 function cơ bản của 1 bài heap: Create, delete và không được cung cấp hàm in để tránh leak libc address hoặc những address quan trọng, bù lại ta được hàm rename một weapon(chắc chắn sẽ có ích trong lương lai)

* Hàm Create: Đơn giản chỉ là nhập size của một chunk, index và data của chunk đó thông qua biến name. 
* Hàm Delete: Tương tự như mọi đề heap khác, chỉ định free một chunk đã có sẵn thông qua biến index
* Hàm rename: Thay đổi nội dung của một chunk chỉ định thông qua biến index. 


Nhìn kỹ hơn bằng ida(mình đã thay đổi tên biến và một số tên hàm để nhìn hiểu rõ hơn)
* Hàm main như mình đã nói ở trên :arrow_up: 
![](https://i.imgur.com/6jjUZyg.png)

* Hàm Create:
![](https://i.imgur.com/sYxmTqp.png)

Bài này chỉ giới hạn size của một chunk trong khoảng 0 đến 96, vì libc bài này cho chỉ là phiên bản libc-2.23 vậy nên sẽ không có tcache mà bài này chỉ gói gọn trong fastbin, tuy bị giới hạn trong fastbin nhưng dường như bài này không có giới hạn số lượng chunk được cho phép.

* Hàm Delete:

![](https://i.imgur.com/7g3oZ41.png)

Bug nằm ở trong hàm delete này, bất cứ một người chơi pwn nào khi nhìn vào hàm này cũng sẽ nhận ra được bug :lol: Bug ở đây đó là hàm này không set pointer về null dẫn đến lỗi use-after-free hoặc là double free, có rất là nhiều cách để tận dụng hai lỗi này. 

Ở bài này ta có thể tận dụng lỗi uaf tạo ra chunk overlapped để hình thành unsorted bin sau đó ghi đè fd một chunk để leak libc, ngoài ra thì ta có thể tận dụng lỗi uaf để hướng đến cấu trúc stdout, modify flags bit để leak libc, vì bài này không có hàm in ra nên mình sẽ kết hợp cả hai cách trên để có thể leak ra được flag.

Mình không biết bài này rốt cuộc bị cái gì, nhưng mà làm ở local dùng env `libc-2.23.so` thì bị lỗi timeout, còn nếu dùng env ở máy mình thì không tận dụng bug ở trên được ,mình ngồi loay hoay sửa gần cả tiếng vẫn không fix được :sadge_pepe:. Vậy nên mình sẽ nói sơ qua về ý tưởng exploit và mình để script exploit ở bên dưới, còn nếu bạn muốn thì bạn hãy debug để hình dung technique trên hoạt động ra sao, I'm so sorry :(

### Hướng exploit 
*Đầu tiên thì fd pointer của fastbin sẽ trỏ đến libc cụ thể là `main_arena + 88`, nhưng bởi vì size được cho phép phải nhỏ hơn 0x60 nên không thể trực tiếp lấy được địa chỉ của libc thông qua fd pointer, thay vào đó ta sẽ tận dụng lỗi uaf, thông qua bug trên thì ta có thể đẩy 1 chunk vào fastbin, sau đó ta có thể fake một chunk với size tương thích với size của unsorted_bin, sau đó free chunk đó một lần nữa, kết quả là chunk mà chúng ta fake sẽ nằm trong fastbin và unsorted_bin, ngoài ra fd pointer sẽ trỏ đến libc. Sau khi có được libc thì chỉ cần tận dụng lỗi uaf ghi đè malloc_hook thành one_gadget để có được shell. Ý tưởng là như vậy.*

* Đầu tiên thì mình sẽ alloc 3 chunk với size 0x70 và sau đó free hai chunk đầu tiên để tận dụng lỗi uaf với mục đích chồng chéo các chunk lên nhau cho bước tiếp theo đó là modify địa chỉ cần muốn. 
```py
alloc(0,0x60,p64(0) + p64(0x71))
alloc(1,0x60,p64(0) + p64(0x51))
alloc(2,0x60,p64(0)*3 + p64(0x51))
delete(0)
delete(1)
rename(1,b'\x10')
alloc(3,0x60,b'a') # bây giờ fd của chunk 3 trỏ tới địa chỉ của chunk1+0x10
```

* Bây giờ ta malloc chunk 4, sau đó rename chunk 4 để có thể modify size của chunk 1 bởi vì ta đã tạo 1 link giữa chunk 3 và chunk 1(fd chunk 3 -> chunk1 + 0x10) có nghĩa là khi ta modify chunk 3 thì ta đang modify chunk 1. Free chunk 1 để đẩy chunk 1 vào fastbin, thay đổi size sao cho size của chunk 1 tương thích với size của unsorted_bin. Kết quả ta thu lại được đó là chunk 1 đang nằm ở fastbin và unsorted_bin 

*(Minh họa cho ý tưởng trên)*
```
alloc(4,0x60,p64(0)*0xb + p64(0x71))
delete(1)
rename(4,p64(0)*0xb + p64(0x91))
delete(1)
gdb.attach(r)
```

* Bây giờ thì ta chỉ cần modify 2 byte cuối fd pointer của chunk 1(main_arena + 88) nằm trong unsorted_bin thành địa chỉ mà ta muốn. Cái mà gần nhất với `main_arena + 88` chính là `_IO_2_1_stdout`, chỉ có 4 byte cuối của hai địa chỉ mà ta nói ở trên là khác nhau 


Bởi vì aslr trên server được bật vì vậy nếu ta ghi đè 0x7fxxxxx5b78 thành 0x7fxxxxx6620 thì không khả thi vì 3 bits cuối 620 sẽ giữ nguyên, nhưng bit thứ 4 từ dưới lên("6") sẽ luôn random 

Tìm kiếm một lúc thì có 1 địa chỉ phù hợp đó là 0x7fxxxxx25dd, vì bit 5dd(địa chỉ của fake chunk) giữ nguyên còn bit có giá trị "2" random thì ta có thể brute-force đến khi nào gặp được bit đó. 
Sau khi ta đã applied địa chỉ fd của 2 chunk(một cái nằm ở fastbin và cái còn lại ở unsorted_bin) có size 0x70 gần với địa chỉ của `_IO_2_1_stdout` bằng cách ghi đè địa chỉ của `main_arena+88` thành 0x7fxxxx25dd thì ta sẽ fill biến flags của `_IO_stdout` thành 0xfbad1800 và 2 số cuối của `_IO_write_base` thành \x00 sẽ khiến cho nó nhỏ hơn do đó ta sẽ leak được nhiều thứ hơn.
```py
rename(1,b'\xdd\x25')

alloc(5,0x60,b'a')
alloc(6,0x60,b'A'*0x33 + p64(0xfbad1800) + p64(0)*3 + b'\x00')
```
Sau khi đã ghi đè thì struct của `_IO_2_1_stdout` sẽ như này 
```c
pwndbg> p _IO_2_1_stdout_
$2 = {
  file = {
    _flags = -72542208,  //0xfbad1800
    _IO_read_ptr = 0x0, 
    _IO_read_end = 0x0, 
    _IO_read_base = 0x0, 
    _IO_write_base = 0x7ffff7dd2600 <_IO_2_1_stderr_+192> 'A' <repeats 32 times>, //ghi đè 2 số cuối thành \x00
    .
    .
    .
  }, 
  vtable = 0x7ffff7dd06e0 <_IO_file_jumps>
}
```
Sau khi modified stdout thì khi chương trình gọi puts(ở lần tiếp theo) thì chương trình sẽ in ra địa chỉ của `_IO_2_1_stderr` vì nó nằm ở sau `_IO_list_all`
(tỉ lệ 1/16 khi brute-force ta sẽ leak được địa chỉ của libc :lol:)
![](Untitled.png)


Sau khi đã có libc base address thì ta có được địa chỉ gốc của malloc_hook, sau đó dùng theo phương pháp trên, ta malloc một chunk với size 0x60 để đẩy chunk đó vào fastbin, tiếp theo modify fd của chunk đó vào fake chunk mà ta muốn, ở đây đó là malloc_hook - 0x23. Malloc chunk đó lại để có được fake chunk ta muốn, sau đó malloc một chunk với size 0x60, fill bởi one_gadget. Cuối cùng malloc một chunk mới để trigger malloc_hook là có được shell.



