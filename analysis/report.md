# CWE 静态分析报告

共发现 **41** 个告警。

## CWE-398 · testcase1/003.main.cpp:1

- 规则：`DEMO-CWE-398-BUILD-BUG`
- 严重性：`warning`
- 说明：Linux/Arch is case-sensitive: source includes `schedule.h`, but sample file is `Schedule.h`.
- 证据：`#include "schedule.h"`
- 建议：Rename the include or the file so GitHub Actions/Linux can compile it.

## CWE-120/CWE-787 · testcase1/003.main.cpp:36

- 规则：`DEMO-CWE-120-CIN-CHAR-ARRAY`
- 严重性：`error`
- 说明：`cin >> command` writes into fixed char[30] without a width limit.
- 证据：`cin>>command;`
- 建议：Replace the buffer with std::string, or use std::setw(buffer_size) before extraction.

## CWE-120/CWE-787 · testcase1/003.main.cpp:43

- 规则：`DEMO-CWE-120-CIN-CHAR-ARRAY`
- 严重性：`error`
- 说明：`cin >> name` writes into fixed char[20] without a width limit.
- 证据：`cin>>name>>time;`
- 建议：Replace the buffer with std::string, or use std::setw(buffer_size) before extraction.

## CWE-120/CWE-787 · testcase1/003.main.cpp:48

- 规则：`DEMO-CWE-120-CIN-CHAR-ARRAY`
- 严重性：`error`
- 说明：`cin >> name` writes into fixed char[20] without a width limit.
- 证据：`cin>>name;`
- 建议：Replace the buffer with std::string, or use std::setw(buffer_size) before extraction.

## CWE-120/CWE-787 · testcase1/Schedule.cpp:20

- 规则：`DEMO-CWE-120-STRCPY`
- 严重性：`error`
- 说明：`strcpy` copies attacker/user-controlled strings without checking destination capacity.
- 证据：`strcpy(p->name,"NoName");//进程名字`
- 建议：Use std::string or a bounded copy routine and explicitly check destination size.

## CWE-120/CWE-787 · testcase1/Schedule.cpp:141

- 规则：`DEMO-CWE-120-STRCPY`
- 严重性：`error`
- 说明：`strcpy` copies attacker/user-controlled strings without checking destination capacity.
- 证据：`strcpy(newPcb->name,name); //填写新进程的名字`
- 建议：Use std::string or a bounded copy routine and explicitly check destination size.

## CWE-362/CWE-667 · testcase1/Schedule.cpp:207

- 规则：`DEMO-CWE-362-THREAD`
- 严重性：`warning`
- 说明：Use of `SuspendThread` can interrupt code while locks or shared state are inconsistent.
- 证据：`SuspendThread(runPCB->hThis);`
- 建议：Use cooperative cancellation and wait/join semantics instead of forced thread termination/suspension.

## CWE-362/CWE-667 · testcase1/Schedule.cpp:222

- 规则：`DEMO-CWE-362-THREAD`
- 严重性：`warning`
- 说明：Use of `TerminateThread` can interrupt code while locks or shared state are inconsistent.
- 证据：`if(!TerminateThread(runPCB->hThis,1))`
- 建议：Use cooperative cancellation and wait/join semantics instead of forced thread termination/suspension.

## CWE-362/CWE-667 · testcase1/Schedule.cpp:272

- 规则：`DEMO-CWE-362-THREAD`
- 严重性：`warning`
- 说明：Use of `TerminateThread` can interrupt code while locks or shared state are inconsistent.
- 证据：`if(!(TerminateThread(removeTarget->hThis,1)))`
- 建议：Use cooperative cancellation and wait/join semantics instead of forced thread termination/suspension.

## CWE-362/CWE-667 · testcase1/Schedule.cpp:321

- 规则：`DEMO-CWE-362-THREAD`
- 严重性：`warning`
- 说明：Use of `TerminateThread` can interrupt code while locks or shared state are inconsistent.
- 证据：`if(!TerminateThread(removeTarget->hThis,0))//执行撤销进程的操作`
- 建议：Use cooperative cancellation and wait/join semantics instead of forced thread termination/suspension.

## CWE-398 · testcase1/Schedule.cpp:367

- 规则：`DEMO-CWE-398-BUILD-BUG`
- 严重性：`warning`
- 说明：Suspicious `<` appears where stream insertion `<<` was probably intended.
- 证据：`log<<"--"<<tmp->id<<':'<<tmp->name<<"--";`
- 建议：Change `<` to `<<` and add a compilation job to CI.

## CWE-398 · testcase1/Schedule.cpp:382

- 规则：`DEMO-CWE-398-BUILD-BUG`
- 严重性：`warning`
- 说明：Suspicious `<` appears where stream insertion `<<` was probably intended.
- 证据：`cout<<"--"<<tmp->id<<':'<<tmp->name<"--";`
- 建议：Change `<` to `<<` and add a compilation job to CI.

## CWE-362/CWE-667 · testcase1/Schedule.cpp:406

- 规则：`DEMO-CWE-362-THREAD`
- 严重性：`warning`
- 说明：Use of `TerminateThread` can interrupt code while locks or shared state are inconsistent.
- 证据：`TerminateThread(runPCB->hThis,0);`
- 建议：Use cooperative cancellation and wait/join semantics instead of forced thread termination/suspension.

## CWE-362/CWE-667 · testcase1/Schedule.cpp:413

- 规则：`DEMO-CWE-362-THREAD`
- 严重性：`warning`
- 说明：Use of `TerminateThread` can interrupt code while locks or shared state are inconsistent.
- 证据：`if(!TerminateThread(p->hThis,0))`
- 建议：Use cooperative cancellation and wait/join semantics instead of forced thread termination/suspension.

## CWE-20/CWE-252 · testcase2/2.cpp:31

- 规则：`DEMO-CWE-20-SCANF-RETURN`
- 严重性：`warning`
- 说明：Return value of `scanf` is ignored when reading `nums`.
- 证据：`scanf("%d",&nums);`
- 建议：Require `scanf(...) == 1`; reject non-numeric input and initialize variables safely.

## CWE-20/CWE-252 · testcase2/2.cpp:35

- 规则：`DEMO-CWE-20-SCANF-RETURN`
- 严重性：`warning`
- 说明：Return value of `scanf` is ignored when reading `j`.
- 证据：`scanf("%d",&j);`
- 建议：Require `scanf(...) == 1`; reject non-numeric input and initialize variables safely.

## CWE-330 · testcase2/2.cpp:63

- 规则：`DEMO-CWE-330-RAND`
- 严重性：`note`
- 说明：`rand()` is predictable; do not use it for security-sensitive randomness.
- 证据：`numbers[i] = rand() % 10;//生成区间0`9的随机页面引用串`
- 建议：For simulation this is acceptable if documented; otherwise use a CSPRNG.

## CWE-20/CWE-787 · testcase2/2.cpp:70

- 规则：`DEMO-CWE-787-INPUT-BOUND`
- 严重性：`error`
- 说明：Input variable `nums` controls a loop that indexes fixed array `stack` with capacity 7.
- 证据：`for(j=0;j<nums;j++)`
- 建议：Validate `nums` before the loop, e.g. `if (nums < 1 || nums > 7) return;`.

## CWE-20/CWE-787 · testcase2/2.cpp:77

- 规则：`DEMO-CWE-787-INPUT-BOUND`
- 严重性：`error`
- 说明：Input variable `nums` controls a loop that indexes fixed array `stack` with capacity 7.
- 证据：`for(i=0;i<nums;i++)`
- 建议：Validate `nums` before the loop, e.g. `if (nums < 1 || nums > 7) return;`.

## CWE-20/CWE-787 · testcase2/2.cpp:100

- 规则：`DEMO-CWE-787-INPUT-BOUND`
- 严重性：`error`
- 说明：Input variable `nums` controls a loop that indexes fixed array `numbers` with capacity 20.
- 证据：`for(m=0;m<nums;m++)`
- 建议：Validate `nums` before the loop, e.g. `if (nums < 1 || nums > 20) return;`.

## CWE-20/CWE-787 · testcase2/2.cpp:104

- 规则：`DEMO-CWE-787-INPUT-BOUND`
- 严重性：`error`
- 说明：Input variable `nums` controls a loop that indexes fixed array `numbers` with capacity 20.
- 证据：`for(k=0;k<nums;k++)`
- 建议：Validate `nums` before the loop, e.g. `if (nums < 1 || nums > 20) return;`.

## CWE-20/CWE-787 · testcase2/2.cpp:134

- 规则：`DEMO-CWE-787-INPUT-BOUND`
- 严重性：`error`
- 说明：Input variable `nums` controls a loop that indexes fixed array `stack` with capacity 7.
- 证据：`for(i=1;i<nums;i++)//前半部分，页面空置的情况`
- 建议：Validate `nums` before the loop, e.g. `if (nums < 1 || nums > 7) return;`.

## CWE-20/CWE-787 · testcase2/2.cpp:136

- 规则：`DEMO-CWE-787-INPUT-BOUND`
- 严重性：`error`
- 说明：Input variable `nums` controls a loop that indexes fixed array `numbers` with capacity 20.
- 证据：`for(j=0;j<nums;j++)`
- 建议：Validate `nums` before the loop, e.g. `if (nums < 1 || nums > 20) return;`.

## CWE-20/CWE-787 · testcase2/2.cpp:141

- 规则：`DEMO-CWE-787-INPUT-BOUND`
- 严重性：`error`
- 说明：Input variable `nums` controls a loop that indexes fixed array `numbers` with capacity 20.
- 证据：`for(j=0;j<nums;j++)  //判断要插入的是否在栈中已经存在`
- 建议：Validate `nums` before the loop, e.g. `if (nums < 1 || nums > 20) return;`.

## CWE-20/CWE-787 · testcase2/2.cpp:153

- 规则：`DEMO-CWE-787-INPUT-BOUND`
- 严重性：`error`
- 说明：Input variable `nums` controls a loop that indexes fixed array `numbers` with capacity 20.
- 证据：`for(j=0;j<nums;j++)`
- 建议：Validate `nums` before the loop, e.g. `if (nums < 1 || nums > 20) return;`.

## CWE-20/CWE-787 · testcase2/2.cpp:175

- 规则：`DEMO-CWE-787-INPUT-BOUND`
- 严重性：`error`
- 说明：Input variable `nums` controls a loop that indexes fixed array `numbers` with capacity 20.
- 证据：`for(j=0;j<nums;j++)`
- 建议：Validate `nums` before the loop, e.g. `if (nums < 1 || nums > 20) return;`.

## CWE-20/CWE-787 · testcase2/2.cpp:179

- 规则：`DEMO-CWE-787-INPUT-BOUND`
- 严重性：`error`
- 说明：Input variable `nums` controls a loop that indexes fixed array `numbers` with capacity 20.
- 证据：`for(j=0;j<nums;j++)//判断输入串中的数字，是否已经在栈中`
- 建议：Validate `nums` before the loop, e.g. `if (nums < 1 || nums > 20) return;`.

## CWE-20/CWE-787 · testcase2/2.cpp:190

- 规则：`DEMO-CWE-787-INPUT-BOUND`
- 严重性：`error`
- 说明：Input variable `nums` controls a loop that indexes fixed array `sequence` with capacity 7.
- 证据：`for(j=0;j<nums;j++)//找优先序列中为0的`
- 建议：Validate `nums` before the loop, e.g. `if (nums < 1 || nums > 7) return;`.

## CWE-20/CWE-787 · testcase2/2.cpp:198

- 规则：`DEMO-CWE-787-INPUT-BOUND`
- 严重性：`error`
- 说明：Input variable `nums` controls a loop that indexes fixed array `numbers` with capacity 20.
- 证据：`for(j=0;j<nums;j++)`
- 建议：Validate `nums` before the loop, e.g. `if (nums < 1 || nums > 20) return;`.

## CWE-20/CWE-787 · testcase2/2.cpp:210

- 规则：`DEMO-CWE-787-INPUT-BOUND`
- 严重性：`error`
- 说明：Input variable `nums` controls a loop that indexes fixed array `sequence` with capacity 7.
- 证据：`for(j=0;j<nums;j++)`
- 建议：Validate `nums` before the loop, e.g. `if (nums < 1 || nums > 7) return;`.

## CWE-20/CWE-787 · testcase2/2.cpp:222

- 规则：`DEMO-CWE-787-INPUT-BOUND`
- 严重性：`error`
- 说明：Input variable `nums` controls a loop that indexes fixed array `sequence` with capacity 7.
- 证据：`for(j=0;j<nums;j++)`
- 建议：Validate `nums` before the loop, e.g. `if (nums < 1 || nums > 7) return;`.

## CWE-20/CWE-787 · testcase2/2.cpp:247

- 规则：`DEMO-CWE-787-INPUT-BOUND`
- 严重性：`error`
- 说明：Input variable `nums` controls a loop that indexes fixed array `stack` with capacity 7.
- 证据：`for(i=1;i<nums;i++)//前半部分，页面空置的情况`
- 建议：Validate `nums` before the loop, e.g. `if (nums < 1 || nums > 7) return;`.

## CWE-20/CWE-787 · testcase2/2.cpp:249

- 规则：`DEMO-CWE-787-INPUT-BOUND`
- 严重性：`error`
- 说明：Input variable `nums` controls a loop that indexes fixed array `numbers` with capacity 20.
- 证据：`for(j=0;j<nums;j++)`
- 建议：Validate `nums` before the loop, e.g. `if (nums < 1 || nums > 20) return;`.

## CWE-20/CWE-787 · testcase2/2.cpp:254

- 规则：`DEMO-CWE-787-INPUT-BOUND`
- 严重性：`error`
- 说明：Input variable `nums` controls a loop that indexes fixed array `numbers` with capacity 20.
- 证据：`for(j=0;j<nums;j++)  //判断要插入的是否在栈中已经存在`
- 建议：Validate `nums` before the loop, e.g. `if (nums < 1 || nums > 20) return;`.

## CWE-20/CWE-787 · testcase2/2.cpp:267

- 规则：`DEMO-CWE-787-INPUT-BOUND`
- 严重性：`error`
- 说明：Input variable `nums` controls a loop that indexes fixed array `numbers` with capacity 20.
- 证据：`for(j=0;j<nums;j++)`
- 建议：Validate `nums` before the loop, e.g. `if (nums < 1 || nums > 20) return;`.

## CWE-20/CWE-787 · testcase2/2.cpp:282

- 规则：`DEMO-CWE-787-INPUT-BOUND`
- 严重性：`error`
- 说明：Input variable `nums` controls a loop that indexes fixed array `seq` with capacity 7.
- 证据：`for(j=0;j<nums;j++)//将之前的优先级序列都减1`
- 建议：Validate `nums` before the loop, e.g. `if (nums < 1 || nums > 7) return;`.

## CWE-20/CWE-787 · testcase2/2.cpp:293

- 规则：`DEMO-CWE-787-INPUT-BOUND`
- 严重性：`error`
- 说明：Input variable `nums` controls a loop that indexes fixed array `numbers` with capacity 20.
- 证据：`for(j=0;j<nums;j++)//前面的页面中内容赋值到新的新的页面中`
- 建议：Validate `nums` before the loop, e.g. `if (nums < 1 || nums > 20) return;`.

## CWE-20/CWE-787 · testcase2/2.cpp:297

- 规则：`DEMO-CWE-787-INPUT-BOUND`
- 严重性：`error`
- 说明：Input variable `nums` controls a loop that indexes fixed array `numbers` with capacity 20.
- 证据：`for(j=0;j<nums;j++)`
- 建议：Validate `nums` before the loop, e.g. `if (nums < 1 || nums > 20) return;`.

## CWE-20/CWE-787 · testcase2/2.cpp:308

- 规则：`DEMO-CWE-787-INPUT-BOUND`
- 严重性：`error`
- 说明：Input variable `nums` controls a loop that indexes fixed array `numbers` with capacity 20.
- 证据：`for(q=0;q<nums;q++)//优先级序列中最大的就是最久不会用的，有可能出现后面没有在用过的情况`
- 建议：Validate `nums` before the loop, e.g. `if (nums < 1 || nums > 20) return;`.

## CWE-20/CWE-787 · testcase2/2.cpp:312

- 规则：`DEMO-CWE-787-INPUT-BOUND`
- 严重性：`error`
- 说明：Input variable `nums` controls a loop that indexes fixed array `numbers` with capacity 20.
- 证据：`for(j=0;j<nums;j++)//寻找新的优先级`
- 建议：Validate `nums` before the loop, e.g. `if (nums < 1 || nums > 20) return;`.

## CWE-20/CWE-787 · testcase2/2.cpp:325

- 规则：`DEMO-CWE-787-INPUT-BOUND`
- 严重性：`error`
- 说明：Input variable `nums` controls a loop that indexes fixed array `numbers` with capacity 20.
- 证据：`for(q=0;q<nums;q++)`
- 建议：Validate `nums` before the loop, e.g. `if (nums < 1 || nums > 20) return;`.
