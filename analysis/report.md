# CWE 静态分析报告

共发现 **61** 个告警。

## 汇总

### 按语言

- C/C++: 41
- Java: 9
- Python: 11

### 按 CWE

- CWE-120/CWE-787: 5
- CWE-20/CWE-252: 2
- CWE-20/CWE-787: 24
- CWE-22: 1
- CWE-295: 1
- CWE-327/CWE-328: 2
- CWE-330: 1
- CWE-338/CWE-330: 2
- CWE-362/CWE-667: 6
- CWE-398: 3
- CWE-489/CWE-215: 1
- CWE-502: 4
- CWE-78: 3
- CWE-798/CWE-259: 2
- CWE-89: 3
- CWE-94/CWE-95: 1

## CWE-398 · testcase1/003.main.cpp:1

- 语言：`C/C++`
- 规则：`DEMO-CWE-398-BUILD-BUG`
- 严重性：`warning`
- 说明：Linux/Arch is case-sensitive: source includes `schedule.h`, but sample file is `Schedule.h`.
- 证据：`#include "schedule.h"`
- 建议：Rename the include or the file so GitHub Actions/Linux can compile it.

## CWE-120/CWE-787 · testcase1/003.main.cpp:36

- 语言：`C/C++`
- 规则：`DEMO-CWE-120-CIN-CHAR-ARRAY`
- 严重性：`error`
- 说明：`cin >> command` writes into fixed char[30] without a width limit.
- 证据：`cin>>command;`
- 建议：Replace the buffer with std::string, or use std::setw(buffer_size) before extraction.

## CWE-120/CWE-787 · testcase1/003.main.cpp:43

- 语言：`C/C++`
- 规则：`DEMO-CWE-120-CIN-CHAR-ARRAY`
- 严重性：`error`
- 说明：`cin >> name` writes into fixed char[20] without a width limit.
- 证据：`cin>>name>>time;`
- 建议：Replace the buffer with std::string, or use std::setw(buffer_size) before extraction.

## CWE-120/CWE-787 · testcase1/003.main.cpp:48

- 语言：`C/C++`
- 规则：`DEMO-CWE-120-CIN-CHAR-ARRAY`
- 严重性：`error`
- 说明：`cin >> name` writes into fixed char[20] without a width limit.
- 证据：`cin>>name;`
- 建议：Replace the buffer with std::string, or use std::setw(buffer_size) before extraction.

## CWE-120/CWE-787 · testcase1/Schedule.cpp:20

- 语言：`C/C++`
- 规则：`DEMO-CWE-120-STRCPY`
- 严重性：`error`
- 说明：`strcpy` copies attacker/user-controlled strings without checking destination capacity.
- 证据：`strcpy(p->name,"NoName");//进程名字`
- 建议：Use std::string or a bounded copy routine and explicitly check destination size.

## CWE-120/CWE-787 · testcase1/Schedule.cpp:141

- 语言：`C/C++`
- 规则：`DEMO-CWE-120-STRCPY`
- 严重性：`error`
- 说明：`strcpy` copies attacker/user-controlled strings without checking destination capacity.
- 证据：`strcpy(newPcb->name,name); //填写新进程的名字`
- 建议：Use std::string or a bounded copy routine and explicitly check destination size.

## CWE-362/CWE-667 · testcase1/Schedule.cpp:207

- 语言：`C/C++`
- 规则：`DEMO-CWE-362-THREAD`
- 严重性：`warning`
- 说明：Use of `SuspendThread` can interrupt code while locks or shared state are inconsistent.
- 证据：`SuspendThread(runPCB->hThis);`
- 建议：Use cooperative cancellation and wait/join semantics instead of forced thread termination/suspension.

## CWE-362/CWE-667 · testcase1/Schedule.cpp:222

- 语言：`C/C++`
- 规则：`DEMO-CWE-362-THREAD`
- 严重性：`warning`
- 说明：Use of `TerminateThread` can interrupt code while locks or shared state are inconsistent.
- 证据：`if(!TerminateThread(runPCB->hThis,1))`
- 建议：Use cooperative cancellation and wait/join semantics instead of forced thread termination/suspension.

## CWE-362/CWE-667 · testcase1/Schedule.cpp:272

- 语言：`C/C++`
- 规则：`DEMO-CWE-362-THREAD`
- 严重性：`warning`
- 说明：Use of `TerminateThread` can interrupt code while locks or shared state are inconsistent.
- 证据：`if(!(TerminateThread(removeTarget->hThis,1)))`
- 建议：Use cooperative cancellation and wait/join semantics instead of forced thread termination/suspension.

## CWE-362/CWE-667 · testcase1/Schedule.cpp:321

- 语言：`C/C++`
- 规则：`DEMO-CWE-362-THREAD`
- 严重性：`warning`
- 说明：Use of `TerminateThread` can interrupt code while locks or shared state are inconsistent.
- 证据：`if(!TerminateThread(removeTarget->hThis,0))//执行撤销进程的操作`
- 建议：Use cooperative cancellation and wait/join semantics instead of forced thread termination/suspension.

## CWE-398 · testcase1/Schedule.cpp:367

- 语言：`C/C++`
- 规则：`DEMO-CWE-398-BUILD-BUG`
- 严重性：`warning`
- 说明：Suspicious `<` appears where stream insertion `<<` was probably intended.
- 证据：`log<<"--"<<tmp->id<<':'<<tmp->name<<"--";`
- 建议：Change `<` to `<<` and add a compilation job to CI.

## CWE-398 · testcase1/Schedule.cpp:382

- 语言：`C/C++`
- 规则：`DEMO-CWE-398-BUILD-BUG`
- 严重性：`warning`
- 说明：Suspicious `<` appears where stream insertion `<<` was probably intended.
- 证据：`cout<<"--"<<tmp->id<<':'<<tmp->name<"--";`
- 建议：Change `<` to `<<` and add a compilation job to CI.

## CWE-362/CWE-667 · testcase1/Schedule.cpp:406

- 语言：`C/C++`
- 规则：`DEMO-CWE-362-THREAD`
- 严重性：`warning`
- 说明：Use of `TerminateThread` can interrupt code while locks or shared state are inconsistent.
- 证据：`TerminateThread(runPCB->hThis,0);`
- 建议：Use cooperative cancellation and wait/join semantics instead of forced thread termination/suspension.

## CWE-362/CWE-667 · testcase1/Schedule.cpp:413

- 语言：`C/C++`
- 规则：`DEMO-CWE-362-THREAD`
- 严重性：`warning`
- 说明：Use of `TerminateThread` can interrupt code while locks or shared state are inconsistent.
- 证据：`if(!TerminateThread(p->hThis,0))`
- 建议：Use cooperative cancellation and wait/join semantics instead of forced thread termination/suspension.

## CWE-20/CWE-252 · testcase2/2.cpp:31

- 语言：`C/C++`
- 规则：`DEMO-CWE-20-SCANF-RETURN`
- 严重性：`warning`
- 说明：Return value of `scanf` is ignored when reading `nums`.
- 证据：`scanf("%d",&nums);`
- 建议：Require `scanf(...) == 1`; reject non-numeric input and initialize variables safely.

## CWE-20/CWE-252 · testcase2/2.cpp:35

- 语言：`C/C++`
- 规则：`DEMO-CWE-20-SCANF-RETURN`
- 严重性：`warning`
- 说明：Return value of `scanf` is ignored when reading `j`.
- 证据：`scanf("%d",&j);`
- 建议：Require `scanf(...) == 1`; reject non-numeric input and initialize variables safely.

## CWE-330 · testcase2/2.cpp:63

- 语言：`C/C++`
- 规则：`DEMO-CWE-330-RAND`
- 严重性：`note`
- 说明：`rand()` is predictable; do not use it for security-sensitive randomness.
- 证据：`numbers[i] = rand() % 10;//生成区间0`9的随机页面引用串`
- 建议：For simulation this is acceptable if documented; otherwise use a CSPRNG.

## CWE-20/CWE-787 · testcase2/2.cpp:70

- 语言：`C/C++`
- 规则：`DEMO-CWE-787-INPUT-BOUND`
- 严重性：`error`
- 说明：Input variable `nums` controls a loop that indexes fixed array `stack` with capacity 7.
- 证据：`for(j=0;j<nums;j++)`
- 建议：Validate `nums` before the loop, e.g. `if (nums < 1 || nums > 7) return;`.

## CWE-20/CWE-787 · testcase2/2.cpp:77

- 语言：`C/C++`
- 规则：`DEMO-CWE-787-INPUT-BOUND`
- 严重性：`error`
- 说明：Input variable `nums` controls a loop that indexes fixed array `stack` with capacity 7.
- 证据：`for(i=0;i<nums;i++)`
- 建议：Validate `nums` before the loop, e.g. `if (nums < 1 || nums > 7) return;`.

## CWE-20/CWE-787 · testcase2/2.cpp:100

- 语言：`C/C++`
- 规则：`DEMO-CWE-787-INPUT-BOUND`
- 严重性：`error`
- 说明：Input variable `nums` controls a loop that indexes fixed array `numbers` with capacity 20.
- 证据：`for(m=0;m<nums;m++)`
- 建议：Validate `nums` before the loop, e.g. `if (nums < 1 || nums > 20) return;`.

## CWE-20/CWE-787 · testcase2/2.cpp:104

- 语言：`C/C++`
- 规则：`DEMO-CWE-787-INPUT-BOUND`
- 严重性：`error`
- 说明：Input variable `nums` controls a loop that indexes fixed array `numbers` with capacity 20.
- 证据：`for(k=0;k<nums;k++)`
- 建议：Validate `nums` before the loop, e.g. `if (nums < 1 || nums > 20) return;`.

## CWE-20/CWE-787 · testcase2/2.cpp:134

- 语言：`C/C++`
- 规则：`DEMO-CWE-787-INPUT-BOUND`
- 严重性：`error`
- 说明：Input variable `nums` controls a loop that indexes fixed array `stack` with capacity 7.
- 证据：`for(i=1;i<nums;i++)//前半部分，页面空置的情况`
- 建议：Validate `nums` before the loop, e.g. `if (nums < 1 || nums > 7) return;`.

## CWE-20/CWE-787 · testcase2/2.cpp:136

- 语言：`C/C++`
- 规则：`DEMO-CWE-787-INPUT-BOUND`
- 严重性：`error`
- 说明：Input variable `nums` controls a loop that indexes fixed array `numbers` with capacity 20.
- 证据：`for(j=0;j<nums;j++)`
- 建议：Validate `nums` before the loop, e.g. `if (nums < 1 || nums > 20) return;`.

## CWE-20/CWE-787 · testcase2/2.cpp:141

- 语言：`C/C++`
- 规则：`DEMO-CWE-787-INPUT-BOUND`
- 严重性：`error`
- 说明：Input variable `nums` controls a loop that indexes fixed array `numbers` with capacity 20.
- 证据：`for(j=0;j<nums;j++)  //判断要插入的是否在栈中已经存在`
- 建议：Validate `nums` before the loop, e.g. `if (nums < 1 || nums > 20) return;`.

## CWE-20/CWE-787 · testcase2/2.cpp:153

- 语言：`C/C++`
- 规则：`DEMO-CWE-787-INPUT-BOUND`
- 严重性：`error`
- 说明：Input variable `nums` controls a loop that indexes fixed array `numbers` with capacity 20.
- 证据：`for(j=0;j<nums;j++)`
- 建议：Validate `nums` before the loop, e.g. `if (nums < 1 || nums > 20) return;`.

## CWE-20/CWE-787 · testcase2/2.cpp:175

- 语言：`C/C++`
- 规则：`DEMO-CWE-787-INPUT-BOUND`
- 严重性：`error`
- 说明：Input variable `nums` controls a loop that indexes fixed array `numbers` with capacity 20.
- 证据：`for(j=0;j<nums;j++)`
- 建议：Validate `nums` before the loop, e.g. `if (nums < 1 || nums > 20) return;`.

## CWE-20/CWE-787 · testcase2/2.cpp:179

- 语言：`C/C++`
- 规则：`DEMO-CWE-787-INPUT-BOUND`
- 严重性：`error`
- 说明：Input variable `nums` controls a loop that indexes fixed array `numbers` with capacity 20.
- 证据：`for(j=0;j<nums;j++)//判断输入串中的数字，是否已经在栈中`
- 建议：Validate `nums` before the loop, e.g. `if (nums < 1 || nums > 20) return;`.

## CWE-20/CWE-787 · testcase2/2.cpp:190

- 语言：`C/C++`
- 规则：`DEMO-CWE-787-INPUT-BOUND`
- 严重性：`error`
- 说明：Input variable `nums` controls a loop that indexes fixed array `sequence` with capacity 7.
- 证据：`for(j=0;j<nums;j++)//找优先序列中为0的`
- 建议：Validate `nums` before the loop, e.g. `if (nums < 1 || nums > 7) return;`.

## CWE-20/CWE-787 · testcase2/2.cpp:198

- 语言：`C/C++`
- 规则：`DEMO-CWE-787-INPUT-BOUND`
- 严重性：`error`
- 说明：Input variable `nums` controls a loop that indexes fixed array `numbers` with capacity 20.
- 证据：`for(j=0;j<nums;j++)`
- 建议：Validate `nums` before the loop, e.g. `if (nums < 1 || nums > 20) return;`.

## CWE-20/CWE-787 · testcase2/2.cpp:210

- 语言：`C/C++`
- 规则：`DEMO-CWE-787-INPUT-BOUND`
- 严重性：`error`
- 说明：Input variable `nums` controls a loop that indexes fixed array `sequence` with capacity 7.
- 证据：`for(j=0;j<nums;j++)`
- 建议：Validate `nums` before the loop, e.g. `if (nums < 1 || nums > 7) return;`.

## CWE-20/CWE-787 · testcase2/2.cpp:222

- 语言：`C/C++`
- 规则：`DEMO-CWE-787-INPUT-BOUND`
- 严重性：`error`
- 说明：Input variable `nums` controls a loop that indexes fixed array `sequence` with capacity 7.
- 证据：`for(j=0;j<nums;j++)`
- 建议：Validate `nums` before the loop, e.g. `if (nums < 1 || nums > 7) return;`.

## CWE-20/CWE-787 · testcase2/2.cpp:247

- 语言：`C/C++`
- 规则：`DEMO-CWE-787-INPUT-BOUND`
- 严重性：`error`
- 说明：Input variable `nums` controls a loop that indexes fixed array `stack` with capacity 7.
- 证据：`for(i=1;i<nums;i++)//前半部分，页面空置的情况`
- 建议：Validate `nums` before the loop, e.g. `if (nums < 1 || nums > 7) return;`.

## CWE-20/CWE-787 · testcase2/2.cpp:249

- 语言：`C/C++`
- 规则：`DEMO-CWE-787-INPUT-BOUND`
- 严重性：`error`
- 说明：Input variable `nums` controls a loop that indexes fixed array `numbers` with capacity 20.
- 证据：`for(j=0;j<nums;j++)`
- 建议：Validate `nums` before the loop, e.g. `if (nums < 1 || nums > 20) return;`.

## CWE-20/CWE-787 · testcase2/2.cpp:254

- 语言：`C/C++`
- 规则：`DEMO-CWE-787-INPUT-BOUND`
- 严重性：`error`
- 说明：Input variable `nums` controls a loop that indexes fixed array `numbers` with capacity 20.
- 证据：`for(j=0;j<nums;j++)  //判断要插入的是否在栈中已经存在`
- 建议：Validate `nums` before the loop, e.g. `if (nums < 1 || nums > 20) return;`.

## CWE-20/CWE-787 · testcase2/2.cpp:267

- 语言：`C/C++`
- 规则：`DEMO-CWE-787-INPUT-BOUND`
- 严重性：`error`
- 说明：Input variable `nums` controls a loop that indexes fixed array `numbers` with capacity 20.
- 证据：`for(j=0;j<nums;j++)`
- 建议：Validate `nums` before the loop, e.g. `if (nums < 1 || nums > 20) return;`.

## CWE-20/CWE-787 · testcase2/2.cpp:282

- 语言：`C/C++`
- 规则：`DEMO-CWE-787-INPUT-BOUND`
- 严重性：`error`
- 说明：Input variable `nums` controls a loop that indexes fixed array `seq` with capacity 7.
- 证据：`for(j=0;j<nums;j++)//将之前的优先级序列都减1`
- 建议：Validate `nums` before the loop, e.g. `if (nums < 1 || nums > 7) return;`.

## CWE-20/CWE-787 · testcase2/2.cpp:293

- 语言：`C/C++`
- 规则：`DEMO-CWE-787-INPUT-BOUND`
- 严重性：`error`
- 说明：Input variable `nums` controls a loop that indexes fixed array `numbers` with capacity 20.
- 证据：`for(j=0;j<nums;j++)//前面的页面中内容赋值到新的新的页面中`
- 建议：Validate `nums` before the loop, e.g. `if (nums < 1 || nums > 20) return;`.

## CWE-20/CWE-787 · testcase2/2.cpp:297

- 语言：`C/C++`
- 规则：`DEMO-CWE-787-INPUT-BOUND`
- 严重性：`error`
- 说明：Input variable `nums` controls a loop that indexes fixed array `numbers` with capacity 20.
- 证据：`for(j=0;j<nums;j++)`
- 建议：Validate `nums` before the loop, e.g. `if (nums < 1 || nums > 20) return;`.

## CWE-20/CWE-787 · testcase2/2.cpp:308

- 语言：`C/C++`
- 规则：`DEMO-CWE-787-INPUT-BOUND`
- 严重性：`error`
- 说明：Input variable `nums` controls a loop that indexes fixed array `numbers` with capacity 20.
- 证据：`for(q=0;q<nums;q++)//优先级序列中最大的就是最久不会用的，有可能出现后面没有在用过的情况`
- 建议：Validate `nums` before the loop, e.g. `if (nums < 1 || nums > 20) return;`.

## CWE-20/CWE-787 · testcase2/2.cpp:312

- 语言：`C/C++`
- 规则：`DEMO-CWE-787-INPUT-BOUND`
- 严重性：`error`
- 说明：Input variable `nums` controls a loop that indexes fixed array `numbers` with capacity 20.
- 证据：`for(j=0;j<nums;j++)//寻找新的优先级`
- 建议：Validate `nums` before the loop, e.g. `if (nums < 1 || nums > 20) return;`.

## CWE-20/CWE-787 · testcase2/2.cpp:325

- 语言：`C/C++`
- 规则：`DEMO-CWE-787-INPUT-BOUND`
- 严重性：`error`
- 说明：Input variable `nums` controls a loop that indexes fixed array `numbers` with capacity 20.
- 证据：`for(q=0;q<nums;q++)`
- 建议：Validate `nums` before the loop, e.g. `if (nums < 1 || nums > 20) return;`.

## CWE-798/CWE-259 · testcase_java/InsecureDemo.java:9

- 语言：`Java`
- 规则：`DEMO-CWE-798-HARDCODED-SECRET`
- 严重性：`warning`
- 说明：Secret-like Java variable `API_TOKEN` is assigned a string literal.
- 证据：`private static final String API_TOKEN = "demo-token-123456";`
- 建议：Move secrets to a secret manager or CI secret, and rotate exposed credentials.

## CWE-78 · testcase_java/InsecureDemo.java:14

- 语言：`Java`
- 规则：`DEMO-CWE-78-JAVA-EXEC`
- 严重性：`error`
- 说明：`Runtime.exec` executes an OS command; dynamic arguments may become command injection.
- 证据：`Runtime.getRuntime().exec("sh -c " + cmd);`
- 建议：Avoid shell command construction; use allow-lists and pass fixed argv arrays.

## CWE-89 · testcase_java/InsecureDemo.java:16

- 语言：`Java`
- 规则：`DEMO-CWE-89-JAVA-SQL-CONCAT`
- 严重性：`error`
- 说明：SQL string `sql` is built dynamically and may include untrusted input.
- 证据：`String sql = "SELECT * FROM users WHERE name = '" + user + "'";`
- 建议：Use PreparedStatement with bind parameters instead of string concatenation.

## CWE-89 · testcase_java/InsecureDemo.java:17

- 语言：`Java`
- 规则：`DEMO-CWE-89-JAVA-SQL-CONCAT`
- 严重性：`error`
- 说明：Dynamic SQL is passed to a JDBC execute method.
- 证据：`stmt.executeQuery(sql);`
- 建议：Use PreparedStatement with bind parameters instead of string concatenation.

## CWE-22 · testcase_java/InsecureDemo.java:20

- 语言：`Java`
- 规则：`DEMO-CWE-22-JAVA-PATH`
- 严重性：`warning`
- 说明：User-controlled input appears to influence a file path.
- 证据：`new FileInputStream(file);`
- 建议：Canonicalize paths, enforce a safe base directory, and reject traversal sequences.

## CWE-502 · testcase_java/InsecureDemo.java:22

- 语言：`Java`
- 规则：`DEMO-CWE-502-JAVA-DESERIALIZATION`
- 严重性：`warning`
- 说明：Native Java deserialization appears in the code.
- 证据：`ObjectInputStream ois = new ObjectInputStream(request.getInputStream());`
- 建议：Avoid native Java deserialization for untrusted data; use safe formats and object filters.

## CWE-502 · testcase_java/InsecureDemo.java:23

- 语言：`Java`
- 规则：`DEMO-CWE-502-JAVA-DESERIALIZATION`
- 严重性：`warning`
- 说明：Native Java deserialization appears in the code.
- 证据：`Object obj = ois.readObject();`
- 建议：Avoid native Java deserialization for untrusted data; use safe formats and object filters.

## CWE-327/CWE-328 · testcase_java/InsecureDemo.java:25

- 语言：`Java`
- 规则：`DEMO-CWE-327-JAVA-WEAK-CRYPTO`
- 严重性：`warning`
- 说明：Weak digest algorithm `MD5` is requested.
- 证据：`MessageDigest md = MessageDigest.getInstance("MD5");`
- 建议：Use modern algorithms such as SHA-256/HMAC-SHA-256, bcrypt, scrypt, or Argon2 as appropriate.

## CWE-338/CWE-330 · testcase_java/InsecureDemo.java:26

- 语言：`Java`
- 规则：`DEMO-CWE-330-JAVA-RANDOM`
- 严重性：`note`
- 说明：Predictable Java random generator is used.
- 证据：`int resetCode = new Random().nextInt();`
- 建议：Use java.security.SecureRandom for secrets, session IDs, reset tokens, and nonces.

## CWE-798/CWE-259 · testcase_python/insecure_demo.py:10

- 语言：`Python`
- 规则：`DEMO-CWE-798-HARDCODED-SECRET`
- 严重性：`warning`
- 说明：Secret-like Python variable `API_KEY` is assigned a string literal.
- 证据：`API_KEY = "demo-api-key-123456"`
- 建议：Move secrets to a secret manager or CI secret, and rotate exposed credentials.

## CWE-78 · testcase_python/insecure_demo.py:14

- 语言：`Python`
- 规则：`DEMO-CWE-78-PY-SHELL`
- 严重性：`error`
- 说明：Command execution sink `os.system` is used.
- 证据：`os.system("ping " + user_input)`
- 建议：Avoid shell=True; pass fixed argument lists and validate user-controlled values.

## CWE-78 · testcase_python/insecure_demo.py:15

- 语言：`Python`
- 规则：`DEMO-CWE-78-PY-SHELL`
- 严重性：`error`
- 说明：Command execution sink `subprocess.run` is used with `shell=True`.
- 证据：`subprocess.run("cat " + user_input, shell=True)`
- 建议：Avoid shell=True; pass fixed argument lists and validate user-controlled values.

## CWE-94/CWE-95 · testcase_python/insecure_demo.py:16

- 语言：`Python`
- 规则：`DEMO-CWE-94-PY-EVAL`
- 严重性：`error`
- 说明：Dynamic code execution `eval` appears in the code.
- 证据：`eval(user_input)`
- 建议：Use safe parsers such as json.loads or ast.literal_eval, and never evaluate untrusted input.

## CWE-502 · testcase_python/insecure_demo.py:17

- 语言：`Python`
- 规则：`DEMO-CWE-502-PY-DESERIALIZATION`
- 严重性：`warning`
- 说明：Unsafe Python deserialization sink `pickle.loads` appears in the code.
- 证据：`pickle.loads(blob)`
- 建议：Avoid pickle/marshal for untrusted data; use yaml.safe_load or a strict JSON schema.

## CWE-502 · testcase_python/insecure_demo.py:18

- 语言：`Python`
- 规则：`DEMO-CWE-502-PY-DESERIALIZATION`
- 严重性：`warning`
- 说明：`yaml.load` is used without an explicit SafeLoader.
- 证据：`yaml.load(blob)`
- 建议：Use yaml.safe_load or Loader=yaml.SafeLoader.

## CWE-327/CWE-328 · testcase_python/insecure_demo.py:19

- 语言：`Python`
- 规则：`DEMO-CWE-327-PY-WEAK-HASH`
- 严重性：`warning`
- 说明：Weak hash `MD5` is used.
- 证据：`hashlib.md5(user_input.encode()).hexdigest()`
- 建议：Use SHA-256/HMAC or a password hashing scheme such as bcrypt/scrypt/Argon2 as appropriate.

## CWE-338/CWE-330 · testcase_python/insecure_demo.py:20

- 语言：`Python`
- 规则：`DEMO-CWE-338-PY-RANDOM`
- 严重性：`note`
- 说明：Python `random` module is predictable if used for security tokens.
- 证据：`token = random.randint(100000, 999999)`
- 建议：Use secrets.token_urlsafe/token_bytes or os.urandom for security-sensitive randomness.

## CWE-295 · testcase_python/insecure_demo.py:21

- 语言：`Python`
- 规则：`DEMO-CWE-295-PY-VERIFY-FALSE`
- 严重性：`error`
- 说明：TLS certificate verification is disabled with `verify=False`.
- 证据：`requests.get(url, verify=False)`
- 建议：Remove verify=False and install/trust the proper CA certificate instead.

## CWE-89 · testcase_python/insecure_demo.py:26

- 语言：`Python`
- 规则：`DEMO-CWE-89-PY-SQL-DYNAMIC`
- 严重性：`error`
- 说明：Potentially dynamic SQL is passed to execute().
- 证据：`cur.execute(query)`
- 建议：Use parameterized queries instead of f-strings, %, format(), or string concatenation.

## CWE-489/CWE-215 · testcase_python/insecure_demo.py:31

- 语言：`Python`
- 规则：`DEMO-CWE-489-PY-DEBUG`
- 严重性：`warning`
- 说明：Application run method enables debug mode.
- 证据：`app.run(debug=True)`
- 建议：Disable debug mode outside local development.
