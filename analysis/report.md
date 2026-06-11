# CWE 静态分析报告

共发现 **40** 个告警。

推理后端：`souffle`

## 汇总

### 按语言

- C/C++: 21
- Java: 9
- Python: 10

### 按 CWE

- CWE-120/CWE-787: 5
- CWE-20/CWE-252: 2
- CWE-20/CWE-787: 4
- CWE-22: 1
- CWE-295: 1
- CWE-327/CWE-328: 2
- CWE-330: 1
- CWE-338/CWE-330: 2
- CWE-362/CWE-667: 6
- CWE-398: 3
- CWE-489/CWE-215: 1
- CWE-502: 5
- CWE-78: 3
- CWE-798/CWE-259: 2
- CWE-89: 1
- CWE-94/CWE-95: 1

## 分析架构

本报告由 `extract_facts.py` 先从 C/C++、Java、Python 源码抽取 facts，再由 `rules/cwe_rules.dl` 的 Datalog 规则推导 CWE findings；若本机未安装 Soufflé，则使用与 Datalog 规则等价的 Python fallback 生成同形 `finding.csv`，保证课堂演示稳定。

## CWE-398 · testcase1/003.main.cpp:1

- 语言：`C/C++`
- 规则：`DEMO-CWE-398-BUILD-BUG`
- 严重性：`note`
- 说明：case-sensitive include may fail on Linux
- 证据：`#include "schedule.h"`
- 建议：Fix the typo and add CI compilation checks.

## CWE-120/CWE-787 · testcase1/003.main.cpp:36

- 语言：`C/C++`
- 规则：`DEMO-CWE-120-CIN-CHAR-ARRAY`
- 严重性：`error`
- 说明：Unbounded cin>> read into fixed char buffer: command
- 证据：`cin>>command;`
- 建议：Use std::string, std::setw(sizeof(buf)), or bounded parsing.

## CWE-120/CWE-787 · testcase1/003.main.cpp:43

- 语言：`C/C++`
- 规则：`DEMO-CWE-120-CIN-CHAR-ARRAY`
- 严重性：`error`
- 说明：Unbounded cin>> read into fixed char buffer: name
- 证据：`cin>>name>>time;`
- 建议：Use std::string, std::setw(sizeof(buf)), or bounded parsing.

## CWE-120/CWE-787 · testcase1/003.main.cpp:48

- 语言：`C/C++`
- 规则：`DEMO-CWE-120-CIN-CHAR-ARRAY`
- 严重性：`error`
- 说明：Unbounded cin>> read into fixed char buffer: name
- 证据：`cin>>name;`
- 建议：Use std::string, std::setw(sizeof(buf)), or bounded parsing.

## CWE-120/CWE-787 · testcase1/Schedule.cpp:20

- 语言：`C/C++`
- 规则：`DEMO-CWE-120-STRCPY`
- 严重性：`error`
- 说明：strcpy can overflow a destination buffer because it does not know the destination capacity.
- 证据：`strcpy(p->name,"NoName");//进程名字`
- 建议：Use std::string, strncpy_s on Windows, or copy with explicit bounds and NUL termination.

## CWE-120/CWE-787 · testcase1/Schedule.cpp:141

- 语言：`C/C++`
- 规则：`DEMO-CWE-120-STRCPY`
- 严重性：`error`
- 说明：strcpy can overflow a destination buffer because it does not know the destination capacity.
- 证据：`strcpy(newPcb->name,name); //填写新进程的名字`
- 建议：Use std::string, strncpy_s on Windows, or copy with explicit bounds and NUL termination.

## CWE-362/CWE-667 · testcase1/Schedule.cpp:207

- 语言：`C/C++`
- 规则：`DEMO-CWE-362-THREAD`
- 严重性：`warning`
- 说明：SuspendThread can leave shared state inconsistent and is race-prone.
- 证据：`SuspendThread(runPCB->hThis);`
- 建议：Prefer cooperative cancellation, joins, condition variables, and scoped locks.

## CWE-362/CWE-667 · testcase1/Schedule.cpp:222

- 语言：`C/C++`
- 规则：`DEMO-CWE-362-THREAD`
- 严重性：`warning`
- 说明：TerminateThread can leave shared state inconsistent and is race-prone.
- 证据：`if(!TerminateThread(runPCB->hThis,1))`
- 建议：Prefer cooperative cancellation, joins, condition variables, and scoped locks.

## CWE-362/CWE-667 · testcase1/Schedule.cpp:272

- 语言：`C/C++`
- 规则：`DEMO-CWE-362-THREAD`
- 严重性：`warning`
- 说明：TerminateThread can leave shared state inconsistent and is race-prone.
- 证据：`if(!(TerminateThread(removeTarget->hThis,1)))`
- 建议：Prefer cooperative cancellation, joins, condition variables, and scoped locks.

## CWE-362/CWE-667 · testcase1/Schedule.cpp:321

- 语言：`C/C++`
- 规则：`DEMO-CWE-362-THREAD`
- 严重性：`warning`
- 说明：TerminateThread can leave shared state inconsistent and is race-prone.
- 证据：`if(!TerminateThread(removeTarget->hThis,0))//执行撤销进程的操作`
- 建议：Prefer cooperative cancellation, joins, condition variables, and scoped locks.

## CWE-398 · testcase1/Schedule.cpp:367

- 语言：`C/C++`
- 规则：`DEMO-CWE-398-BUILD-BUG`
- 严重性：`note`
- 说明：suspicious stream insertion typo
- 证据：`log<<"--"<<tmp->id<<':'<<tmp->name<<"--";`
- 建议：Fix the typo and add CI compilation checks.

## CWE-398 · testcase1/Schedule.cpp:382

- 语言：`C/C++`
- 规则：`DEMO-CWE-398-BUILD-BUG`
- 严重性：`note`
- 说明：suspicious stream insertion typo
- 证据：`cout<<"--"<<tmp->id<<':'<<tmp->name<"--";`
- 建议：Fix the typo and add CI compilation checks.

## CWE-362/CWE-667 · testcase1/Schedule.cpp:406

- 语言：`C/C++`
- 规则：`DEMO-CWE-362-THREAD`
- 严重性：`warning`
- 说明：TerminateThread can leave shared state inconsistent and is race-prone.
- 证据：`TerminateThread(runPCB->hThis,0);`
- 建议：Prefer cooperative cancellation, joins, condition variables, and scoped locks.

## CWE-362/CWE-667 · testcase1/Schedule.cpp:413

- 语言：`C/C++`
- 规则：`DEMO-CWE-362-THREAD`
- 严重性：`warning`
- 说明：TerminateThread can leave shared state inconsistent and is race-prone.
- 证据：`if(!TerminateThread(p->hThis,0))`
- 建议：Prefer cooperative cancellation, joins, condition variables, and scoped locks.

## CWE-20/CWE-252 · testcase2/2.cpp:31

- 语言：`C/C++`
- 规则：`DEMO-CWE-20-SCANF-RETURN`
- 严重性：`warning`
- 说明：scanf return value is ignored, so invalid input may leave the destination variable unchanged.
- 证据：`scanf("%d",&nums);`
- 建议：Check scanf's return value and reject invalid input.

## CWE-20/CWE-252 · testcase2/2.cpp:35

- 语言：`C/C++`
- 规则：`DEMO-CWE-20-SCANF-RETURN`
- 严重性：`warning`
- 说明：scanf return value is ignored, so invalid input may leave the destination variable unchanged.
- 证据：`scanf("%d",&j);`
- 建议：Check scanf's return value and reject invalid input.

## CWE-330 · testcase2/2.cpp:63

- 语言：`C/C++`
- 规则：`DEMO-CWE-330-RAND`
- 严重性：`note`
- 说明：rand() is predictable and is not suitable for security-sensitive randomness.
- 证据：`numbers[i] = rand() % 10;//生成区间0`9的随机页面引用串`
- 建议：Use a CSPRNG for security; if this is only simulation data, document that it is non-security randomness.

## CWE-20/CWE-787 · testcase2/2.cpp:70

- 语言：`C/C++`
- 规则：`DEMO-CWE-787-INPUT-BOUND`
- 严重性：`error`
- 说明：User-controlled value nums controls access to fixed array stack with capacity 7
- 证据：`for(j=0;j<nums;j++)`
- 建议：Validate the input range before it controls array access.

## CWE-20/CWE-787 · testcase2/2.cpp:100

- 语言：`C/C++`
- 规则：`DEMO-CWE-787-INPUT-BOUND`
- 严重性：`error`
- 说明：User-controlled value nums controls access to fixed array numbers with capacity 20
- 证据：`for(m=0;m<nums;m++)`
- 建议：Validate the input range before it controls array access.

## CWE-20/CWE-787 · testcase2/2.cpp:153

- 语言：`C/C++`
- 规则：`DEMO-CWE-787-INPUT-BOUND`
- 严重性：`error`
- 说明：User-controlled value nums controls access to fixed array sequence with capacity 7
- 证据：`for(j=0;j<nums;j++)`
- 建议：Validate the input range before it controls array access.

## CWE-20/CWE-787 · testcase2/2.cpp:267

- 语言：`C/C++`
- 规则：`DEMO-CWE-787-INPUT-BOUND`
- 严重性：`error`
- 说明：User-controlled value nums controls access to fixed array seq with capacity 7
- 证据：`for(j=0;j<nums;j++)`
- 建议：Validate the input range before it controls array access.

## CWE-502 · testcase_java/InsecureDemo.java:2

- 语言：`Java`
- 规则：`DEMO-CWE-502-JAVA-DESERIALIZATION`
- 严重性：`warning`
- 说明：ObjectInputStream/readObject may deserialize attacker-controlled objects.
- 证据：`import java.io.ObjectInputStream;`
- 建议：Avoid native Java deserialization for untrusted data; use safe formats and object filters.

## CWE-798/CWE-259 · testcase_java/InsecureDemo.java:9

- 语言：`Java`
- 规则：`DEMO-CWE-798-HARDCODED-SECRET`
- 严重性：`warning`
- 说明：Java hard-coded secret-like variable: API_TOKEN
- 证据：`private static final String API_TOKEN = "demo-token-123456";`
- 建议：Move secrets to a secret manager or CI secret, and rotate exposed credentials.

## CWE-78 · testcase_java/InsecureDemo.java:14

- 语言：`Java`
- 规则：`DEMO-CWE-78-JAVA-EXEC`
- 严重性：`error`
- 说明：Java command execution sink may execute user-controlled commands.
- 证据：`Runtime.getRuntime().exec("sh -c " + cmd);`
- 建议：Avoid shell command construction; use allow-lists and pass fixed argv arrays.

## CWE-89 · testcase_java/InsecureDemo.java:16

- 语言：`Java`
- 规则：`DEMO-CWE-89-JAVA-SQL-CONCAT`
- 严重性：`error`
- 说明：Java SQL string is dynamically constructed and may allow SQL injection.
- 证据：`String sql = "SELECT * FROM users WHERE name = '" + user + "'";`
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
- 说明：ObjectInputStream/readObject may deserialize attacker-controlled objects.
- 证据：`ObjectInputStream ois = new ObjectInputStream(request.getInputStream());`
- 建议：Avoid native Java deserialization for untrusted data; use safe formats and object filters.

## CWE-502 · testcase_java/InsecureDemo.java:23

- 语言：`Java`
- 规则：`DEMO-CWE-502-JAVA-DESERIALIZATION`
- 严重性：`warning`
- 说明：ObjectInputStream/readObject may deserialize attacker-controlled objects.
- 证据：`Object obj = ois.readObject();`
- 建议：Avoid native Java deserialization for untrusted data; use safe formats and object filters.

## CWE-327/CWE-328 · testcase_java/InsecureDemo.java:25

- 语言：`Java`
- 规则：`DEMO-CWE-327-JAVA-WEAK-CRYPTO`
- 严重性：`warning`
- 说明：Java weak cryptographic algorithm: MD5
- 证据：`MessageDigest md = MessageDigest.getInstance("MD5");`
- 建议：Use modern algorithms such as SHA-256/HMAC-SHA-256, bcrypt, scrypt, or Argon2 as appropriate.

## CWE-338/CWE-330 · testcase_java/InsecureDemo.java:26

- 语言：`Java`
- 规则：`DEMO-CWE-330-JAVA-RANDOM`
- 严重性：`warning`
- 说明：java.util.Random/Math.random are predictable for security-sensitive tokens.
- 证据：`int resetCode = new Random().nextInt();`
- 建议：Use java.security.SecureRandom for secrets, session IDs, reset tokens, and nonces.

## CWE-798/CWE-259 · testcase_python/insecure_demo.py:10

- 语言：`Python`
- 规则：`DEMO-CWE-798-HARDCODED-SECRET`
- 严重性：`warning`
- 说明：Python hard-coded secret-like variable: API_KEY
- 证据：`API_KEY = "demo-api-key-123456"`
- 建议：Move secrets to a secret manager or CI secret, and rotate exposed credentials.

## CWE-78 · testcase_python/insecure_demo.py:14

- 语言：`Python`
- 规则：`DEMO-CWE-78-PY-SHELL`
- 严重性：`error`
- 说明：Python command execution sink can execute user-controlled commands.
- 证据：`os.system("ping " + user_input)`
- 建议：Avoid shell=True; pass fixed argument lists and validate user-controlled values.

## CWE-78 · testcase_python/insecure_demo.py:15

- 语言：`Python`
- 规则：`DEMO-CWE-78-PY-SHELL`
- 严重性：`error`
- 说明：Python command execution sink can execute user-controlled commands.
- 证据：`subprocess.run("cat " + user_input, shell=True)`
- 建议：Avoid shell=True; pass fixed argument lists and validate user-controlled values.

## CWE-94/CWE-95 · testcase_python/insecure_demo.py:16

- 语言：`Python`
- 规则：`DEMO-CWE-94-PY-EVAL`
- 严重性：`error`
- 说明：eval/exec/compile executes code represented as data.
- 证据：`eval(user_input)`
- 建议：Use safe parsers such as json.loads or ast.literal_eval, and never evaluate untrusted input.

## CWE-502 · testcase_python/insecure_demo.py:17

- 语言：`Python`
- 规则：`DEMO-CWE-502-PY-DESERIALIZATION`
- 严重性：`warning`
- 说明：pickle/marshal/yaml.load can deserialize or construct unsafe objects.
- 证据：`pickle.loads(blob)`
- 建议：Avoid pickle/marshal for untrusted data; use yaml.safe_load or a strict JSON schema.

## CWE-502 · testcase_python/insecure_demo.py:18

- 语言：`Python`
- 规则：`DEMO-CWE-502-PY-DESERIALIZATION`
- 严重性：`warning`
- 说明：pickle/marshal/yaml.load can deserialize or construct unsafe objects.
- 证据：`yaml.load(blob)`
- 建议：Avoid pickle/marshal for untrusted data; use yaml.safe_load or a strict JSON schema.

## CWE-327/CWE-328 · testcase_python/insecure_demo.py:19

- 语言：`Python`
- 规则：`DEMO-CWE-327-PY-WEAK-HASH`
- 严重性：`warning`
- 说明：Python weak cryptographic algorithm: MD5
- 证据：`hashlib.md5(user_input.encode()).hexdigest()`
- 建议：Use SHA-256/HMAC or a password hashing scheme such as bcrypt/scrypt/Argon2 as appropriate.

## CWE-338/CWE-330 · testcase_python/insecure_demo.py:20

- 语言：`Python`
- 规则：`DEMO-CWE-338-PY-RANDOM`
- 严重性：`warning`
- 说明：Python random module output is predictable for security-sensitive secrets.
- 证据：`token = random.randint(100000, 999999)`
- 建议：Use secrets.token_urlsafe/token_bytes or os.urandom for security-sensitive randomness.

## CWE-295 · testcase_python/insecure_demo.py:21

- 语言：`Python`
- 规则：`DEMO-CWE-295-PY-VERIFY-FALSE`
- 严重性：`warning`
- 说明：verify=False disables TLS certificate validation.
- 证据：`requests.get(url, verify=False)`
- 建议：Remove verify=False and install/trust the proper CA certificate instead.

## CWE-489/CWE-215 · testcase_python/insecure_demo.py:31

- 语言：`Python`
- 规则：`DEMO-CWE-489-PY-DEBUG`
- 严重性：`warning`
- 说明：Debug mode can leak sensitive internals in production.
- 证据：`app.run(debug=True)`
- 建议：Disable debug mode outside local development.
