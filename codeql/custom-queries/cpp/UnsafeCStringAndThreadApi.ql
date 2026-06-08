/**
 * @name Unsafe C string and thread API demo query
 * @description Demo query for coursework: flags strcpy and forced Windows thread APIs.
 * @kind problem
 * @problem.severity warning
 * @security-severity 7.0
 * @precision medium
 * @id cpp/coursework/unsafe-cstring-thread-api
 * @tags security
 *       external/cwe/cwe-120
 *       external/cwe/cwe-362
 *       external/cwe/cwe-667
 */

import cpp

from FunctionCall call, string fn
where
  call.getTarget().hasGlobalName(fn) and
  fn in ["strcpy", "TerminateThread", "SuspendThread"]
select call, "Security-sensitive API call: " + fn + ". Map to CWE and explain the safer replacement."
