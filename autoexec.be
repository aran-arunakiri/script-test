# Script to manage battery charging with calibration and eco mode

import string
import json
import math

# ---- Self-healing for Tasmota Rules & Backlog ----
var RULE1 = 'ON Button1#State=2 DO Backlog Power1 ON; RuleTimer1 10 ENDON'
var RULE2 = 'ON Rules#Timer=1 DO RuleTimer2 10 ENDON ON Energy#Power>5 DO Backlog RuleTimer2 10 ENDON ON Rules#Timer=2 DO Power1 OFF ENDON'

var USER_BACKLOG = 'Module 0; ButtonTopic 0; SetButton1 1; SetButton3 1; VoltageSet 230; ADCParam1 2,4000,80000,4250,1; Rule1 1; Rule2 1'

def ensure_rule(idx, want)
  # Read current rule text/state (string like: "Rule1 1 ON Button1#State=2 ...")
  var res = tasmota.cmd('Rule' + idx)
  var need_seed = (res == nil) || !string.find(str(res), want)

  if need_seed
    # Atomically replace + enable
    tasmota.cmd('Backlog Rule' + idx + ' 0; Rule' + idx + ' "' + want + '"; Rule' + idx + ' 1')
  else
    # Ensure enabled; idempotent
    tasmota.cmd('Rule' + idx + ' 1')
  end
end

def ensure_backlog()
  # Use VoltageSet as a simple sentinel to avoid re-running backlog unnecessarily
  var res = tasmota.cmd('VoltageSet')
  var s = str(res)

  # If VoltageSet is not 230 yet, apply our defaults
  if !string.find(s, '230')
    tasmota.cmd('Backlog ' + USER_BACKLOG)
  end
end
# ----------------------------------------

# Run self-healing once on script load (every boot / after reset)
ensure_rule('1', RULE1)
ensure_rule('2', RULE2)
ensure_backlog()


var SCRIPT_VERSION = "1.0.0"

tasmota.add_cmd("ScriptVersion", def(cmd, idx, p, pj)
  var payload = {"ScriptVersion": SCRIPT_VERSION}
  tasmota.resp_cmnd(json.dump(payload))
end)
