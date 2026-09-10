# autoexec.be - AccuSaver Auto-Off (robust, minimal) + DIAG LOGS
tasmota.cmd("SetOption31 0")

# Ensure voltage calibration (only if not already set)
tasmota.set_timer(2000, def ()
  var s = tasmota.cmd("Status 10")
  if s && s.find("StatusSNS")
    var e = s["StatusSNS"].find("ENERGY")
    if e && e.find("Voltage") && e["Voltage"] < 100
      tasmota.cmd("VoltageSet 230")
      tasmota.cmd("ADCParam1 2,4000,80000,4250,1")
    end
  end
end)

var script_version = "2.1"

# ---- Eco Mode State ----
# 0=off, 1=pending (calibrating), 2=active
import persist
if persist.eco_state == nil
  persist.eco_state = 0
end

var LOW_W       = 5
var HIGH_W      = 6
var LOW_SECONDS = 20
var WATCHDOG_MS = 5000

var relay_is_on  = false
var last_power   = nil
var low_since    = nil
var checking     = false

# ---- diag knobs ----
var DIAG         = false
var DIAG_TICK_MS = 10000

def now_s()
  return tasmota.rtc()["local"]
end

def dlog(msg)
  if DIAG
    log("AUTOFF-DIAG: " + msg, 3)
  end
end

def dump_state(tag)
  var lp_str = "nil"
  if last_power != nil
    lp_str = str(last_power)
  end
  var ls_str = "nil"
  if low_since != nil
    ls_str = str(low_since)
  end
  dlog(tag +
    " relay_is_on=" + str(relay_is_on) +
    " checking=" + str(checking) +
    " last_power=" + lp_str +
    " low_since=" + ls_str +
    " now=" + str(now_s()))
end

def stop_check()
  if checking || low_since != nil
    dlog("stop_check()")
    dump_state("before_stop")
  end
  checking = false
  low_since = nil
end

def check_low_power()
  if !relay_is_on
    dlog("check_low_power(): relay_is_on=false -> stop")
    stop_check()
    return
  end

  if last_power == nil
    dlog("check_low_power(): last_power=nil -> wait")
    tasmota.set_timer(1000, check_low_power)
    return
  end

  if last_power >= HIGH_W
    dlog("check_low_power(): last_power=" + str(last_power) + " >= HIGH_W=" + str(HIGH_W) + " -> cancel")
    stop_check()
    return
  end

  if last_power >= LOW_W
    if low_since != nil
      dlog("check_low_power(): last_power=" + str(last_power) + " in [" + str(LOW_W) + "," + str(HIGH_W) + ") -> reset low_since")
    end
    low_since = nil
    tasmota.set_timer(1000, check_low_power)
    return
  end

  var n = now_s()
  if low_since == nil
    low_since = n
    dlog("LOW start: power=" + str(last_power) + " < " + str(LOW_W) + "W, start timer " + str(LOW_SECONDS) + "s")
  else
    var dt = n - low_since
    dlog("LOW cont: power=" + str(last_power) + " dt=" + str(dt) + "s/" + str(LOW_SECONDS) + "s")
    if dt >= LOW_SECONDS
      dlog("TRIP: power < " + str(LOW_W) + "W for " + str(LOW_SECONDS) + "s -> Power1 OFF")
      var res = tasmota.cmd("Power1 0")
      dlog("cmd(Power1 0) -> " + str(res))
      stop_check()
      return
    end
  end

  tasmota.set_timer(1000, check_low_power)
end

def start_check(reason)
  if checking
    dlog("start_check(): already checking (reason=" + reason + ")")
    return
  end
  checking = true
  dlog("start_check(): begin (reason=" + reason + ")")
  dump_state("start_check")
  tasmota.set_timer(1000, check_low_power)
end

def arm_if_relay_on(reason)
  dlog("arm_if_relay_on(reason=" + reason + ") relay_is_on=" + str(relay_is_on))
  if relay_is_on
    start_check("arm:" + reason)
  else
    stop_check()
  end
end

var blink_disabled = false

tasmota.add_rule("Power1#State", def (v)
  dlog("event Power1#State v=" + str(v))
  relay_is_on = (v == 1)

  # Disable blinking once on first power off
  if v == 0 && !blink_disabled
    tasmota.cmd("SetOption31 1")
    blink_disabled = true
  end

  arm_if_relay_on("Power1#State")
end)

tasmota.add_rule("Energy#Power", def (p)
  dlog("event Energy#Power p=" + str(p))
  last_power = p

  if relay_is_on && p < LOW_W && !checking
    start_check("Energy#Power low")
  end
end)

def sync_relay_state()
  var actual_on = tasmota.get_power(0)
  dlog("sync_relay_state(): get_power(0) -> " + str(actual_on))

  if actual_on != relay_is_on
    dlog("sync_relay_state(): mismatch believed=" + str(relay_is_on) + " actual=" + str(actual_on))
    relay_is_on = actual_on
    arm_if_relay_on("watchdog-sync")
  end
end

def relay_watchdog()
  dlog("watchdog tick")
  sync_relay_state()
  tasmota.set_timer(WATCHDOG_MS, relay_watchdog)
end

def diag_tick()
  dump_state("periodic")
  tasmota.set_timer(DIAG_TICK_MS, diag_tick)
end

dlog("BOOT: autoexec started")
relay_watchdog()
diag_tick()

log("AutoOff loaded: OFF if Power1 ON and Power < " + str(LOW_W) + "W for " + str(LOW_SECONDS) + "s", 3)

tasmota.add_cmd("SCRIPTVERSION", def(cmd, idx, payload, payload_json)
  tasmota.resp_cmnd({"ScriptVersion": {"version": script_version}})
end)

# StartCal command: start calibration with battery percentage
# StartCal 70  -> start calibration at 70%
tasmota.add_cmd("STARTCAL", def(cmd, idx, payload, payload_json)
  var percentage = 0
  if payload != nil && payload != ""
    percentage = int(payload)
  end

  # Store calibration start percentage (for future use)
  persist.cal_start_pct = percentage
  persist.save()

  # Set eco mode to pending (calibrating)
  persist.eco_state = 1
  persist.save()

  tasmota.resp_cmnd({"StartCal": {"status": "ok", "percentage": percentage}})
end)

# EcoMode command: get or set eco state
# EcoMode      -> returns current state
# EcoMode 0    -> set off
# EcoMode 1    -> set pending
# EcoMode 2    -> set active
tasmota.add_cmd("ECOMODE", def(cmd, idx, payload, payload_json)
  var state_names = ["off", "pending", "active"]

  if payload != nil && payload != ""
    var new_state = int(payload)
    if new_state >= 0 && new_state <= 2
      persist.eco_state = new_state
      persist.save()
    end
  end

  var current = persist.eco_state
  var state_name = "unknown"
  if current >= 0 && current <= 2
    state_name = state_names[current]
  end

  tasmota.resp_cmnd({"EcoMode": {"status": state_name, "eco_state": current}})
end)
