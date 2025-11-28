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

# Global variables for battery management
var calibration_start_total = nil
var calibration_start_time = nil
var start_battery_percentage = nil
var is_calibrating = false
var eco_mode_enabled = false
var total_battery_capacity = nil
var charging_start_total = nil
var charging_start_time = nil
var is_charging = false
var charging_history = []
var max_history_entries = 365  # ~1 year of data
var weekday_totals = {}  # Stores cumulative data per weekday

# Initialize weekday totals structure
def init_weekday_totals()
  var days = ["Sunday", "Monday", "Tuesday", "Wednesday", "Thursday", "Friday", "Saturday"]
  for day: days
    weekday_totals[day] = {
      "total_energy": 0.0,
      "session_count": 0,
      "eco_sessions": 0
    }
  end
end

# Get weekday name from timestamp
def get_weekday_name(timestamp)
  var weekday_num = tasmota.rtc()["local"] != nil ? tasmota.time_dump(timestamp)["weekday"] : 0
  var days = ["Sunday", "Monday", "Tuesday", "Wednesday", "Thursday", "Friday", "Saturday"]
  return days[weekday_num]
end

# Get current weekday average
def get_current_weekday_average()
  var now = tasmota.rtc()["local"]
  var weekday = get_weekday_name(now)
  
  if weekday_totals.contains(weekday) && weekday_totals[weekday]["session_count"] > 0
    return weekday_totals[weekday]["total_energy"] / weekday_totals[weekday]["session_count"]
  end
  
  return nil
end

# Update weekday totals when logging a session
def update_weekday_totals(session)
  var weekday = get_weekday_name(session["start_time"])
  
  if !weekday_totals.contains(weekday)
    init_weekday_totals()
  end
  
  weekday_totals[weekday]["total_energy"] += session["energy_used"]
  weekday_totals[weekday]["session_count"] += 1
  if session["eco_mode_active"]
    weekday_totals[weekday]["eco_sessions"] += 1
  end
end

# Rebuild weekday totals from history (for initial load or recalculation)
def rebuild_weekday_totals()
  init_weekday_totals()
  
  for session: charging_history
    update_weekday_totals(session)
  end
end

# Load saved data if exists
try
  var f = open("battery_manager.json", "r")
  if f != nil
    var content = f.read()
    f.close()
    var data = json.load(content)
    if data
      # Load calibration data
      calibration_start_total = data.find("calibration_start_total")
      calibration_start_time = data.find("calibration_start_time")
      start_battery_percentage = data.find("start_battery_percentage")
      is_calibrating = data.find("is_calibrating") || false
      
      # Load eco mode data
      eco_mode_enabled = data.find("eco_mode_enabled") || false
      total_battery_capacity = data.find("total_battery_capacity")
      
      # Load charging history
      if data.find("charging_history")
        charging_history = data["charging_history"]
      end
      
      # Load weekday totals
      if data.find("weekday_totals")
        weekday_totals = data["weekday_totals"]
      else
        # Rebuild from history if not found
        rebuild_weekday_totals()
      end
      
      if is_calibrating
        log("Resuming calibration in progress:", 3)
        log("  Battery level: " + str(start_battery_percentage) + "%", 3)
      end
      
      if eco_mode_enabled
        log("Eco mode is enabled", 3)
        if total_battery_capacity
          log("Battery capacity: " + str(total_battery_capacity) + " kWh", 3)
        else
          log("Battery capacity not yet calibrated", 3)
        end
      end
    end
  end
except .. as e
  log("No saved data found, initializing", 3)
end

# Save all data to file
def save_data()
  var data = {
    "calibration_start_total": calibration_start_total,
    "calibration_start_time": calibration_start_time,
    "start_battery_percentage": start_battery_percentage,
    "is_calibrating": is_calibrating,
    "eco_mode_enabled": eco_mode_enabled,
    "total_battery_capacity": total_battery_capacity,
    "charging_history": charging_history,
    "weekday_totals": weekday_totals
  }
  
  try
    var f = open("battery_manager.json", "w")
    f.write(json.dump(data))
    f.close()
  except .. as e
    log("Error saving data: " + str(e), 2)
  end
end

# Log a charging session to history
def log_charging_session(start_time, end_time, energy_used, eco_mode_active)
  var session = {
    "start_time": start_time,
    "end_time": end_time,
    "duration": end_time - start_time,
    "energy_used": energy_used,
    "eco_mode_active": eco_mode_active,
    "date": tasmota.strftime("%Y-%m-%d", end_time)
  }
  
  charging_history.push(session)
  
  # Update weekday totals
  update_weekday_totals(session)
  
  # Keep only last max_history_entries
  while charging_history.size() > max_history_entries
    charging_history.remove(0)
  end
  
  save_data()
end

# Get energy data from Tasmota
def get_energy_data()
  var energy_data = tasmota.cmd("Status 8")
  
  if energy_data && energy_data.find("StatusSNS") && energy_data["StatusSNS"].find("ENERGY")
    return energy_data["StatusSNS"]["ENERGY"]
  end
  return nil
end

# Start calibration with initial battery percentage
def start_calibration(battery_percentage)
  var energy = get_energy_data()
  if energy
    if battery_percentage != nil && battery_percentage > 0 && battery_percentage < 100
      calibration_start_total = energy["Total"]
      calibration_start_time = tasmota.rtc()["local"]
      start_battery_percentage = battery_percentage
      is_calibrating = true
      save_data()
      
      log("Calibration started", 3)
      log("  Start energy: " + str(calibration_start_total) + " kWh", 3)
      log("  Start time: " + str(tasmota.time_str(calibration_start_time)), 3)
      log("  Battery level: " + str(battery_percentage) + "%", 3)
      
      # Return status info in resp_cmnd
      return {
        "status": "started",
        "start_energy": calibration_start_total,
        "start_percentage": battery_percentage
      }
    else
      log("Error: Battery percentage must be between 1-99%", 2)
      return {"error": "Battery percentage must be between 1-99%"}
    end
  else
    log("Error: Could not retrieve energy data", 2)
    return {"error": "Could not retrieve energy data"}
  end
end

# End calibration - calculate battery capacity
def end_calibration()
  var energy = get_energy_data()
  if energy && calibration_start_total != nil && start_battery_percentage != nil
    var end_total = energy["Total"]
    var energy_used_kwh = end_total - calibration_start_total
    var end_time = tasmota.rtc()["local"]
    var duration_seconds = end_time - calibration_start_time
    var hours = duration_seconds / 3600
    var minutes = (duration_seconds % 3600) / 60
    var seconds = duration_seconds % 60
    
    # Calculate total battery capacity
    var percentage_charged = 100 - start_battery_percentage
    var energy_per_percent = energy_used_kwh / percentage_charged
    total_battery_capacity = energy_per_percent * 100
    
    log("Calibration ended", 3)
    log("  Start energy: " + str(calibration_start_total) + " kWh", 3)
    log("  End energy: " + str(end_total) + " kWh", 3)
    log("  Energy used: " + str(energy_used_kwh) + " kWh", 3)
    log("  Start battery: " + str(start_battery_percentage) + "%", 3)
    log("  End battery: 100%", 3)
    log("  Battery capacity: " + str(total_battery_capacity) + " kWh", 3)
    log("  Duration: " + string.format("%d:%02d:%02d", hours, minutes, seconds), 3)
    
    # Reset calibration state
    var old_start = start_battery_percentage
    calibration_start_total = nil
    calibration_start_time = nil
    start_battery_percentage = nil
    is_calibrating = false
    
    # Save updated data
    save_data()
    
    # Return status info
    return {
      "status": "completed",
      "battery_capacity": total_battery_capacity,
      "start_percentage": old_start,
      "energy_used": energy_used_kwh,
      "duration_seconds": duration_seconds
    }
  else
    log("Error: Could not complete calibration", 2)
    return {"error": "Could not complete calibration"}
  end
  
  return {"status": "error"}
end

# Start charging session
def start_charging()
  var energy = get_energy_data()
  if energy
    charging_start_total = energy["Total"]
    charging_start_time = tasmota.rtc()["local"]
    is_charging = true
    log("Charging session started", 3)
    log("  Start energy: " + str(charging_start_total) + " kWh", 3)
    log("  Start time: " + str(tasmota.time_str(charging_start_time)), 3)
    
    var info = {
      "start_energy": charging_start_total,
      "start_time": charging_start_time
    }
    
    if eco_mode_enabled
      var weekday_avg = get_current_weekday_average()
      if weekday_avg
        var threshold = weekday_avg * 0.7
        log("  Eco mode active - will stop at " + str(threshold) + " kWh (70% of weekday average)", 3)
        info["eco_threshold"] = threshold
      else
        log("  Eco mode active but no weekday average available yet", 3)
      end
    end
    
    return info
  end
  
  return {"error": "Could not start charging"}
end

# End charging session
def end_charging()
  if !is_charging
    return {"status": "not_charging"}
  end
  
  var energy = get_energy_data()
  if energy && charging_start_total
    var end_total = energy["Total"]
    var energy_used_kwh = end_total - charging_start_total
    var end_time = tasmota.rtc()["local"]
    
    log("Charging session ended", 3)
    log("  Energy used: " + str(energy_used_kwh) + " kWh", 3)
    
    # Log session to history
    log_charging_session(
      charging_start_time,
      end_time,
      energy_used_kwh,
      eco_mode_enabled
    )
    
    var old_start = charging_start_total
    charging_start_total = nil
    charging_start_time = nil
    is_charging = false
    
    return {
      "status": "completed",
      "start_energy": old_start,
      "end_energy": end_total,
      "energy_used": energy_used_kwh
    }
  end
  
  return {"status": "error"}
end

# Check if charging threshold has been reached
def check_energy_threshold()
  if !eco_mode_enabled || !is_charging || !charging_start_total
    return false
  end
  
  var weekday_avg = get_current_weekday_average()
  if !weekday_avg
    return false
  end
  
  var energy = get_energy_data()
  if energy
    var current_total = energy["Total"]
    var energy_used = current_total - charging_start_total
    var eco_threshold = weekday_avg * 0.7
    
    if energy_used >= eco_threshold
      log("Eco mode threshold reached:", 3)
      log("  Energy used: " + str(energy_used) + " kWh", 3)
      log("  Threshold: " + str(eco_threshold) + " kWh (70% of weekday average)", 3)
      return true
    end
  end
  
  return false
end

var low_power_since = nil

tasmota.add_rule("Energy#Power", def (value)
  var now = tasmota.rtc()["local"]

  if value > 5
    if !is_charging
      start_charging()
    end
    low_power_since = nil
  elif value <= 1
    if low_power_since == nil
      low_power_since = now
    elif now - low_power_since >= 15  # wait 15 seconds
      if is_charging
        end_charging()
        if is_calibrating
          end_calibration()
        end
      end
      low_power_since = nil
    end
  end
end)

# Monitor power state changes
tasmota.add_rule("Power1#State", def (value)
  log("Power1 state changed to: " + str(value), 3)
  
  if value == 1
    # Power turned ON
    if !is_charging
      start_charging()
    end
  elif value == 0
    # Power turned OFF
    if is_charging
      end_charging()         
      # If this was a calibration, end it
      if is_calibrating
        end_calibration()
      end
    end
  end
end)

# Set up a timer to check energy threshold for eco mode
def monitor_energy()
  if eco_mode_enabled && is_charging
    if check_energy_threshold()
      # Turn off power when threshold reached
      tasmota.cmd("Power1 0")
      log("Eco mode: stopping charge at 70% of weekday average", 3)
    end
  end
  
  # Re-schedule the timer every 5 seconds
  tasmota.set_timer(5000, monitor_energy)
end

# Register StartCal command that accepts battery percentage
tasmota.add_cmd("StartCal", def(cmd, idx, payload, payload_json)
  var percentage = nil
  
  if payload
    percentage = number(payload)
  end
  
  if percentage != nil
    var result = start_calibration(percentage)
    tasmota.resp_cmnd({"StartCal": result})
  else
    tasmota.resp_cmnd({"StartCal": {"error": "Please specify battery percentage (1-99)"}})
  end
end)

# Register manual EndCal command
tasmota.add_cmd("EndCal", def(cmd, idx, payload, payload_json)
  if is_calibrating
    var result = end_calibration()
    tasmota.resp_cmnd({"EndCal": result})
  else
    tasmota.resp_cmnd({"EndCal": {"status": "no_calibration"}})
  end
end)

# Register EcoMode command to enable/disable eco mode
tasmota.add_cmd("EcoMode", def(cmd, idx, payload, payload_json)
  if payload
    if payload == "1" || string.tolower(payload) == "on" || string.tolower(payload) == "true"
      # Check if we have weekday data for current day
      var weekday_avg = get_current_weekday_average()
      if weekday_avg == nil
        tasmota.resp_cmnd({"EcoMode": {"error": "No weekday data available"}})
        return
      end
      eco_mode_enabled = true
      save_data()
      tasmota.resp_cmnd({"EcoMode": {"status": "ON"}})
    elif payload == "0" || string.tolower(payload) == "off" || string.tolower(payload) == "false"
      eco_mode_enabled = false
      save_data()
      tasmota.resp_cmnd({"EcoMode": {"status": "OFF"}})
    end
  else
    tasmota.resp_cmnd({"EcoMode": {"status": eco_mode_enabled ? "ON" : "OFF"}})
  end
end)

# Register history command
tasmota.add_cmd("ChargingHistory", def(cmd, idx, payload, payload_json)
  tasmota.resp_cmnd({"ChargingHistory": charging_history})
end)

# Register daily summary command
tasmota.add_cmd("DailySummary", def(cmd, idx, payload, payload_json)
  var days = {}
  
  for i: 0..charging_history.size()-1
    var session = charging_history[i]
    var date = session["date"]
    
    if !days.contains(date)
      days[date] = {"total_energy": 0, "sessions": 0, "eco_sessions": 0, "total_duration": 0}
    end
    
    days[date]["total_energy"] += session["energy_used"]
    days[date]["sessions"] += 1
    if session["eco_mode_active"]
      days[date]["eco_sessions"] += 1
    end
    days[date]["total_duration"] += session["duration"]
  end
  
  tasmota.resp_cmnd({"DailySummary": days})
end)

# Register status command
tasmota.add_cmd("BatteryStatus", def(cmd, idx, payload, payload_json)
  var status = {
    "calibration_active": is_calibrating,
    "eco_mode": eco_mode_enabled,
    "charging": is_charging
  }
  
  if total_battery_capacity
    status["capacity"] = total_battery_capacity
  end
  
  if is_calibrating
    status["battery_start"] = start_battery_percentage
  end
  
  if is_charging && eco_mode_enabled
    var weekday_avg = get_current_weekday_average()
    if weekday_avg
      var energy = get_energy_data()
      if energy && charging_start_total
        var current_total = energy["Total"]
        var energy_used = current_total - charging_start_total
        var eco_threshold = weekday_avg * 0.7
        status["energy_used"] = energy_used
        status["eco_threshold"] = eco_threshold
        status["percentage"] = (energy_used / eco_threshold) * 100
        status["weekday_average"] = weekday_avg
      end
    end
  end
  
  tasmota.resp_cmnd({"BatteryStatus": status})
end)

# Register WeekdayAverage command
tasmota.add_cmd("WeekdayAverage", def(cmd, idx, payload, payload_json)
  var averages = {}
  var days_order = ["Monday", "Tuesday", "Wednesday", "Thursday", "Friday", "Saturday", "Sunday"]
  
  for day: days_order
    if weekday_totals.contains(day) && weekday_totals[day]["session_count"] > 0
      var total = weekday_totals[day]["total_energy"]
      var count = weekday_totals[day]["session_count"]
      var eco_count = weekday_totals[day]["eco_sessions"]
      
      averages[day] = {
        "average_energy": total / count,
        "total_sessions": count,
        "eco_sessions": eco_count,
        "eco_percentage": (eco_count * 100.0) / count
      }
    else
      averages[day] = {
        "average_energy": 0,
        "total_sessions": 0,
        "eco_sessions": 0,
        "eco_percentage": 0
      }
    end
  end
  
  tasmota.resp_cmnd({"WeekdayAverage": averages})
end)

# Register RecalculateStats command to rebuild statistics from history
tasmota.add_cmd("RecalculateStats", def(cmd, idx, payload, payload_json)
  rebuild_weekday_totals()
  save_data()
  tasmota.resp_cmnd({"RecalculateStats": {"status": "completed", "sessions_processed": charging_history.size()}})
end)

# Generate dummy test data for history
def generate_test_data()
  var now = tasmota.rtc()["local"]
  charging_history = []
  init_weekday_totals()  # Reset weekday totals
  
  # Generate 52 weeks of data (1 year)
  for week: 0..51
    for day: 0..6
      var day_offset = (week * 7) + day
      var day_ts = now - (day_offset * 86400)
      var day_date = tasmota.strftime("%Y-%m-%d", day_ts)
      
      # 1-3 sessions per day
      var sessions_today = 1 + (math.rand() % 3)
      
      for s: 0..sessions_today-1
        var dur = 1800 + ((math.rand() % 7200))  # 30min to 2.5hrs
        var end_t = day_ts - (s * 21600)
        var start_t = end_t - dur
        
        # Weekday-specific energy patterns
        var weekday_num = tasmota.time_dump(day_ts)["weekday"]
        var base_energy = 0.4
        
        # Higher usage on weekends
        if weekday_num == 0 || weekday_num == 6
          base_energy = 0.6
        end
        
        var r_kwh = (math.rand() / 2147483647.0) * 0.3
        var energy_used = base_energy + r_kwh
        var eco_active = (math.rand() % 2) == 0
        
        var session = {
          "start_time": start_t,
          "end_time": end_t,
          "duration": dur,
          "energy_used": energy_used,
          "eco_mode_active": eco_active,
          "date": day_date
        }
        
        charging_history.push(session)
        update_weekday_totals(session)
      end
    end
  end
  
  # Trim to max entries if needed
  while charging_history.size() > max_history_entries
    charging_history.remove(0)
  end
  
  log("Test data generated: " + str(charging_history.size()) + " sessions", 3)
  save_data()
  return {"status": "generated", "count": charging_history.size()}
end

# Register test data command
tasmota.add_cmd("GenerateTestData", def(cmd, idx, payload, payload_json)
  var result = generate_test_data()
  tasmota.resp_cmnd({"GenerateTestData": result})
end)

# Add a SetCapacity command so you can fake the calibration via curl
tasmota.add_cmd("SetCapacity", def(cmd, idx, payload, payload_json)
  if payload
    total_battery_capacity = number(payload)
    save_data()
    tasmota.resp_cmnd({cmd: {"status":"OK","capacity": total_battery_capacity}})
  else
    tasmota.resp_cmnd({cmd: {"error":"Missing value"}})
  end
end)

# Initialize weekday totals if not loaded
if !weekday_totals || weekday_totals.size() == 0
  init_weekday_totals()
  if charging_history.size() > 0
    rebuild_weekday_totals()
  end
end

# Start energy monitoring
tasmota.set_timer(5000, monitor_energy)

log("Battery manager initialized", 3)
if eco_mode_enabled
  log("Eco mode is active", 3)
end
