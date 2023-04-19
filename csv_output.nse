-- nmap_csv_output.nse
-- Usage: nmap -sC -sV --script=nmap_csv_output.nse -oN results.txt <target>

local csv = require "csv"

-- Define the output format
local fields = {"host", "port", "protocol", "state", "service", "version"}

-- Initialize the output CSV file
local csvfile = assert(io.open("nmap_results.csv", "w"))
csvfile:write(csv.generate_header(fields))

-- Define the function to handle each result
local function process_result(host, port, protocol, state, service, version)
  local row = {host.ip, port.number, protocol, state, service.name, version}
    csvfile:write(csv.generate_line(fields, row))
    end

    -- Register the script with NMap
    local csv_output = {}
    csv_output["portrule"] = function(host, port)
      process_result(host, port, port.protocol, port.state, port.service, port.version)
      end
